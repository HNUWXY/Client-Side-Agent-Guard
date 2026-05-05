"""
统一入口：**所有智能体 / 任意大模型的对话与工具**，建议经 `SecureLLMGateway` 再下行。

宿主（NextChat、LangChain、MCP Proxy、自建 Agent）只做两件事：
1. 把待发 API 的 `messages`（OpenAI-compatible）交给 ``prepare_messages``；
2. 把每次工具调用交给 ``evaluate_tool``.

具体如何请求 OpenAI/Anthropic/本地私有化接口仍由宿主实现；本模块只负责强制安全切面。
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Dict, List, MutableSequence, Optional

from ..core.config import GuardConfig
from ..facade import AgentGuard
from ..policy.consent import ConsentFn
from .types import MessagesPrepareOutcome, PlainToolOutcome

ConsentFactory = Callable[[], ConsentFn]


def create_default_gateway_session(
    *,
    audit_log_path: Optional[str] = None,
    consent_callback: Optional[ConsentFn] = None,
    guard_config: Optional[GuardConfig] = None,
) -> SecureLLMGateway:
    cfg = guard_config or GuardConfig(
        audit_log_path=audit_log_path,
        injection_confidence_threshold=0.72,
    )
    guard = AgentGuard(cfg, consent_callback=consent_callback)
    return SecureLLMGateway(guard)


class SecureLLMGateway:
    def __init__(self, guard: AgentGuard):
        self._g = guard

    @property
    def guard(self) -> AgentGuard:
        return self._g

    def prepare_messages(self, messages: List[Dict[str, Any]]) -> MessagesPrepareOutcome:
        """
        在调用任意 Chat Completions 类 API 前调用。

        对 **最后一条** ``role=user`` 的文本（含 multimodal 中所有 ``type=text`` 分段）逐项做：
        Prompt 注入 + 指令边界 +（可选）PII 脱敏。
        """
        if not messages:
            return MessagesPrepareOutcome(True, messages=[])

        msgs = deepcopy(messages)
        idx = self._find_last_user_index(msgs)
        if idx is None:
            return MessagesPrepareOutcome(True, messages=msgs)

        entry = msgs[idx]
        content = entry.get("content")

        rebuilt, signals_out = self._secure_user_content(content)
        if not rebuilt.ok:
            return MessagesPrepareOutcome(
                False,
                messages=None,
                block_reason=rebuilt.block_reason,
                threat_signals=rebuilt.signals,
            )

        entry["content"] = rebuilt.content
        return MessagesPrepareOutcome(True, messages=msgs, threat_signals=signals_out)

    def evaluate_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        post_apply_after_tool: bool = False,
        raw_tool_result: Any = None,
    ) -> PlainToolOutcome:
        v = self._g.before_tool(tool_name, arguments)
        if not v.allowed:
            return PlainToolOutcome(
                False,
                sanitized_arguments=v.sanitized_arguments,
                block_reason=v.block_reason,
                consent_required=v.consent_required,
            )
        outcome = PlainToolOutcome(
            True,
            sanitized_arguments=v.sanitized_arguments,
            consent_required=v.consent_required,
        )
        # 调用方在执行完真实工具后可再调 guard.after_tool；此处占位便于扩展同步 RPC
        if post_apply_after_tool:
            assert raw_tool_result is not None  # noqa: S101 — 仅占位语义
        return outcome

    def format_tool_result_safe(self, tool_name: str, raw: Any) -> Any:
        return self._g.after_tool(tool_name, raw)

    def observability_snapshot(self) -> Dict[str, Any]:
        return self._g.observability_snapshot()

    # --- internals ---

    def _find_last_user_index(self, msgs: MutableSequence[Dict[str, Any]]) -> Optional[int]:
        for i in range(len(msgs) - 1, -1, -1):
            if msgs[i].get("role") == "user":
                return i
        return None

    class _SecureContentResult:
        __slots__ = ("ok", "content", "block_reason", "signals")

        def __init__(
            self,
            ok: bool,
            content: Any,
            *,
            block_reason: Optional[str] = None,
            signals: Optional[List[str]] = None,
        ):
            self.ok = ok
            self.content = content
            self.block_reason = block_reason
            self.signals = signals or []

    def _secure_user_content(self, content: Any) -> tuple[_SecureContentResult, List[str]]:
        signals_all: List[str] = []

        if content is None:
            return SecureLLMGateway._SecureContentResult(True, content), signals_all

        if isinstance(content, str):
            r = self._g.check_user_message(content)
            signals_all.extend(r.threat_signals)
            if not r.allowed:
                return (
                    SecureLLMGateway._SecureContentResult(False, None, block_reason=r.block_reason, signals=signals_all),
                    signals_all,
                )
            return (
                SecureLLMGateway._SecureContentResult(True, r.sanitized_text if r.sanitized_text is not None else content),
                signals_all,
            )

        if isinstance(content, list):
            new_parts: List[Any] = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    txt = item.get("text") or ""
                    r = self._g.check_user_message(txt)
                    signals_all.extend(r.threat_signals)
                    if not r.allowed:
                        return (
                            SecureLLMGateway._SecureContentResult(
                                False, None, block_reason=r.block_reason, signals=signals_all
                            ),
                            signals_all,
                        )
                    st = r.sanitized_text if r.sanitized_text is not None else txt
                    new_parts.append({**item, "text": st})
                else:
                    new_parts.append(deepcopy(item))
            return SecureLLMGateway._SecureContentResult(True, new_parts), signals_all

        # 少见类型：转字符串单行检测
        r = self._g.check_user_message(str(content))
        signals_all.extend(r.threat_signals)
        if not r.allowed:
            return (
                SecureLLMGateway._SecureContentResult(False, None, block_reason=r.block_reason, signals=signals_all),
                signals_all,
            )
        return SecureLLMGateway._SecureContentResult(True, r.sanitized_text or str(content)), signals_all
