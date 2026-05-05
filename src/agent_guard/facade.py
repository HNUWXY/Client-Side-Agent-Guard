from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional

from .audit.event_log import AuditSink
from .pii import PIIRedactor, PIIScanner
from .core.config import GuardConfig
from .core.exceptions import ConsentRejected, DLPBlocked, PolicyDenied, PromptBlocked, SandboxViolation
from .core.types import AuditEventType, ChatCheckResult, ToolCheckResult
from .detectors.instruction_boundary import InstructionBoundaryGuard
from .detectors.prompt_injection import PromptInjectionDetector
from .policy.consent import ConsentFn, ConsentManager
from .policy.sandbox import NetworkSandbox, PathSandbox


def _collect_strings(obj: Any, out: Optional[List[str]] = None) -> List[str]:
    if out is None:
        out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_strings(v, out)
    return out


def _redact_mapping(obj: Any, redactor: PIIRedactor) -> Any:
    if isinstance(obj, str):
        return redactor.redact(obj)
    if isinstance(obj, dict):
        return {k: _redact_mapping(v, redactor) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_mapping(v, redactor) for v in obj]
    return obj


class AgentGuard:
    """
    对外统一 façade：任意 Agent / Chat API 可在三处钩子接入：

    1. ``check_user_message`` — 发往模型前的用户文本
    2. ``before_tool`` / ``after_tool`` — 工具入参 / 出参
    3. ``attach_openai_chat_guard`` — OpenAI 风格客户端补丁（可选）

    与治理代码中的「拦截 — 审计 — 再执行」链路一致。
    """

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        consent_callback: Optional[ConsentFn] = None,
    ):
        self.config = config or GuardConfig()

        self._injection = (
            PromptInjectionDetector(threshold=self.config.injection_confidence_threshold)
            if self.config.enable_prompt_pattern_injection
            else None
        )
        self._boundary = (
            InstructionBoundaryGuard(threshold=0.72) if self.config.enable_instruction_boundary else None
        )

        self._path_sandbox = (
            PathSandbox(self.config.path_allow_prefixes) if self.config.enable_path_sandbox else None
        )
        self._net_sandbox = (
            NetworkSandbox(self.config.url_allowed_hosts) if self.config.enable_network_sandbox else None
        )

        self._consent = ConsentManager(
            self.config.sensitive_tools,
            consent_callback,
            deny_if_no_callback=True,
        )

        self._pii_scanner = PIIScanner()
        self._redactor = PIIRedactor()

        self.audit = AuditSink(path=self.config.audit_log_path)

    def reset_session(self) -> None:
        self._consent.reset_session()

    def check_user_message(self, text: str) -> ChatCheckResult:
        if not text:
            return ChatCheckResult(True, sanitized_text=text)

        working = text
        signals: List[str] = []

        if self._injection:
            det = self._injection.detect(working)
            if det.is_injection:
                signals.extend(det.matched_patterns or [det.attack_type])
                self.audit.emit(
                    AuditEventType.THREAT,
                    "prompt_injection_detected",
                    {"attack_type": det.attack_type, "confidence": det.confidence},
                )
                return ChatCheckResult(
                    False,
                    sanitized_text=None,
                    block_reason=f"prompt_injection:{det.attack_type}",
                    threat_signals=signals,
                )

        if self._boundary:
            b = self._boundary.analyze(working)
            if b.reasons:
                signals.extend(b.reasons)
            if b.suspicious and self.config.block_instruction_boundary:
                self.audit.emit(
                    AuditEventType.THREAT,
                    "instruction_boundary_suspicious",
                    {"reasons": b.reasons, "confidence": b.confidence},
                )
                return ChatCheckResult(
                    False,
                    block_reason="instruction_boundary",
                    threat_signals=signals,
                )
            if self.config.strip_boundary_markers_from_user_text:
                working = b.sanitized

        if self.config.redact_input_pii:
            red = self._redactor.redact(working)
            if red != working:
                self.audit.emit(
                    AuditEventType.CHAT_CHECK,
                    "user_message_pii_redacted",
                    {"length_before": len(working)},
                )
            working = red

        self.audit.emit(AuditEventType.CHAT_CHECK, "user_message_ok", {})
        return ChatCheckResult(True, sanitized_text=working, threat_signals=signals)

    def before_tool(self, tool_name: str, arguments: Dict[str, Any]) -> ToolCheckResult:
        args = copy.deepcopy(arguments)

        if self.config.enforce_tool_allowlist and self.config.allowed_tools is not None:
            if tool_name not in self.config.allowed_tools:
                self.audit.emit(
                    AuditEventType.POLICY_DENY,
                    f"tool_not_in_allowlist:{tool_name}",
                    {},
                )
                return ToolCheckResult(False, args, block_reason="tool_not_allowed")

        if self._path_sandbox:
            for key in self.config.argument_keys_for_paths:
                if key in args and isinstance(args[key], str):
                    if not self._path_sandbox.is_allowed(args[key]):
                        self.audit.emit(
                            AuditEventType.SANDBOX_DENY,
                            f"path_out_of_sandbox:{tool_name}",
                            {"key": key, "path": args[key]},
                        )
                        return ToolCheckResult(False, args, block_reason="path_sandbox")

        if self._net_sandbox:
            for key in self.config.argument_keys_for_urls:
                if key in args and isinstance(args[key], str):
                    if not self._net_sandbox.is_allowed(args[key]):
                        self.audit.emit(
                            AuditEventType.SANDBOX_DENY,
                            f"url_blocked:{tool_name}",
                            {"key": key, "url": args[key]},
                        )
                        return ToolCheckResult(False, args, block_reason="network_sandbox")

        ok, reason = self._consent.request(tool_name, args)
        if not ok:
            self.audit.emit(
                AuditEventType.CONSENT,
                f"consent_denied:{tool_name}",
                {"reason": reason},
            )
            return ToolCheckResult(
                False,
                args,
                block_reason=reason,
                consent_required=self._consent.is_sensitive(tool_name),
            )

        if self.config.enable_dlp_on_tool_args and tool_name in self.config.exfil_sensitive_tools:
            blob = "\n".join(_collect_strings(args))
            hits = self._pii_scanner.scan(blob)
            if hits and self.config.dlp_block_when_pii_in_exfil_tools:
                self.audit.emit(
                    AuditEventType.DLP_DENY,
                    f"pii_in_tool_args:{tool_name}",
                    {"types": sorted({h.type.value for h in hits})},
                )
                return ToolCheckResult(False, args, block_reason="dlp_pii_in_arguments")

        if self.config.enable_dlp_on_tool_args:
            args = _redact_mapping(args, self._redactor)

        self.audit.emit(
            AuditEventType.TOOL_BEFORE,
            f"allow:{tool_name}",
            {"arg_keys": list(args.keys())},
        )
        return ToolCheckResult(True, sanitized_arguments=args)

    def after_tool(self, tool_name: str, result: Any) -> Any:
        if not self.config.redact_output_pii:
            self.audit.emit(AuditEventType.TOOL_AFTER, f"done:{tool_name}", {})
            return result

        if isinstance(result, str):
            out = self._redactor.redact(result)
        elif isinstance(result, dict):
            out = _redact_mapping(result, self._redactor)
        else:
            try:
                text = json.dumps(result, ensure_ascii=False, default=str)
                out = json.loads(self._redactor.redact(text))
            except Exception:
                out = result

        self.audit.emit(AuditEventType.TOOL_AFTER, f"done_redacted:{tool_name}", {})
        return out

    def assert_user_message(self, text: str) -> str:
        r = self.check_user_message(text)
        if not r.allowed:
            raise PromptBlocked(r.block_reason or "blocked")
        return r.sanitized_text if r.sanitized_text is not None else text

    def assert_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        v = self.before_tool(tool_name, arguments)
        if not v.allowed:
            if v.block_reason == "user_rejected_sensitive_tool":
                raise ConsentRejected(v.block_reason)
            if v.block_reason == "path_sandbox":
                raise SandboxViolation(v.block_reason)
            if v.block_reason == "network_sandbox":
                raise SandboxViolation(v.block_reason)
            if v.block_reason == "dlp_pii_in_arguments":
                raise DLPBlocked(v.block_reason)
            raise PolicyDenied(v.block_reason or "denied")
        return v.sanitized_arguments

    def observability_snapshot(self) -> Dict[str, Any]:
        return self.audit.snapshots_for_demo()
