from __future__ import annotations

from typing import Any

from ..core.exceptions import PromptBlocked
from ..facade import AgentGuard


def attach_openai_chat_guard(client: Any, guard: AgentGuard) -> Any:
    """
    为 OpenAI 兼容 ``client.chat.completions.create`` 挂载用户消息检测（与 agent-security SecureAgent 同思路）。

    注意：工具循环需在应用侧对 ``tool_calls`` 调用 ``guard.before_tool``；本函数只覆盖「最后一轮 user 文本」。
    """

    if not hasattr(client, "chat") or not hasattr(client.chat, "completions"):
        return client

    original = client.chat.completions.create

    def secure_create(*args: Any, **kwargs: Any):
        messages = kwargs.get("messages")
        if messages is None and len(args) > 1:
            messages = args[1]
        if messages:
            last = messages[-1]
            if isinstance(last, dict):
                role = last.get("role")
                content = last.get("content")
                if role == "user" and isinstance(content, str):
                    check = guard.check_user_message(content)
                    if not check.allowed:
                        raise PromptBlocked(check.block_reason or "prompt_blocked")
                    if check.sanitized_text is not None:
                        messages = list(messages)
                        messages[-1] = {**last, "content": check.sanitized_text}
                        kwargs["messages"] = messages
        return original(*args, **kwargs)

    client.chat.completions.create = secure_create
    return client
