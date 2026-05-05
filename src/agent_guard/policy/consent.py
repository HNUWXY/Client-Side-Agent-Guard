from __future__ import annotations

from typing import Callable, Dict, FrozenSet, Optional, Set


ConsentFn = Callable[[str, Dict], bool]


class ConsentManager:
    """
    「首次敏感工具须用户授权」的简单会话级实现。

    与 agent-mesh 中 ApprovalHandler 概念对齐：由宿主应用实现真正弹窗。
    """

    def __init__(
        self,
        sensitive_tools: FrozenSet[str],
        callback: Optional[ConsentFn] = None,
        deny_if_no_callback: bool = True,
    ):
        self._sensitive = sensitive_tools
        self._callback = callback
        self._deny_if_no_callback = deny_if_no_callback
        self._granted: Set[str] = set()

    def reset_session(self) -> None:
        self._granted.clear()

    def is_sensitive(self, tool_name: str) -> bool:
        return tool_name in self._sensitive

    def already_granted(self, tool_name: str) -> bool:
        return tool_name in self._granted

    def request(self, tool_name: str, arguments: Dict) -> tuple[bool, str]:
        if not self.is_sensitive(tool_name):
            return True, ""
        if tool_name in self._granted:
            return True, ""
        if self._callback is None:
            if self._deny_if_no_callback:
                return False, "consent_callback_not_configured"
            self._granted.add(tool_name)
            return True, ""
        ok = bool(self._callback(tool_name, arguments))
        if ok:
            self._granted.add(tool_name)
        return ok, "user_rejected_sensitive_tool" if not ok else ""
