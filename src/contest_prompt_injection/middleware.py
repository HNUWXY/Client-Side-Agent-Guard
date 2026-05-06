from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .detector import PromptInjectionBaseline
from .models import DetectionResult, Message


def _msg_role(msg: Any) -> Optional[str]:
    if isinstance(msg, dict):
        r = msg.get("role")
        return str(r) if r is not None else None
    r = getattr(msg, "role", None)
    return str(r) if r is not None else None


def _msg_content(msg: Any) -> str:
    if isinstance(msg, dict):
        return str(msg.get("content", "") or "")
    c = getattr(msg, "content", None)
    return str(c) if c is not None else ""


def content_source_index(messages: Sequence[Any]) -> Optional[int]:
    """Index of the message used for detection (last user, else last)."""
    for i in range(len(messages) - 1, -1, -1):
        if _msg_role(messages[i]) == "user":
            return i
    return len(messages) - 1 if messages else None


def latest_user_content(messages: Sequence[Any]) -> str:
    for msg in reversed(messages):
        if _msg_role(msg) == "user":
            return _msg_content(msg)
    return _msg_content(messages[-1]) if messages else ""


class AgentSecurityMiddleware:
    """
    Framework-agnostic middleware.

    - before_model_call: sanitize input + run detector
    - after_model_response: output filter / encoding
    """

    def __init__(self, detector: Optional[PromptInjectionBaseline] = None):
        self.detector = detector or PromptInjectionBaseline()

    def before_model_call(
        self, messages: Sequence[Dict[str, str] | Message]
    ) -> tuple[List[Dict[str, str]], DetectionResult]:
        normalized_messages = [self._normalize_message(msg) for msg in messages]
        user_content = latest_user_content(normalized_messages)
        result = self.detector.detect(user_content)

        idx = content_source_index(normalized_messages)
        if idx is not None:
            original = _msg_content(normalized_messages[idx])
            if result.sanitized_text != original and isinstance(
                normalized_messages[idx], dict
            ):
                normalized_messages[idx] = {
                    **normalized_messages[idx],
                    "content": result.sanitized_text,
                }

        return normalized_messages, result

    def after_model_response(self, text: str) -> str:
        return self.detector.sanitize_output(text)

    @staticmethod
    def _normalize_message(msg: Dict[str, str] | Message) -> Dict[str, str]:
        if isinstance(msg, Message):
            return {"role": msg.role, "content": msg.content}
        return {"role": msg.get("role", "user"), "content": msg.get("content", "")}
