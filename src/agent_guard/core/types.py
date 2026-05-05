from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class AuditEventType(str, Enum):
    CHAT_CHECK = "chat_check"
    TOOL_BEFORE = "tool_before"
    TOOL_AFTER = "tool_after"
    THREAT = "threat"
    POLICY_DENY = "policy_deny"
    SANDBOX_DENY = "sandbox_deny"
    DLP_DENY = "dlp_deny"
    CONSENT = "consent"


@dataclass
class ChatCheckResult:
    allowed: bool
    """是否允许发往模型"""

    sanitized_text: Optional[str] = None
    """若为字符串输入，可能被清洗后的文本"""

    block_reason: Optional[str] = None
    threat_signals: List[str] = field(default_factory=list)


@dataclass
class ToolCheckResult:
    allowed: bool
    sanitized_arguments: Dict[str, Any] = field(default_factory=dict)
    block_reason: Optional[str] = None
    consent_required: bool = False


@dataclass
class AuditRecord:
    id: str
    ts: datetime
    event_type: AuditEventType
    summary: str
    detail: Dict[str, Any] = field(default_factory=dict)
