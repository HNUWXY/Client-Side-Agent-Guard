from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


JsonDict = Dict[str, Any]
ChatMessagePart = Dict[str, Any]


@dataclass
class MessagesPrepareOutcome:
    """发往任意 LLM/API 之前的准备结果（OpenAI 风格 messages）。"""

    allowed: bool
    messages: Optional[List[JsonDict]] = None
    block_reason: Optional[str] = None
    threat_signals: List[str] = field(default_factory=list)
    """仅当 blocked 时亦有部分信号可供审计"""


@dataclass
class PlainToolOutcome:
    allowed: bool
    sanitized_arguments: Dict[str, Any] = field(default_factory=dict)
    block_reason: Optional[str] = None
    consent_required: bool = False
