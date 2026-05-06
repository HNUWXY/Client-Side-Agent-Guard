from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class RiskAction(str, Enum):
    ALLOW = "allow"
    ALERT = "alert"
    CHALLENGE = "challenge"
    BLOCK = "block"


@dataclass(frozen=True)
class Rule:
    name: str
    attack_type: str
    pattern: str
    weight: float


@dataclass
class DetectionEvidence:
    rule_hits: List[str] = field(default_factory=list)
    heuristic_hits: List[str] = field(default_factory=list)
    boundary_hits: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    is_injection: bool
    confidence: float
    attack_type: str
    action: RiskAction
    sanitized_text: str
    evidence: DetectionEvidence


@dataclass
class Message:
    role: str
    content: str
