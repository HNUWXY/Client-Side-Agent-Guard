"""
Competition-grade prompt injection baseline (rules + heuristics + boundaries + optional ML).

Use via ``SecureAgent`` with ``injection_engine=\"competition\"`` or import middleware directly.
"""

from .config import BaselineConfig, baseline_config_from_detection
from .detector import PromptInjectionBaseline
from .middleware import AgentSecurityMiddleware, content_source_index, latest_user_content
from .models import DetectionEvidence, DetectionResult, Message, RiskAction, Rule
from .rules import DEFAULT_RULES

__all__ = [
    "AgentSecurityMiddleware",
    "BaselineConfig",
    "DEFAULT_RULES",
    "DetectionEvidence",
    "DetectionResult",
    "Message",
    "PromptInjectionBaseline",
    "RiskAction",
    "Rule",
    "baseline_config_from_detection",
    "content_source_index",
    "latest_user_content",
]
