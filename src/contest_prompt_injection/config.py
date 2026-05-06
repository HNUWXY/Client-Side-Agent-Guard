from dataclasses import dataclass
from typing import Any, Sequence


@dataclass
class BaselineConfig:
    # Risk thresholds (tiered)
    alert_threshold: float = 0.45
    challenge_threshold: float = 0.65
    block_threshold: float = 0.80
    # Mechanism switches
    enable_input_sanitization: bool = True
    enable_boundary_checks: bool = True
    enable_output_filter: bool = True
    enable_structural_scores: bool = True
    # Optional third signal (install transformers + torch, enable explicitly)
    enable_ml_scorer: bool = False
    ml_score_cap: float = 0.15
    ml_model_name: str = "protectai/deberta-v3-base-prompt-injection"
    # Output filtering patterns
    sensitive_output_patterns: Sequence[str] = (
        r"system\s+prompt",
        r"developer\s+instructions?",
        r"internal\s+policy",
        r"hidden\s+chain[- ]of[- ]thought",
    )


def baseline_config_from_detection(dc: Any) -> BaselineConfig:
    """Build competition baseline config from core ``DetectionConfig``."""
    patterns = getattr(dc, "injection_sensitive_output_patterns", None)
    kwargs: dict[str, Any] = {}
    if patterns:
        kwargs["sensitive_output_patterns"] = patterns
    return BaselineConfig(
        alert_threshold=getattr(dc, "injection_alert_threshold", 0.45),
        challenge_threshold=getattr(dc, "injection_challenge_threshold", 0.65),
        block_threshold=getattr(dc, "injection_block_threshold", 0.80),
        enable_input_sanitization=getattr(dc, "injection_enable_input_sanitization", True),
        enable_boundary_checks=getattr(dc, "injection_enable_boundary_checks", True),
        enable_output_filter=getattr(dc, "injection_enable_output_filter", True),
        enable_structural_scores=getattr(dc, "injection_enable_structural_scores", True),
        enable_ml_scorer=getattr(dc, "injection_enable_ml_scorer", False),
        ml_score_cap=getattr(dc, "injection_ml_score_cap", 0.15),
        ml_model_name=getattr(dc, "injection_ml_model_name", "protectai/deberta-v3-base-prompt-injection"),
        **kwargs,
    )
