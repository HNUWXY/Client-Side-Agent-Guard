"""
Optional Hugging Face classifier score for prompt injection (requires `pip install agent-security[ml]`).
When unavailable or disabled, scores are zero.
"""

from __future__ import annotations

from typing import Protocol


class InjectionMLScorer(Protocol):
    def score(self, text: str) -> float:
        """Return additive confidence in [0, 1], capped upstream."""


class NullMLScorer:
    def score(self, text: str) -> float:
        return 0.0


def build_ml_scorer(enabled: bool, model_name: str, score_cap: float) -> InjectionMLScorer:
    if not enabled:
        return NullMLScorer()
    try:
        return _HFMLScorer(model_name=model_name, score_cap=score_cap)
    except Exception:
        return NullMLScorer()


class _HFMLScorer:
    """Lazy-loaded transformers pipeline; falls back to Null at build time if deps missing."""

    def __init__(self, model_name: str, score_cap: float):
        from transformers import pipeline  # type: ignore

        self._score_cap = score_cap
        self._pipe = pipeline(
            "text-classification",
            model=model_name,
            truncation=True,
            max_length=512,
        )

    def score(self, text: str) -> float:
        if not text.strip():
            return 0.0
        try:
            raw = self._pipe(text[:4000])
        except Exception:
            return 0.0
        items = raw if isinstance(raw, list) else [raw]
        if not items:
            return 0.0
        try:
            best = max(items, key=lambda x: float(x.get("score", 0.0)))
            label = str(best.get("label", "")).lower()
            conf = float(best.get("score", 0.0))
        except (TypeError, ValueError):
            return 0.0
        positive = any(
            k in label for k in ("inject", "unsafe", "attack", "malicious", "injection", "jailbreak")
        )
        negative = any(k in label for k in ("safe", "benign", "legitimate", "clean", "harmless"))
        if positive:
            return min(self._score_cap, conf)
        if negative:
            return 0.0
        return min(self._score_cap * 0.35, conf * 0.35)
