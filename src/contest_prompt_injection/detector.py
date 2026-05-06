from __future__ import annotations

import html
import re
from typing import Optional, Sequence

from .config import BaselineConfig
from .models import DetectionEvidence, DetectionResult, RiskAction, Rule
from .heuristic_lexicon import (
    chinese_imperative_and_sensitive_counts,
    english_imperative_and_sensitive_counts,
)
from .ml_scorer import build_ml_scorer
from .rules import DEFAULT_RULES

_HEURISTIC_SCORE_CAP = 0.55

_ZW_SPACE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]+",
)


class PromptInjectionBaseline:
    """
    Competition-grade detector: rules + heuristics + boundaries (+ optional ML).

    Mechanisms:
    - Input sanitization
    - Weighted rule engine
    - Heuristic scoring
    - Instruction-boundary checks
    - Structural anomaly hints (delimiter / fence density)
    - Optional HF classifier score (extras `ml`)
    - Tiered risk actions
    """

    def __init__(
        self,
        config: Optional[BaselineConfig] = None,
        rules: Optional[Sequence[Rule]] = None,
    ):
        self.config = config or BaselineConfig()
        self.rules = tuple(rules or DEFAULT_RULES)
        self._compiled_rules = [
            (rule, re.compile(rule.pattern, re.IGNORECASE | re.DOTALL))
            for rule in self.rules
        ]
        self._compiled_output_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.config.sensitive_output_patterns
        ]
        self._re_obfuscation = re.compile(
            r"(base64|rot13|hex|unicode)\s*(decode|decode it|deobfuscate)",
            re.IGNORECASE,
        )
        self._re_xml_boundary = re.compile(r"(<\s*system\s*>|<\s*developer\s*>)", re.IGNORECASE)
        self._re_structured_role = re.compile(
            r"```(?:json|yaml)?\s*[\[{].*\"role\"\s*:\s*\"(system|developer)\"",
            re.IGNORECASE | re.DOTALL,
        )
        self._re_role_markers = re.compile(r"\b(system|developer|assistant|tool)\s*:\s*", re.IGNORECASE)
        self._re_zh_role_prefix = re.compile(
            r"(?:^|\n)\s*(系统|开发者|助手|工具)\s*[：:]",
            re.MULTILINE,
        )
        self._re_line_role_en = re.compile(r"^\s*(system|developer|assistant)\s*:\s*", re.I)
        self._re_line_role_zh = re.compile(r"^\s*(系统|开发者|助手)\s*[：:]")
        self._ml = build_ml_scorer(
            self.config.enable_ml_scorer,
            self.config.ml_model_name,
            self.config.ml_score_cap,
        )

    def detect(self, text: str) -> DetectionResult:
        normalized = self._sanitize_input(text) if self.config.enable_input_sanitization else (text or "")
        evidence = DetectionEvidence()

        rule_score, attack_type = self._rule_score(normalized, evidence)
        heuristic_score = self._heuristic_score(normalized, evidence)
        boundary_score = self._boundary_score(normalized, evidence) if self.config.enable_boundary_checks else 0.0
        structural_score = self._structural_score(normalized, evidence)
        ml_score = self._ml.score(normalized) if self.config.enable_ml_scorer else 0.0
        ml_score = min(ml_score, self.config.ml_score_cap)

        confidence = min(
            1.0,
            rule_score + heuristic_score + boundary_score + structural_score + ml_score,
        )
        action = self._decide_action(confidence)
        is_injection = action in (RiskAction.CHALLENGE, RiskAction.BLOCK)

        if attack_type == "unknown" and evidence.boundary_hits:
            attack_type = "boundary_confusion"
        elif attack_type == "unknown" and evidence.heuristic_hits:
            attack_type = "heuristic_suspicion"

        if evidence.rule_hits and confidence >= self.config.block_threshold:
            evidence.notes.append("High-confidence attack matched explicit rules.")
        elif confidence >= self.config.challenge_threshold:
            evidence.notes.append("Medium-high risk: require user confirmation or manual review.")

        return DetectionResult(
            is_injection=is_injection,
            confidence=confidence,
            attack_type=attack_type,
            action=action,
            sanitized_text=normalized,
            evidence=evidence,
        )

    def sanitize_output(self, output_text: str) -> str:
        if not self.config.enable_output_filter or not output_text:
            return output_text

        sanitized = output_text
        for pattern in self._compiled_output_patterns:
            sanitized = pattern.sub("[REDACTED_SENSITIVE_CONTEXT]", sanitized)
        return html.escape(sanitized, quote=False)

    def _sanitize_input(self, text: str) -> str:
        if not text:
            return ""
        normalized = _ZW_SPACE_RE.sub("", text)
        normalized = re.sub(r"[ \t]+", " ", normalized)
        normalized = re.sub(r"\n{3,}", "\n\n", normalized)
        normalized = re.sub(r"(.)\1{8,}", r"\1\1\1", normalized)
        return normalized.strip()

    def _rule_score(self, text: str, evidence: DetectionEvidence) -> tuple[float, str]:
        score = 0.0
        matched_attack_type = "unknown"

        for rule, pattern in self._compiled_rules:
            if score >= 0.90:
                break
            if pattern.search(text):
                score += rule.weight
                evidence.rule_hits.append(rule.name)
                if matched_attack_type == "unknown":
                    matched_attack_type = rule.attack_type

        return min(score, 0.90), matched_attack_type

    def _heuristic_score(self, text: str, evidence: DetectionEvidence) -> float:
        text_lower = text.lower()
        score = 0.0

        imperative_count, target_count = english_imperative_and_sensitive_counts(text_lower)

        if imperative_count >= 2:
            score += 0.16
            evidence.heuristic_hits.append("multi_imperative_tokens")
        if target_count >= 2:
            score += 0.14
            evidence.heuristic_hits.append("sensitive_target_density")
        if imperative_count >= 1 and target_count >= 1:
            score += 0.12
            evidence.heuristic_hits.append("imperative_plus_sensitive_targets")
        if self._re_obfuscation.search(text_lower):
            score += 0.12
            evidence.heuristic_hits.append("obfuscation_hint")

        zi, zs = chinese_imperative_and_sensitive_counts(text)
        if zi >= 2:
            score += 0.14
            evidence.heuristic_hits.append("zh_multi_imperative")
        if zs >= 2:
            score += 0.12
            evidence.heuristic_hits.append("zh_sensitive_density")
        if zi >= 1 and zs >= 1:
            score += 0.11
            evidence.heuristic_hits.append("zh_imperative_plus_sensitive")

        return min(score, _HEURISTIC_SCORE_CAP)

    def _boundary_score(self, text: str, evidence: DetectionEvidence) -> float:
        score = 0.0

        role_marker_hits = len(self._re_role_markers.findall(text))
        if role_marker_hits > 0:
            score += min(0.2, 0.05 * role_marker_hits)
            evidence.boundary_hits.append("faked_role_markers")

        zh_role_lines = len(self._re_zh_role_prefix.findall(text))
        if zh_role_lines > 0:
            score += min(0.18, 0.045 * zh_role_lines)
            evidence.boundary_hits.append("zh_role_colon_prefix")

        if self._re_xml_boundary.search(text):
            score += 0.12
            evidence.boundary_hits.append("xml_like_role_boundary")

        if self._re_structured_role.search(text):
            score += 0.15
            evidence.boundary_hits.append("structured_role_injection")

        return min(score, 0.35)

    def _structural_score(self, text: str, evidence: DetectionEvidence) -> float:
        if not self.config.enable_structural_scores:
            return 0.0
        score = 0.0
        if text.count("```") >= 4:
            score += 0.05
            evidence.heuristic_hits.append("code_fence_density")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        role_like = sum(
            1
            for ln in lines
            if self._re_line_role_en.match(ln) or self._re_line_role_zh.match(ln)
        )
        if role_like >= 2:
            score += 0.05
            evidence.boundary_hits.append("multi_role_like_lines")
        return min(score, 0.10)

    def _decide_action(self, confidence: float) -> RiskAction:
        if confidence >= self.config.block_threshold:
            return RiskAction.BLOCK
        if confidence >= self.config.challenge_threshold:
            return RiskAction.CHALLENGE
        if confidence >= self.config.alert_threshold:
            return RiskAction.ALERT
        return RiskAction.ALLOW
