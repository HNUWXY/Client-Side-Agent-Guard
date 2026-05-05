"""
与 agent-security 保持同一思路：正则 + 轻量启发式，无外部模型依赖。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass
class InjectionDetectionResult:
    is_injection: bool
    confidence: float
    attack_type: str
    matched_patterns: List[str]


class PromptInjectionDetector:
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?previous\s+instructions",
        r"forget\s+(all\s+)?previous\s+instructions",
        r"override\s+(all\s+)?previous\s+instructions",
        r"(repeat|show|print|display|reveal)\s+(the\s+)?system\s+prompt",
        r"what\s+(is|are)\s+(your|the)\s+instructions",
        r"show\s+me\s+your\s+instructions",
        r"you\s+are\s+now\s+",
        r"act\s+as\s+",
        r"pretend\s+(to\s+be|you\s+are)",
        r"roleplay\s+as",
        r"```\s*system",
        r"\[system\]",
        r"<\|im_start\|>system",
        r"DAN\s+mode",
        r"developer\s+mode",
        r"jailbreak",
        r"for\s+research\s+purposes\s+only",
        r"output\s+.*\s+without\s+any\s+restrictions",
        r"bypass\s+content\s+policy",
    ]

    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]

    def detect(self, text: str) -> InjectionDetectionResult:
        if not text:
            return InjectionDetectionResult(False, 0.0, "none", [])

        matched = [p.pattern for p in self.patterns if p.search(text)]
        if matched:
            confidence = min(1.0, 0.6 + len(matched) * 0.15)
            attack_type = self._attack_type(matched)
            return InjectionDetectionResult(
                confidence >= self.threshold,
                confidence,
                attack_type,
                matched,
            )

        heuristic = self._heuristic(text)
        if heuristic > 0.5:
            return InjectionDetectionResult(
                heuristic >= self.threshold,
                heuristic,
                "heuristic_detection",
                [],
            )
        return InjectionDetectionResult(False, 0.0, "none", [])

    def _heuristic(self, text: str) -> float:
        score = 0.0
        low = text.lower()
        instruction_words = ["ignore", "disregard", "forget", "override", "bypass", "reveal", "show", "repeat"]
        instruction_count = sum(1 for w in instruction_words if w in low)
        if instruction_count >= 2:
            score += 0.3
        system_words = ["system", "admin", "root", "sudo", "privileged"]
        system_count = sum(1 for w in system_words if w in low)
        if system_count >= 1 and instruction_count >= 1:
            score += 0.3
        if "```" in text or "[system]" in low or "<|" in text:
            score += 0.4
        return min(1.0, score)

    def _attack_type(self, patterns: List[str]) -> str:
        blob = " ".join(patterns)
        if "override" in blob or "previous" in blob:
            return "instruction_override"
        if "system" in blob or "prompt" in blob:
            return "system_prompt_extraction"
        if "act" in blob or "pretend" in blob:
            return "role_switching"
        return "generic_injection"
