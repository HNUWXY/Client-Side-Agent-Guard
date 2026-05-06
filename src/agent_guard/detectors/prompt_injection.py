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
        r"(忽略|无视|忘记|覆盖|绕过|不要遵守).{0,12}(之前|前面|以上|上面|所有|原来).{0,12}(指令|规则|要求|约束|限制)",
        r"(显示|打印|输出|泄露|透露|告诉我|给我看).{0,12}(系统提示词|系统提示|系统指令|隐藏指令|开发者指令|内部指令)",
        r"(你现在是|从现在开始你是|现在开始扮演|扮演|假装).{0,12}(系统管理员|管理员|开发者|root|超级用户|无约束助手)",
        r"(开启|进入|启用).{0,8}(开发者模式|越狱模式|DAN模式|无限制模式)",
        r"(绕过|规避|跳过|不遵守).{0,12}(安全策略|内容策略|安全规则|限制|审查|过滤)",
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
        instruction_words = [
            "ignore",
            "disregard",
            "forget",
            "override",
            "bypass",
            "reveal",
            "show",
            "repeat",
            "忽略",
            "无视",
            "忘记",
            "覆盖",
            "绕过",
            "泄露",
            "透露",
            "显示",
            "输出",
        ]
        instruction_count = sum(1 for w in instruction_words if w in low)
        if instruction_count >= 2:
            score += 0.3
        system_words = [
            "system",
            "admin",
            "root",
            "sudo",
            "privileged",
            "系统",
            "管理员",
            "开发者",
            "超级用户",
            "隐藏指令",
            "系统提示",
        ]
        system_count = sum(1 for w in system_words if w in low)
        if system_count >= 1 and instruction_count >= 1:
            score += 0.3
        if "开发者模式" in text or "越狱模式" in text or "无限制模式" in text:
            score += 0.4
        if "```" in text or "[system]" in low or "<|" in text:
            score += 0.4
        return min(1.0, score)

    def _attack_type(self, patterns: List[str]) -> str:
        blob = " ".join(patterns)
        if "override" in blob or "previous" in blob:
            return "instruction_override"
        if any(w in blob for w in ("忽略", "无视", "忘记", "覆盖", "之前", "以上", "上面")):
            return "instruction_override"
        if "system" in blob or "prompt" in blob:
            return "system_prompt_extraction"
        if any(w in blob for w in ("系统提示", "系统指令", "隐藏指令", "开发者指令")):
            return "system_prompt_extraction"
        if "act" in blob or "pretend" in blob:
            return "role_switching"
        if any(w in blob for w in ("扮演", "假装", "你现在是", "从现在开始")):
            return "role_switching"
        if any(w in blob for w in ("绕过", "规避", "开发者模式", "越狱模式", "无限制模式")):
            return "policy_bypass"
        return "generic_injection"
