"""
第二条 Prompt 注入防御：识别「分隔符逃逸 / 伪造多段角色」等非纯关键词攻击。

思路：对齐赛题所述「指令边界识别」——在客户端侧对用户可控片段做结构化解耦与告警。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass
class BoundaryDetectionResult:
    suspicious: bool
    confidence: float
    reasons: List[str]
    sanitized: str


# 含未完成闭合围栏的 ```system 开头（常见注入起手式）
_FAKE_SYSTEM = re.compile(
    r"(?is)(\[\s*SYSTEM\s*\]|<\|im_start\|>system|<\|system\|>|```\s*system\b)",
)
_ROLE_FENCE = re.compile(r"(?m)^\s*(user|assistant|system)\s*:\s*", re.IGNORECASE)


class InstructionBoundaryGuard:
    def __init__(self, threshold: float = 0.75):
        self.threshold = threshold

    def analyze(self, text: str) -> BoundaryDetectionResult:
        if not text:
            return BoundaryDetectionResult(False, 0.0, [], "")

        reasons: List[str] = []
        score = 0.0

        if _FAKE_SYSTEM.search(text):
            reasons.append("fake_system_or_fence_marker")
            score += 0.82

        multi_role_lines = len(_ROLE_FENCE.findall(text))
        if multi_role_lines >= 2:
            reasons.append("multi_role_lines_in_user_turn")
            score += 0.35

        if text.count("```") >= 4:
            reasons.append("excessive_code_fences")
            score += 0.2

        suspicious = score >= self.threshold
        sanitized = self._sanitize(text) if reasons else text
        return BoundaryDetectionResult(suspicious, min(1.0, score), reasons, sanitized)

    def should_block(self, result: BoundaryDetectionResult, block_on_suspicion: bool) -> bool:
        return block_on_suspicion and result.suspicious

    def _sanitize(self, text: str) -> str:
        """弱化明显的伪造 system 围栏（不改变合法代码块中非 system 语义）"""

        cleaned = _FAKE_SYSTEM.sub("[removed_untrusted_fence]", text)
        return cleaned
