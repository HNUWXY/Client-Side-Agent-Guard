"""
English heuristic token patterns (word-boundary) + Chinese substring lexicons.

Separated from detector.py to keep scoring logic readable.
"""

from __future__ import annotations

import re
from typing import Sequence

# Distinct English token types present in text (not raw frequency).
_EN_IMP_RE = re.compile(
    r"\b(ignore|reveal|bypass|override|disable|print|dump|leak)\b",
    re.I,
)
_EN_SENS_RE = re.compile(
    r"\b(system|prompt|policy|guardrails?|secrets?|tokens?|passwords?)\b",
    re.I,
)

ZH_IMPERATIVE = (
    "忽略",
    "无视",
    "绕过",
    "泄露",
    "导出",
    "解除",
    "越狱",
    "覆盖",
    "忘掉",
    "忘记",
    "取代",
    "关闭",
    "取消",
)

ZH_SENSITIVE = (
    "系统提示词",
    "内容审查",
    "安全策略",
    "系统提示",
    "提示词",
    "开发者",
    "上下文",
    "审查",
    "密钥",
    "凭据",
    "令牌",
    "密码",
    "护栏",
)


def english_imperative_and_sensitive_counts(text_lower: str) -> tuple[int, int]:
    imperative = len({m.lower() for m in _EN_IMP_RE.findall(text_lower)})
    sensitive = len({m.lower() for m in _EN_SENS_RE.findall(text_lower)})
    return imperative, sensitive


def _masked_phrase_hits(text: str, phrases: Sequence[str]) -> int:
    """Non-overlapping hits; longer phrases first to reduce nested substring inflation."""
    ordered = sorted({p for p in phrases if p}, key=len, reverse=True)
    n = len(text)
    covered = bytearray(n)
    hits = 0
    for p in ordered:
        plen = len(p)
        if plen == 0 or plen > n:
            continue
        i = 0
        while i <= n - plen:
            if any(covered[i + k] for k in range(plen)):
                i += 1
                continue
            if text[i : i + plen] == p:
                hits += 1
                for k in range(plen):
                    covered[i + k] = 1
                i += plen
            else:
                i += 1
    return hits


def chinese_imperative_and_sensitive_counts(text: str) -> tuple[int, int]:
    zi = sum(1 for t in ZH_IMPERATIVE if t in text)
    zs = _masked_phrase_hits(text, ZH_SENSITIVE)
    return zi, zs
