from __future__ import annotations

import re
from typing import Iterable, List, Optional

from .types import PIIDetection, PIIType


class PIIScanner:
    """基于正则的 PII 跨度扫描（与先前 dlp 包逻辑等价，独立于其它目录）。"""

    PATTERNS: dict[PIIType, str] = {
        PIIType.RIC: r"\b\d{17}[0-9Xx]\b",
        PIIType.CREDIT_CARD: r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        PIIType.EMAIL: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        PIIType.PHONE: r"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
        PIIType.IP_ADDRESS: r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    }

    def __init__(self, pii_types: Optional[Iterable[str]] = None):
        self.pii_types = list(pii_types) if pii_types is not None else [
            "ric",
            "credit_card",
            "email",
            "phone",
            "ip_address",
        ]
        self._compiled: dict[PIIType, re.Pattern[str]] = {}
        for pii_type, pattern in self.PATTERNS.items():
            if pii_type.value in self.pii_types:
                self._compiled[pii_type] = re.compile(pattern)

    def scan(self, text: str) -> List[PIIDetection]:
        if not text:
            return []
        out: List[PIIDetection] = []
        for pii_type, pat in self._compiled.items():
            for m in pat.finditer(text):
                out.append(
                    PIIDetection(
                        type=pii_type,
                        start_pos=m.start(),
                        end_pos=m.end(),
                        confidence=0.9,
                    )
                )
        return out
