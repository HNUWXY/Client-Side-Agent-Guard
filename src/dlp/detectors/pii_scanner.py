from __future__ import annotations

import re
from typing import Iterable, List, Optional

from ..core.types import PIIDetection, PIIType


class PIIScanner:
    """
    Regex-based PII scanner.

    Patterns intentionally mirror the basic types in agent_security,
    but SSN is adapted to China's Resident Identity Card (RIC):
    - RIC, credit card, email, phone, IP address
    """

    PATTERNS: dict[PIIType, str] = {
        PIIType.RIC: r"\b\d{17}[0-9Xx]\b",
        PIIType.CREDIT_CARD: r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        PIIType.EMAIL: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        PIIType.PHONE: r"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
        PIIType.IP_ADDRESS: r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    }

    def __init__(self, pii_types: Optional[Iterable[str]] = None):
        """
        Args:
            pii_types: iterable of type strings, e.g. ["email", "phone"].
                      If None, defaults to ric/credit_card/email/phone/ip_address.
        """
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
        """Return span-based PII detections in text."""
        if not text:
            return []

        detections: list[PIIDetection] = []
        for pii_type, pat in self._compiled.items():
            for m in pat.finditer(text):
                detections.append(
                    PIIDetection(
                        type=pii_type,
                        start_pos=m.start(),
                        end_pos=m.end(),
                        confidence=0.9,
                    )
                )
        return detections

    def contains_pii(self, text: str) -> bool:
        """Quick boolean check."""
        return bool(self.scan(text))

