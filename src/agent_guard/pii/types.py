from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PIIType(Enum):
    RIC = "ric"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"


@dataclass(frozen=True)
class PIIDetection:
    type: PIIType
    start_pos: int
    end_pos: int
    confidence: float = 0.9
