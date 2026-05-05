from __future__ import annotations

from .scanner import PIIScanner


class PIIRedactor:
    """同长度掩码脱敏（无外部日志依赖）。"""

    def __init__(self, mask_char: str = "*"):
        if not mask_char or len(mask_char) != 1:
            raise ValueError("mask_char must be a single character")
        self.mask_char = mask_char
        self.scanner = PIIScanner()

    def redact(self, text: str) -> str:
        if not text:
            return text
        detections = self.scanner.scan(text)
        if not detections:
            return text
        detections.sort(key=lambda d: d.start_pos, reverse=True)
        redacted = text
        for d in detections:
            length = max(0, d.end_pos - d.start_pos)
            replacement = self.mask_char * length
            redacted = redacted[: d.start_pos] + replacement + redacted[d.end_pos :]
        return redacted
