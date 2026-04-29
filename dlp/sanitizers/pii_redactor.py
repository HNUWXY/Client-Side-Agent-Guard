from __future__ import annotations

from typing import Optional

from ..detectors.pii_scanner import PIIScanner
from ..logger import DLPLogger


class PIIRedactor:
    """Redacts PII by masking with same-length characters."""

    def __init__(self, mask_char: str = "*", logger: DLPLogger | None = None):
        if not mask_char or len(mask_char) != 1:
            raise ValueError("mask_char must be a single character")
        self.mask_char = mask_char
        self.scanner = PIIScanner()
        self.logger = logger

    def redact(self, text: str) -> str:
        """
        Redact PII from text by replacing each detected span with mask_char
        repeated to the same length as the matched substring.
        """
        if not text:
            return text

        if self.logger:
            self.logger.log_input(text, tool="pii_redact")

        detections = self.scanner.scan(text)
        if not detections:
            if self.logger:
                # Output is identical to input; still record as "summary" for consistency.
                self.logger.log_output_summary(text, tool="pii_redact", metadata={"detections": 0})
            return text

        # Replace from end to start so earlier indices stay valid.
        detections.sort(key=lambda d: d.start_pos, reverse=True)

        redacted = text
        for d in detections:
            length = max(0, d.end_pos - d.start_pos)
            replacement = self.mask_char * length
            redacted = redacted[: d.start_pos] + replacement + redacted[d.end_pos :]
        if self.logger:
            self.logger.log_output_summary(
                redacted,
                tool="pii_redact",
                metadata={"detections": len(detections), "types": sorted({dd.type.value for dd in detections})},
            )
        return redacted

