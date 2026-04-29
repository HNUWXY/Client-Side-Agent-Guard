"""
dlp - minimal sensitive data scanning + redaction utilities.

This package provides:
- Regex-based PII scanning (span-based detections)
- Same-length masking redaction
"""

from .detectors.pii_scanner import PIIScanner
from .sanitizers.pii_redactor import PIIRedactor

__all__ = ["PIIScanner", "PIIRedactor"]

