import os
import sys

# Ensure repo root is on sys.path so `import dlp` works even when running this file directly.
_HERE = os.path.dirname(__file__)
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from dlp.logger import DLPLogger
from dlp.sanitizers.pii_redactor import PIIRedactor

logger = DLPLogger()  # 默认写到 dlp/logs
redactor = PIIRedactor(logger=logger)
print(redactor.redact("Email a@b.com and phone 415-555-2671."))