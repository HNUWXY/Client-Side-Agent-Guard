"""
agent_guard 内置的轻量 PII 扫描与脱敏（不依赖仓库内其它目录）。

可被同目录其他同学提供的 DLP 包替换接入点：`AgentGuard(..., redactor=` / 后续扩展钩子）。
"""

from .scanner import PIIScanner
from .redactor import PIIRedactor
from .types import PIIDetection, PIIType

__all__ = ["PIIScanner", "PIIRedactor", "PIIDetection", "PIIType"]
