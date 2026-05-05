"""
统一网关：从大模型 / 智能体宿主接收「标准化的对话与工具意图」，在安全检测之后再交给具体后端。
"""

from .entry import SecureLLMGateway, create_default_gateway_session
from .types import MessagesPrepareOutcome, PlainToolOutcome

__all__ = [
    "SecureLLMGateway",
    "create_default_gateway_session",
    "MessagesPrepareOutcome",
    "PlainToolOutcome",
]
