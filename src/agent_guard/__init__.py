"""
agent_guard — 可插拔的客户端 Agent 安全网关

整合思路来自：
- agent-security：Prompt 注入检测、PII 扫描/脱敏、安全日志
- Microsoft agent-governance：策略评估、工具调用门禁、审计与放行/拒绝语义

与本仓库 ``dlp`` 包配合做数据外泄监控与脱敏。
"""

from .core.config import GuardConfig
from .core.types import ChatCheckResult, ToolCheckResult, AuditEventType
from .facade import AgentGuard
from .gateway import SecureLLMGateway, create_default_gateway_session
from .integration.hooks import guarded_executor, guarded_tool_call
from .integration.openai_wrap import attach_openai_chat_guard

__all__ = [
    "AgentGuard",
    "GuardConfig",
    "ChatCheckResult",
    "ToolCheckResult",
    "AuditEventType",
    "SecureLLMGateway",
    "create_default_gateway_session",
    "guarded_tool_call",
    "guarded_executor",
    "attach_openai_chat_guard",
]
