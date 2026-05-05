from __future__ import annotations


class GuardError(Exception):
    """与安全网关相关的业务异常基类。"""


class PromptBlocked(GuardError):
    """用户输入在未到达模型前被拦截（注入/边界等手段）。"""


class PolicyDenied(GuardError):
    """工具不在权限清单或未通过策略。"""


class SandboxViolation(GuardError):
    """路径或域名等沙箱约束未满足。"""


class DLPBlocked(GuardError):
    """敏感数据外泄检测触发阻断。"""


class ConsentRejected(GuardError):
    """用户拒绝敏感工具的首次授权。"""
