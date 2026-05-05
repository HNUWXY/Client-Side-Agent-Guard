"""将 AgentGuard 暴露给非 Python 宿主（如 NextChat / Electron）的适配层。"""

from .http_server import run_http_bridge

__all__ = ["run_http_bridge"]
