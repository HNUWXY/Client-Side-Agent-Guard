"""
命令行入口：启动可被 NextChat 等调用的本地 HTTP 服务。

用法::

    PYTHONPATH=src python -m agent_guard --port 8765
"""

from __future__ import annotations

from .bridge.http_server import main

if __name__ == "__main__":
    main()
