#!/usr/bin/env python3
"""
最小可运行演示：请先设置 PYTHONPATH=项目根目录下的 src。

  cd NextChat && PYTHONPATH=src python src/agent_guard/examples/minimal_demo.py
"""

from __future__ import annotations

import json
import os
import tempfile

from agent_guard import AgentGuard, GuardConfig, guarded_executor
from agent_guard.testing import default_attack_suite, run_red_team_suite


def main():
    approvals: list[str] = []

    def ui_consent(tool: str, args: dict) -> bool:
        approvals.append(tool)
        print(f"[Consent] Auto-approve sensitive tool={tool} keys={list(args)}")
        return True

    safe_root = tempfile.mkdtemp(prefix="demo_agent_") + os.sep

    cfg = GuardConfig(
        audit_log_path=None,
        enforce_tool_allowlist=True,
        allowed_tools={"write_file", "fetch_url"},
        path_allow_prefixes=(safe_root,),
        url_allowed_hosts=("127.0.0.1",),
        injection_confidence_threshold=0.72,
    )
    guard = AgentGuard(cfg, consent_callback=ui_consent)

    print("=== 红队自检 ===")
    blocked, mismatches_n, mismatches = run_red_team_suite(guard, default_attack_suite())
    print(json.dumps({"blocked_expected_attacks": blocked, "mismatches": mismatches}, indent=2, ensure_ascii=False))

    print("\n=== 工具链路（路径沙箱 + 敏感授权 + DLP） ===")

    def dispatch(tool_name: str, arguments: dict):
        if tool_name == "write_file":
            return {"ok": True, "path": arguments["path"]}
        if tool_name == "fetch_url":
            return {"ok": True, "url": arguments["url"]}
        raise NotImplementedError(tool_name)

    run = guarded_executor(guard, dispatch)

    ok_path = os.path.join(safe_root, "demo.txt")
    print("write_file:", run("write_file", {"path": ok_path, "content": "no pii"}))

    try:
        run("write_file", {"path": "/etc/passwd", "content": "x"})
    except Exception as e:
        print("blocked bad path:", e)

    snap = guard.observability_snapshot()
    print("\n=== 可观测快照 ===")
    print(json.dumps(snap, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
