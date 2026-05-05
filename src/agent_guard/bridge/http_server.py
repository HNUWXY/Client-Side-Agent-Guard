"""
本地 HTTP 桥梁：供 NextChat/Web/Tauri 通过 fetch 调用安全检查。

仅用于开发与内网联调；生产应加鉴权、mTLS 或本机 Unix socket。

用法::
    PYTHONPATH=src python -m agent_guard.bridge.http_server --port 8765
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Lock
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from ..core.config import GuardConfig
from ..facade import AgentGuard
from ..gateway.entry import SecureLLMGateway


class _SessionBridge:
    """会话级 Guard + 将单次请求里的「用户已授权敏感工具」传入 Consent 回调。"""

    __slots__ = ("gateway", "guard", "_approve_this_request")

    def __init__(self, audit_dir: str | None):
        cfg = GuardConfig(
            audit_log_path=os.path.join(audit_dir, "audit.jsonl") if audit_dir else None,
            injection_confidence_threshold=0.72,
        )
        self._approve_this_request = False

        def consent(tool: str, arguments: Dict[str, Any]) -> bool:
            return self._approve_this_request

        self.guard = AgentGuard(cfg, consent_callback=consent)
        self.gateway = SecureLLMGateway(self.guard)

    def begin_request(self, approve_sensitive_tools: bool) -> None:
        self._approve_this_request = approve_sensitive_tools

    def end_request(self) -> None:
        self._approve_this_request = False


class BridgeRegistry:
    def __init__(self, audit_dir: str | None):
        self._audit_dir = audit_dir
        self._sessions: Dict[str, _SessionBridge] = {}
        self._lock = Lock()

    def session(self, session_id: str) -> _SessionBridge:
        with self._lock:
            sid = session_id or "default"
            if sid not in self._sessions:
                self._sessions[sid] = _SessionBridge(self._audit_dir)
            return self._sessions[sid]


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.end_headers()
    handler.wfile.write(body)


def make_handler(registry: BridgeRegistry):
    class Handler(BaseHTTPRequestHandler):
        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

        def do_GET(self) -> None:
            u = urlparse(self.path)
            if u.path == "/guard/health":
                _json_response(self, 200, {"ok": True, "service": "agent_guard"})
                return
            if u.path == "/guard/snapshot":
                qs = parse_qs(u.query)
                sid = (qs.get("session_id") or ["default"])[0]
                b = registry.session(sid)
                _json_response(self, 200, b.guard.observability_snapshot())
                return
            _json_response(self, 404, {"error": "not_found"})

        def do_POST(self) -> None:
            u = urlparse(self.path)
            if u.path not in ("/guard/chat", "/guard/tool", "/guard/prepare_messages"):
                _json_response(self, 404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid_json"})
                return

            session_id = str(body.get("session_id") or "default")
            approve = bool(body.get("approve_sensitive_tools", False))
            b = registry.session(session_id)
            b.begin_request(approve)

            try:
                if u.path == "/guard/chat":
                    text = body.get("text") or ""
                    r = b.guard.check_user_message(text)
                    _json_response(
                        self,
                        200,
                        {
                            "allowed": r.allowed,
                            "block_reason": r.block_reason,
                            "sanitized_text": r.sanitized_text,
                            "threat_signals": r.threat_signals,
                        },
                    )
                    return

                if u.path == "/guard/prepare_messages":
                    raw_msgs = body.get("messages")
                    if raw_msgs is None:
                        _json_response(self, 400, {"error": "missing_messages"})
                        return
                    if not isinstance(raw_msgs, list):
                        _json_response(self, 400, {"error": "messages_must_be_array"})
                        return
                    out = b.gateway.prepare_messages(raw_msgs)
                    _json_response(
                        self,
                        200,
                        {
                            "allowed": out.allowed,
                            "block_reason": out.block_reason,
                            "messages": out.messages,
                            "threat_signals": out.threat_signals,
                        },
                    )
                    return

                tool = body.get("tool") or body.get("tool_name")
                args = body.get("arguments") or {}
                if not isinstance(args, dict):
                    _json_response(self, 400, {"error": "arguments_must_be_object"})
                    return
                if not tool:
                    _json_response(self, 400, {"error": "missing_tool"})
                    return
                v = b.guard.before_tool(str(tool), args)
                _json_response(
                    self,
                    200,
                    {
                        "allowed": v.allowed,
                        "block_reason": v.block_reason,
                        "sanitized_arguments": v.sanitized_arguments,
                        "consent_required": v.consent_required,
                    },
                )
            finally:
                b.end_request()

        def log_message(self, fmt: str, *args: Any) -> None:
            print("[agent_guard-http]", fmt % args)

    return Handler


def run_http_bridge(host: str = "127.0.0.1", port: int = 8765, audit_dir: str | None = None) -> None:
    registry = BridgeRegistry(audit_dir)
    handler = make_handler(registry)
    server = HTTPServer((host, port), handler)
    print(f"agent_guard HTTP bridge listening on http://{host}:{port}")
    print("  POST /guard/chat               body: {session_id?, text, approve_sensitive_tools?}")
    print("  POST /guard/prepare_messages   body: {session_id?, messages:[{role,content}], ...}")
    print("  POST /guard/tool               body: {session_id?, tool, arguments, approve_sensitive_tools?}")
    print("  GET  /guard/snapshot?session_id=...")
    server.serve_forever()


def main() -> None:
    p = argparse.ArgumentParser(description="AgentGuard HTTP bridge for NextChat etc.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument(
        "--audit-dir",
        default=None,
        help="若设置，则每个会话的 JSONL 审计写入此目录",
    )
    args = p.parse_args()
    run_http_bridge(args.host, args.port, args.audit_dir)


if __name__ == "__main__":
    main()
