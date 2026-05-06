from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..core.types import AuditEventType


class AuditSink:
    """
    JSONL 可观测性与内存环形视图（简易「面板」数据源）。

    与 agent-security 的 SecurityLogger 类似，条目为单行 JSON。
    """

    def __init__(self, path: Optional[str] = None, memory_max: int = 500):
        self.path = path
        self.memory_max = memory_max
        self._buf: List[Dict[str, Any]] = []

    def emit(
        self,
        event_type: AuditEventType,
        summary: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> str:
        eid = str(uuid.uuid4())
        row = {
            "id": eid,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type.value if isinstance(event_type, AuditEventType) else event_type,
            "summary": summary,
            "detail": detail or {},
        }
        self._buf.append(row)
        if len(self._buf) > self.memory_max:
            self._buf = self._buf[-self.memory_max :]
        if self.path:
            parent = os.path.dirname(os.path.abspath(self.path))
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return eid

    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self._buf[-limit:])

    def snapshots_for_demo(self) -> Dict[str, Any]:
        threats = sum(1 for r in self._buf if r.get("event_type") == AuditEventType.THREAT.value)
        denies = sum(
            1
            for r in self._buf
            if r.get("event_type")
            in (
                AuditEventType.POLICY_DENY.value,
                AuditEventType.SANDBOX_DENY.value,
                AuditEventType.DLP_DENY.value,
            )
        )
        return {
            "total_events": len(self._buf),
            "threat_events": threats,
            "blocked_events": denies,
            "last": self._buf[-5:] if self._buf else [],
        }


def safe_asdict(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return obj
