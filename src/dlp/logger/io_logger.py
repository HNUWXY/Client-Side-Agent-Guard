from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class IOEvent:
    direction: str  # "input" | "output"
    text: str
    request_id: Optional[str] = None
    tool: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class DLPLogger:
    """
    Minimal IO logger for DLP demos.

    Writes JSONL to dlp/logs by default, one file per UTC day.
    """

    def __init__(self, logs_dir: str | None = None, *, output_summary_chars: int = 200):
        if logs_dir is None:
            # d:\lark_ai\dlp\logger\io_logger.py -> d:\lark_ai\dlp\logs
            base = os.path.dirname(os.path.dirname(__file__))
            logs_dir = os.path.join(base, "logs")

        self.logs_dir = logs_dir
        self.output_summary_chars = max(0, int(output_summary_chars))
        os.makedirs(self.logs_dir, exist_ok=True)

    def log_input(self, text: str, *, request_id: str | None = None, tool: str | None = None, metadata: Dict[str, Any] | None = None) -> None:
        self._write(IOEvent(direction="input", text=text, request_id=request_id, tool=tool, metadata=metadata))

    def log_output(self, text: str, *, request_id: str | None = None, tool: str | None = None, metadata: Dict[str, Any] | None = None) -> None:
        self._write(IOEvent(direction="output", text=text, request_id=request_id, tool=tool, metadata=metadata))

    def log_output_summary(
        self,
        redacted_text: str,
        *,
        request_id: str | None = None,
        tool: str | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> None:
        """Log output using a truncated summary of redacted text."""
        summary = self._summarize(redacted_text)
        meta = dict(metadata or {})
        meta.setdefault("full_len", len(redacted_text or ""))
        meta.setdefault("summary_len", len(summary))
        self._write(IOEvent(direction="output", text=summary, request_id=request_id, tool=tool, metadata=meta))

    def _summarize(self, text: str) -> str:
        if text is None:
            return ""
        if self.output_summary_chars <= 0:
            return ""
        if len(text) <= self.output_summary_chars:
            return text
        return text[: self.output_summary_chars] + "…"

    def _write(self, event: IOEvent) -> None:
        ts = datetime.now(timezone.utc)
        path = os.path.join(self.logs_dir, f"io_{ts.strftime('%Y%m%d')}.jsonl")
        record = {
            "ts": ts.isoformat(),
            "direction": event.direction,
            "request_id": event.request_id,
            "tool": event.tool,
            "text": event.text,
            "metadata": event.metadata or {},
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

