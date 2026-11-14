"""结构化日志：JSON Lines，统一脱敏，按大小轮转。"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

from .redact import REDACTOR

LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


def new_op_id() -> str:
    return uuid.uuid4().hex[:12]


class RotatingFile:
    def __init__(self, path: Path, *, max_bytes: int, keep: int) -> None:
        self.path, self.max_bytes, self.keep = path, max_bytes, max(keep, 1)
        self._lock = threading.Lock()

    def write_line(self, line: str) -> None:
        data = (line.rstrip("\n") + "\n").encode("utf-8", "replace")
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size + len(data) > self.max_bytes:
                    self._rotate()
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
                with os.fdopen(fd, "ab") as f:
                    f.write(data)
            except OSError:
                pass  # 日志写失败不能拖垮主流程

    def _rotate(self) -> None:
        name = self.path.name
        self.path.with_name(f"{name}.{self.keep}").unlink(missing_ok=True)
        for i in range(self.keep - 1, 0, -1):
            src = self.path.with_name(f"{name}.{i}")
            if src.exists():
                os.replace(src, self.path.with_name(f"{name}.{i + 1}"))
        os.replace(self.path, self.path.with_name(f"{name}.1"))


class Logger:
    def __init__(self, module: str, *, op_id: str | None = None, sink: RotatingFile | None = None,
                 stderr: bool = True, level: str = "info") -> None:
        self.module, self.op_id, self.sink = module, op_id or new_op_id(), sink
        self.stderr, self.level = stderr, LEVELS.get(level, 20)

    def log(self, level: str, event: str, **detail) -> None:
        if LEVELS[level] < self.level:
            return
        record = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "level": level,
            "module": self.module,
            "op_id": self.op_id,
            "event": event,
            "detail": REDACTOR.redact_obj(detail),
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if self.sink:
            self.sink.write_line(line)
        if self.stderr:
            print(line, file=sys.stderr, flush=True)

    def debug(self, event, **d): self.log("debug", event, **d)
    def info(self, event, **d): self.log("info", event, **d)
    def warn(self, event, **d): self.log("warn", event, **d)
    def error(self, event, **d): self.log("error", event, **d)
