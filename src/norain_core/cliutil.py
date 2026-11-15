"""命令行共用的输出、错误显示和日志查看。"""

from __future__ import annotations

import collections
import json
import sys
import time
from pathlib import Path

from .errors import EXIT_FAILURE, EXIT_OK, NorainError
from .log import new_op_id
from .redact import redact


def out(args, payload: dict, text: str) -> None:
    if getattr(args, "json", False):
        print(json.dumps({"ok": True, "exit_code": 0, "business_code": 0, **payload},
                         ensure_ascii=False, indent=2))
    else:
        print(text)


def fail(args, e: NorainError) -> int:
    if getattr(args, "json", False):
        print(json.dumps({
            "ok": False, "exit_code": e.exit_code, "business_code": e.business_code,
            "error_id": new_op_id(), "module": e.module, "retryable": e.retryable,
            "detail": redact(e.message), "hint": e.hint,
            "field_errors": [f.as_dict() for f in e.field_errors],
        }, ensure_ascii=False, indent=2))
    else:
        print(f"错误：{redact(e.message)}", file=sys.stderr)
        for f in e.field_errors:
            print(f"  {f.path}: {redact(f.message)}", file=sys.stderr)
        if e.hint:
            print(f"提示：{e.hint}", file=sys.stderr)
        if e.business_code:
            print(f"业务码：{e.business_code}", file=sys.stderr)
    return e.exit_code or EXIT_FAILURE


def tail(path: Path, *, lines: int, follow: bool) -> int:
    if not path.exists():
        raise NorainError(f"还没有日志：{path}", module="log")
    f = path.open("r", encoding="utf-8", errors="replace")
    try:
        # 只保留最后 lines 行，不把整个日志（可达几十 MB）读进内存；-n 0 不输出历史
        sys.stdout.writelines(collections.deque(f, maxlen=max(lines, 0)))
        sys.stdout.flush()
        while follow:
            line = f.readline()
            if line:
                sys.stdout.write(line)
                sys.stdout.flush()
                continue
            time.sleep(0.5)
            try:
                if path.stat().st_size < f.tell():  # 日志已轮转
                    f.close()
                    f = path.open("r", encoding="utf-8", errors="replace")
            except FileNotFoundError:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        f.close()
    return EXIT_OK
