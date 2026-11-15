"""统一脱敏。所有日志、错误输出和外部命令输出在显示前都要经过 redact()。"""

from __future__ import annotations

import re

MASK = "***"

_PEM_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
)
_AUTH_URL = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]+@")
_KEY_VALUE = re.compile(
    r"""(["']?(?:password|passwd|token|secret|private_key|mac_key)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,}]+)""",
    re.I,
)
_KEY_HINT = re.compile(r"passw|token|secret|_key", re.I)  # _KEY_VALUE 能命中的必要条件
_SECRET_KEYS = {"password", "passwd", "token", "secret", "private_key", "mac_key", "key"}


class Redactor:
    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._ordered: tuple[str, ...] = ()

    def register(self, value: str) -> None:
        if value and value not in self._secrets:
            self._secrets.add(value)
            # 长的在前，避免一个秘密是另一个的子串时泄漏剩余部分；只在登记时排序一次
            self._ordered = tuple(sorted(self._secrets, key=len, reverse=True))

    def redact(self, text: str) -> str:
        # 每一行日志都会经过这里：先用便宜的子串检查排除绝大多数不含敏感内容的行
        for secret in self._ordered:
            if secret in text:
                text = text.replace(secret, MASK)
        if "PRIVATE KEY-----" in text:
            text = _PEM_KEY.sub(MASK, text)
        if "://" in text and "@" in text:
            text = _AUTH_URL.sub(lambda m: m.group(1) + MASK + "@", text)
        if _KEY_HINT.search(text):
            text = _KEY_VALUE.sub(lambda m: m.group(1) + MASK, text)
        return text

    def redact_obj(self, obj):
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, dict):
            return {
                k: (MASK if isinstance(k, str) and k.lower() in _SECRET_KEYS and isinstance(v, str)
                    else self.redact_obj(v))
                for k, v in obj.items()
            }
        if isinstance(obj, (list, tuple)):
            return [self.redact_obj(v) for v in obj]
        return obj


REDACTOR = Redactor()
redact = REDACTOR.redact
