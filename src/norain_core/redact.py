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
_SECRET_KEYS = {"password", "passwd", "token", "secret", "private_key", "mac_key", "key"}


class Redactor:
    def __init__(self) -> None:
        self._secrets: set[str] = set()

    def register(self, value: str) -> None:
        if value:
            self._secrets.add(value)

    def redact(self, text: str) -> str:
        # 先替换长的秘密，避免一个秘密是另一个的子串时泄漏剩余部分
        for secret in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(secret, MASK)
        text = _PEM_KEY.sub(MASK, text)
        text = _AUTH_URL.sub(lambda m: m.group(1) + MASK + "@", text)
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
