"""credential_ref 解析。语法和权限要求见 docs/decisions/0014。"""

from __future__ import annotations

import hashlib
import os
import secrets as _secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import BIZ_CONFIG, EXIT_CONFLICT, EXIT_PERMISSION, FieldError, NorainError, config_error
from .redact import REDACTOR

COMPAT_ENV = "NORAIN_PASSWORD"


@dataclass(frozen=True)
class Secret:
    value: str
    source: str  # 例如 "file:/etc/…" 或 "env:NORAIN_PASSWORD"，不含秘密值

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.value.encode()).hexdigest()[:8]


def check_private_file(path: Path, *, field: str) -> None:
    """要求文件只对属主可读写（POSIX）。Windows ACL 检查在客户端阶段实现。"""
    if os.name != "posix":
        return
    st = path.stat()
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise config_error([FieldError(
            field, f"{path} 的权限过宽（{stat.S_IMODE(st.st_mode):04o}），要求不宽于 0600")])
    if st.st_uid != os.geteuid() and os.geteuid() != 0:
        raise config_error([FieldError(field, f"{path} 的属主不是当前运行用户")])


def resolve(ref: str, *, field: str = "auth.credential_ref") -> Secret:
    ref = (ref or "").strip()
    if not ref:
        if os.environ.get(COMPAT_ENV):
            ref = f"env:{COMPAT_ENV}"
        else:
            raise config_error([FieldError(
                field, "未设置。使用 file:<路径> 或 env:<变量名>，或运行 secret generate")])
    scheme, _, rest = ref.partition(":")
    if scheme == "file" and rest:
        path = Path(rest).expanduser()
        if not path.is_file():
            raise config_error([FieldError(field, f"秘密文件不存在：{path}")])
        check_private_file(path, field=field)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except PermissionError:
            raise NorainError(f"无权读取秘密文件：{path}", exit_code=EXIT_PERMISSION,
                              business_code=BIZ_CONFIG, module="secrets") from None
        value = lines[0].strip() if lines else ""
        source = f"file:{path}"
    elif scheme == "env" and rest:
        value = os.environ.get(rest, "").strip()
        if not value:
            raise config_error([FieldError(field, f"环境变量 {rest} 未设置或为空")])
        source = f"env:{rest}"
    else:
        raise config_error([FieldError(
            field, "格式不支持。当前只支持 file:<路径> 和 env:<变量名>")])
    if not value:
        raise config_error([FieldError(field, f"秘密为空（{source}）")])
    REDACTOR.register(value)
    return Secret(value=value, source=source)


def generate_to_file(path: Path, *, force: bool = False) -> Secret:
    path = path.expanduser()
    if path.exists() and not force:
        raise NorainError(f"{path} 已存在。确认要覆盖时加 --force",
                          exit_code=EXIT_CONFLICT, module="secrets")
    path.parent.mkdir(parents=True, exist_ok=True)
    value = _secrets.token_urlsafe(24)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value + "\n")
    os.chmod(path, 0o600)
    REDACTOR.register(value)
    return Secret(value=value, source=f"file:{path}")
