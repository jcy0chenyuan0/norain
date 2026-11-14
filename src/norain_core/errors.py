"""CLI 退出码、业务状态码和统一异常。约定见 docs/decisions/0003。"""

from __future__ import annotations

from dataclasses import dataclass, field

# CLI 进程退出码
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_PERMISSION = 4
EXIT_DEPENDENCY = 5
EXIT_TIMEOUT = 6
EXIT_CONFLICT = 7
EXIT_EXTERNAL = 8
EXIT_RESTART_LIMIT = 9  # 守护达到连续重启上限；systemd 单元用它阻止外层再拉起

# 服务端业务状态码（最初目标约定）
BIZ_OK = 0
BIZ_CONFIG = 110
BIZ_CERT = 120
BIZ_PORT_IN_USE = 130
BIZ_PROCESS_EXITED = 140
BIZ_BINARY_MISSING = 150
BIZ_RESTART_LIMIT = 160


@dataclass(frozen=True)
class FieldError:
    path: str
    message: str

    def as_dict(self) -> dict:
        return {"path": self.path, "message": self.message}


@dataclass
class NorainError(Exception):
    message: str
    exit_code: int = EXIT_FAILURE
    business_code: int = BIZ_OK
    module: str = "core"
    retryable: bool = False
    hint: str = ""
    field_errors: list[FieldError] = field(default_factory=list)

    def __str__(self) -> str:
        return self.message


def config_error(errors: list[FieldError], *, module: str = "config") -> NorainError:
    return NorainError(
        message="配置无效",
        exit_code=EXIT_CONFIG,
        business_code=BIZ_CONFIG,
        module=module,
        field_errors=errors,
        hint="按字段路径修正配置后重新运行 config validate",
    )
