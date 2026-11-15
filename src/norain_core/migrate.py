"""配置 Schema 的迁移入口。

迁移规则集中在这里，按版本逐级执行；配置模型只负责字段校验，不再各自实现
一套迁移规则。当前 Schema 只有版本 1，所以唯一的迁移是「0 → 1」：旧配置
没有顶层 ``schema``，补上并按版本 1 处理，同时返回可展示的 warning。

版本策略（docs/decisions/0004 通用规则 1）：

- 缺失 ``schema``：按版本 1 处理并给出 warning；
- 版本高于当前：拒绝加载，错误路径固定为 ``schema``；
- 版本低于当前：从该版本开始逐级迁移到当前版本。

迁移只作用于内存里的字典，不写回配置文件，所以这里没有「迁移前备份原文件」
这一步。唯一会写盘的路径是命令行的改配置（``norain/cli.py`` 的 ``_save_config``），
它在写之前本来就会 ``atomic.backup``。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .errors import FieldError, config_error

SCHEMA_VERSION = 1
"""当前配置 Schema 版本。两端模型都从这里取，避免各写一个常量。"""


@dataclass(frozen=True)
class MigrationResult:
    data: dict
    warnings: tuple[str, ...] = ()


def _step_0_to_1(data: dict) -> dict:
    """版本 1 之前的配置没有顶层 ``schema``；补上即可，字段含义没有变化。"""
    out = dict(data)
    out["schema"] = 1
    return out


# 版本 N 的配置 -> 版本 N+1 的配置。每一级只处理自己这一版的变化。
_STEPS: dict[int, Callable[[dict], dict]] = {0: _step_0_to_1}


def migrate(data: dict, *, current: int = SCHEMA_VERSION, source: str = "配置") -> MigrationResult:
    """把输入数据迁移到当前 Schema，并返回需要展示的 warning。

    版本字段本身不可用（类型不对、为负、高于当前）时在这里就拒绝，不等字段
    校验：否则「版本更高但含有新字段」的配置会先撞上「未知字段」，用户看不到
    真正的原因。
    """
    raw = data.get("schema")
    if raw is None:
        version = 0
    elif not isinstance(raw, int) or isinstance(raw, bool):
        # 类型不对交给配置模型报字段类型错误，这里不抢答。
        return MigrationResult(data)
    elif raw < 0 or raw > current:
        raise config_error([FieldError("schema", f"不支持的配置版本 {raw}，本程序支持 {current}")])
    elif raw == current:
        return MigrationResult(data)
    else:
        version = raw

    migrated = data
    for v in range(version, current):
        step = _STEPS.get(v)
        if step is None:
            raise config_error([FieldError("schema", f"缺少从版本 {v} 到版本 {v + 1} 的迁移规则")])
        migrated = step(migrated)

    warnings: tuple[str, ...] = ()
    if version == 0:
        warnings = (f"{source} 缺少顶层 schema，已按版本 {current} 处理；建议补上 schema = {current}",)
    return MigrationResult(migrated, warnings)


def attach_warnings(cfg: object, result: MigrationResult) -> None:
    """把迁移 warning 挂到配置对象上，供展示入口读取。"""
    cfg._config_warnings = list(result.warnings)  # noqa: SLF001 两端模型都声明了这个 PrivateAttr


def migration_warnings(cfg: object) -> list[str]:
    """配置加载时的迁移 warning（两端模型通用）。"""
    return list(getattr(cfg, "_config_warnings", ()) or ())
