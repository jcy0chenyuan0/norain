"""sing-box 二进制定位、版本检查和 check 包装。锁定策略见 docs/decisions/0002。

注意：`sing-box version` 的输出格式和 `check` 的行为是按官方文档推定的，
尚未用真实二进制验证（见 docs/reports/phase-1.md「未验证项目」）。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import (BIZ_BINARY_MISSING, BIZ_CONFIG, EXIT_DEPENDENCY, EXIT_EXTERNAL,
                     EXIT_TIMEOUT, NorainError)
from .redact import redact

# 必须与 third_party/singbox.lock.toml 一致（tests/test_singbox_lock.py 检查）
PINNED_VERSION = "1.14.4"
DEFAULT_PATH = "/usr/local/bin/sing-box"


@dataclass(frozen=True)
class BinaryInfo:
    path: Path
    version: str
    tags: frozenset[str]


def locate(explicit: str | None = None, *, defaults: tuple[str, ...] = (DEFAULT_PATH,),
           env_name: str = "NORAIN_SERVER_SINGBOX") -> Path:
    """显式路径只认它自己；否则依次查默认位置和 PATH。"""
    candidates = [explicit] if explicit else [*defaults, shutil.which("sing-box")]
    for c in candidates:
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return Path(c)
    if explicit:
        msg = f"sing-box 不存在或不可执行：{explicit}"
    else:
        msg = f"找不到 sing-box（已查找 {'、'.join(defaults)} 和 PATH）"
    raise NorainError(msg, exit_code=EXIT_DEPENDENCY, business_code=BIZ_BINARY_MISSING,
                      module="singbox",
                      hint=f"安装 sing-box {PINNED_VERSION}，或用 {env_name} 指定路径")


def _run(args: list[str], *, timeout: float) -> subprocess.CompletedProcess:
    try:
        # 显式 UTF-8：Windows 上 locale 是 GBK，按 GBK 解码会抛 UnicodeDecodeError，
        # 读线程一崩 stdout/stderr 就变成 None，后面的判断全部失效。
        return subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise NorainError(f"{args[0]} {args[1]} 超时（{timeout:.0f} 秒）", exit_code=EXIT_TIMEOUT,
                          module="singbox", retryable=True) from None
    except OSError as e:
        raise NorainError(f"无法执行 sing-box：{e}", exit_code=EXIT_DEPENDENCY,
                          business_code=BIZ_BINARY_MISSING, module="singbox") from None


def inspect(path: Path, *, timeout: float = 10.0) -> BinaryInfo:
    proc = _run([str(path), "version"], timeout=timeout)
    out = proc.stdout + proc.stderr
    m = re.search(r"sing-box version\s+v?(\S+)", out)
    if proc.returncode != 0 or not m:
        raise NorainError("无法识别 sing-box 版本输出", exit_code=EXIT_DEPENDENCY,
                          business_code=BIZ_BINARY_MISSING, module="singbox")
    tags = re.search(r"^Tags:\s*(.*)$", out, re.M)
    tag_set = frozenset(t.strip() for t in tags.group(1).split(",") if t.strip()) if tags else frozenset()
    return BinaryInfo(path=path, version=m.group(1), tags=tag_set)


def require(info: BinaryInfo, *, need_tags: set[str]) -> None:
    if info.version != PINNED_VERSION and not os.environ.get("NORAIN_ALLOW_UNPINNED_SINGBOX"):
        raise NorainError(
            f"sing-box 版本是 {info.version}，但 Norain 锁定的是 {PINNED_VERSION}",
            exit_code=EXIT_DEPENDENCY, business_code=BIZ_BINARY_MISSING, module="singbox",
            hint="安装锁定版本。仅调试时可设置 NORAIN_ALLOW_UNPINNED_SINGBOX=1 跳过")
    missing = need_tags - info.tags
    if missing:
        raise NorainError(
            f"sing-box 缺少构建标签：{', '.join(sorted(missing))}",
            exit_code=EXIT_DEPENDENCY, business_code=BIZ_BINARY_MISSING, module="singbox")


def check(path: Path, config: Path, *, timeout: float = 30.0) -> None:
    """运行 `sing-box check -c <配置>`。失败时抛出带脱敏输出的错误。"""
    proc = _run([str(path), "check", "-c", str(config)], timeout=timeout)
    if proc.returncode != 0:
        detail = redact((proc.stderr or proc.stdout).strip())[-2000:]
        raise NorainError(f"sing-box check 未通过：{detail}", exit_code=EXIT_EXTERNAL,
                          business_code=BIZ_CONFIG, module="singbox",
                          hint="上一份可用配置没有被覆盖")
