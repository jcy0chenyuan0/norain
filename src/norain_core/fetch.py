"""取得、校验并解出 sing-box 二进制。锁定数据必须与 third_party/singbox.lock.toml 一致。

校验顺序：SHA-256 与锁定值一致 → 解出二进制 → 调用方再用 `sing-box version` 核对版本。
摘要是从发布页转录的，尚未对真实文件复核（docs/decisions/0002）。
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable

from .errors import EXIT_DEPENDENCY, EXIT_EXTERNAL, NorainError
from .singbox import PINNED_VERSION

BASE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{PINNED_VERSION}/"
ASSETS: dict[str, tuple[str, str]] = {
    "linux-amd64": (f"sing-box-{PINNED_VERSION}-linux-amd64.tar.gz",
                    "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"),
    "linux-arm64": (f"sing-box-{PINNED_VERSION}-linux-arm64.tar.gz",
                    "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"),
    "windows-amd64": (f"sing-box-{PINNED_VERSION}-windows-amd64.zip",
                      "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"),
    "windows-arm64": (f"sing-box-{PINNED_VERSION}-windows-arm64.zip",
                      "8cd0a4d0cd8cd480be5731ac31f17038969a42d12add9feb6e031fd43d85bbae"),
}
_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}

Downloader = Callable[[str, Path], None]


def target(system: str | None = None, machine: str | None = None) -> str:
    system = (system or platform.system()).lower()
    arch = _ARCH.get((machine or platform.machine()).lower())
    key = f"{system}-{arch}"
    if key not in ASSETS:
        raise NorainError(f"不支持的平台：{system} {machine or platform.machine()}",
                          exit_code=EXIT_DEPENDENCY, business_code=150, module="fetch")
    return key


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url, timeout=120) as r, dest.open("wb") as f:  # noqa: S310
        while chunk := r.read(1 << 20):
            f.write(chunk)


def obtain(tgt: str, cache_dir: Path, *, archive: Path | None = None,
           expected_sha256: str | None = None, downloader: Downloader = _download) -> Path:
    """返回通过校验的压缩包路径。archive 为本地文件时不联网。"""
    name, pinned = ASSETS[tgt]
    expected = (expected_sha256 or pinned).lower()
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / name
    if archive is not None:
        if not archive.is_file():
            raise NorainError(f"压缩包不存在：{archive}", exit_code=EXIT_DEPENDENCY, module="fetch")
        src = archive
    else:
        src = dest
        if not (dest.is_file() and sha256_file(dest) == expected):
            tmp = dest.with_suffix(dest.suffix + ".part")
            try:
                downloader(BASE_URL + name, tmp)
            except OSError as e:
                tmp.unlink(missing_ok=True)
                raise NorainError(f"下载 sing-box 失败：{e}", exit_code=EXIT_EXTERNAL, module="fetch",
                                  retryable=True,
                                  hint=f"手动下载 {BASE_URL + name} 后用 --singbox-archive 指定") from None
            os.replace(tmp, dest)
    actual = sha256_file(src)
    if actual != expected:
        if src == dest:
            dest.unlink(missing_ok=True)
        raise NorainError(f"sing-box 压缩包的 SHA-256 不符：期望 {expected}，实际 {actual}",
                          exit_code=EXIT_DEPENDENCY, business_code=150, module="fetch",
                          hint="文件可能损坏或被替换，已拒绝安装")
    if src != dest:
        dest.write_bytes(src.read_bytes())
    return dest


def extract_binary(archive: Path, dest: Path) -> None:
    """只读取名为 sing-box / sing-box.exe 的成员的内容写到 dest，不按压缩包里的路径落盘。"""
    data = None
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            for n in z.namelist():
                if n.rsplit("/", 1)[-1] == "sing-box.exe":
                    data = z.read(n)
    else:
        with tarfile.open(archive, "r:gz") as t:
            for m in t.getmembers():
                if m.isfile() and m.name.rsplit("/", 1)[-1] == "sing-box":
                    data = t.extractfile(m).read()
    if data is None:
        raise NorainError(f"压缩包里没有 sing-box 可执行文件：{archive}", exit_code=EXIT_DEPENDENCY,
                          business_code=150, module="fetch")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".new")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o755)
    os.replace(tmp, dest)


def install_singbox(dest: Path, cache_dir: Path, *, archive: Path | None = None,
                    expected_sha256: str | None = None, existing: Path | None = None,
                    need_tags: set[str] | None = None):
    """把通过校验的 sing-box 安装到 dest，返回 BinaryInfo。

    来源优先级：existing（已有的可执行文件，直接复制）→ archive（本地压缩包）→ 下载。
    新二进制的版本或构建标签不符时恢复原文件并抛出错误。
    """
    import shutil

    from . import singbox

    backup = dest.with_name(dest.name + ".bak")
    had_old = dest.is_file()
    if had_old:
        shutil.copy2(dest, backup)
    try:
        if existing is not None:
            if not existing.is_file():
                raise NorainError(f"sing-box 不存在：{existing}", exit_code=EXIT_DEPENDENCY,
                                  business_code=150, module="fetch")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if existing.resolve() != dest.resolve():
                tmp = dest.with_name(dest.name + ".new")
                shutil.copy2(existing, tmp)
                os.chmod(tmp, 0o755)
                os.replace(tmp, dest)
        else:
            pkg = obtain(target(), cache_dir, archive=archive, expected_sha256=expected_sha256)
            extract_binary(pkg, dest)
        info = singbox.inspect(dest)
        singbox.require(info, need_tags=need_tags or set())
    except NorainError:
        if had_old:
            os.replace(backup, dest)
        else:
            dest.unlink(missing_ok=True)
        raise
    backup.unlink(missing_ok=True)
    return info
