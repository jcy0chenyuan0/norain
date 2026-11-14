"""修复模块：把代理重置回最初状态。四种修复，各对应一条命令（`norain repair <级别>`）：

  file     文件修复：扫描程序目录，按哈希清单判断文件损坏或缺失，从安装包副本里重新解出。
  builtin  内置配置修复：清掉代理内部状态（生成的 sing-box 配置、选中的协议、学到的名单、
           错误记录），从 cfg.toml 重新生成。不动用户配置。
  full     完全配置修复：在 builtin 之上，把用户配置恢复为安装时的初始配置，并恢复计算机的
           配置（解除阻断对防火墙的修改、清除残留的系统代理、重新同步自启动项）。
  reload   重载修复：完全卸载并清除痕迹，再用安装包副本重新安装。

自维持模块只使用 file 和 builtin 两种。卸载部分是独立的命令（`norain uninstall`）。
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from norain_core import atomic, fetch, singbox
from norain_core.errors import EXIT_CONFLICT, NorainError
from norain_core.log import Logger
from norain_core.state import read_json, write_json

from .paths import Paths

PACKAGES = ("norain", "norain_core", "norain_server")


@dataclass
class Report:
    level: str
    actions: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)   # 没能修好的

    @property
    def ok(self) -> bool:
        return not self.problems

    def as_dict(self) -> dict:
        return {"level": self.level, "ok": self.ok, "actions": self.actions, "problems": self.problems}


def package_root() -> Path:
    """程序文件所在的目录（site-packages 或源码的 src/）。"""
    return Path(__file__).resolve().parent.parent


def _sha(path: Path) -> str:
    return fetch.sha256_file(path)


def _package_files(root: Path) -> list[Path]:
    out = []
    for pkg in PACKAGES:
        base = root / pkg
        if base.is_dir():
            out += [p for p in sorted(base.rglob("*")) if p.is_file() and "__pycache__" not in p.parts
                    and p.suffix != ".pyc"]
    return out


def save_package(paths: Paths) -> dict:
    """安装时调用：把当前的程序文件打成安装包副本，并写哈希清单。"""
    root = package_root()
    paths.package_dir.mkdir(parents=True, exist_ok=True)
    files = _package_files(root)
    tmp = paths.package_zip.with_suffix(".zip.part")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, f.relative_to(root).as_posix())
    os.replace(tmp, paths.package_zip)
    manifest = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "package_root": str(root),
        "files": {f.relative_to(root).as_posix(): _sha(f) for f in files},
        "zip_sha256": _sha(paths.package_zip),
        "singbox": ({"path": str(paths.bundled_singbox), "sha256": _sha(paths.bundled_singbox)}
                    if paths.bundled_singbox.is_file() else None),
    }
    write_json(paths.manifest, manifest)
    return manifest


# ---- 文件修复 ------------------------------------------------------------------

def scan(paths: Paths) -> dict:
    """只扫描不修改：返回缺失和损坏的文件。"""
    manifest = read_json(paths.manifest)
    if not manifest:
        return {"manifest": False, "missing": [], "damaged": [], "singbox": "unknown"}
    root = Path(manifest["package_root"])
    missing, damaged = [], []
    for rel, digest in manifest["files"].items():
        f = root / rel
        if not f.is_file():
            missing.append(rel)
        elif _sha(f) != digest:
            damaged.append(rel)
    sb = manifest.get("singbox")
    sb_state = "ok"
    if sb:
        p = Path(sb["path"])
        sb_state = "missing" if not p.is_file() else ("ok" if _sha(p) == sb["sha256"] else "damaged")
    return {"manifest": True, "missing": missing, "damaged": damaged, "singbox": sb_state}


def repair_files(paths: Paths, log: Logger | None = None) -> Report:
    rep = Report("file")
    manifest = read_json(paths.manifest)
    if not manifest:
        rep.problems.append("没有哈希清单（不是通过 norain install 安装的），无法判断文件是否损坏")
        return rep
    found = scan(paths)
    bad = found["missing"] + found["damaged"]
    if bad:
        if not paths.package_zip.is_file() or _sha(paths.package_zip) != manifest.get("zip_sha256"):
            rep.problems.append(f"{len(bad)} 个程序文件损坏或缺失，但安装包副本也已损坏，需要重新安装（pip）")
        else:
            root = Path(manifest["package_root"])
            with zipfile.ZipFile(paths.package_zip) as z:
                for rel in bad:
                    dest = root / rel
                    try:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        tmp = dest.with_name(dest.name + ".repair")
                        tmp.write_bytes(z.read(rel))
                        os.replace(tmp, dest)
                        rep.actions.append(f"已恢复 {rel}")
                    except (OSError, KeyError) as e:
                        rep.problems.append(f"恢复 {rel} 失败：{e}")
    if found["singbox"] != "ok" and manifest.get("singbox"):
        try:
            # 缓存里的压缩包会重新校验 SHA-256；缓存没有时重新下载
            info = fetch.install_singbox(paths.bundled_singbox, paths.cache_dir, need_tags={"with_quic"})
            rep.actions.append(f"sing-box {found['singbox']}，已重新安装 {info.version}")
            manifest["singbox"] = {"path": str(paths.bundled_singbox), "sha256": _sha(paths.bundled_singbox)}
            write_json(paths.manifest, manifest)
        except NorainError as e:
            rep.problems.append(f"sing-box 无法恢复：{e.message}")
    if not bad and found["singbox"] == "ok":
        rep.actions.append(f"扫描了 {len(manifest['files'])} 个文件，没有发现损坏或缺失")
    if log:
        log.info("repair.file", **rep.as_dict())
    return rep


# ---- 内置配置修复 --------------------------------------------------------------

def repair_builtin(paths: Paths, log: Logger | None = None) -> Report:
    """复位代理内部状态。可以在内控制进程运行期间调用（不删除它的进程状态文件）。"""
    rep = Report("builtin")
    for f, label in ((paths.current_json, "生成的 sing-box 配置"), (paths.meta_json, "配置元数据"),
                     (paths.selection, "自适应选中的协议和 DNS 覆盖"), (paths.learned, "自动学到的名单"),
                     (paths.last_error, "错误记录")):
        if f.exists():
            f.unlink()
            rep.actions.append(f"已清除{label}")
    for srs in paths.rules_dir.glob("*.srs") if paths.rules_dir.is_dir() else []:
        try:
            with srs.open("rb") as fh:
                good = fh.read(3) == b"SRS"
        except OSError:
            good = False
        if not good:
            srs.unlink(missing_ok=True)
            rep.actions.append(f"已删除损坏的规则集 {srs.name}（会自动重新下载）")
    from . import runner
    try:
        prep = runner.prepare(paths, apply=True)
        rep.actions.append(f"已从 cfg.toml 重新生成 sing-box 配置（版本 {prep.applied.version}）")
    except NorainError as e:
        detail = "；".join(f"{fe.path} {fe.message}" for fe in e.field_errors) or e.message
        rep.problems.append(f"重新生成配置失败：{detail}")
    if log:
        log.info("repair.builtin", **rep.as_dict())
    return rep


# ---- 完全配置修复 --------------------------------------------------------------

def repair_full(paths: Paths, log: Logger | None = None) -> Report:
    """调用前必须已经停止代理（命令行负责）。"""
    from . import block, boot, install
    from .model import load_config
    rep = Report("full")
    try:
        if block.release(paths, log=log)["was_active"]:
            rep.actions.append("已解除阻断，恢复防火墙")
    except NorainError as e:
        rep.problems.append(f"{e.message}（{e.hint}）")
    msg = install.clear_system_proxy(paths)
    if msg:
        rep.actions.append(msg)
    if paths.orig_config.is_file():
        if not paths.config.exists() or paths.config.read_bytes() != paths.orig_config.read_bytes():
            saved = atomic.backup(paths.config, paths.backups)
            shutil.copy2(paths.orig_config, paths.config)
            os.chmod(paths.config, 0o600)
            rep.actions.append("已把 cfg.toml 恢复为安装时的初始配置"
                               + (f"（当前配置备份在 {saved}）" if saved else ""))
    else:
        rep.problems.append("没有保存安装时的初始配置，用户配置保持不变")
    inner = repair_builtin(paths, log)
    rep.actions += inner.actions
    rep.problems += inner.problems
    try:
        rep.actions.append(boot.sync(paths, load_config(paths.config)))
    except NorainError as e:
        rep.problems.append(f"自启动项没有同步：{e.message}")
    if log:
        log.info("repair.full", **rep.as_dict())
    return rep


# ---- 重载修复 ------------------------------------------------------------------

def repair_reload(paths: Paths, *, start: bool = True) -> Report:
    """完全卸载并清除痕迹，再从安装包副本重新安装。调用前必须已经停止代理。"""
    from . import install
    rep = Report("reload")
    manifest = read_json(paths.manifest)
    if not manifest or not paths.package_zip.is_file():
        raise NorainError("没有安装包副本，无法重载修复", exit_code=EXIT_CONFLICT, module="repair",
                          hint="重新安装 Norain（pip），然后运行 norain install")
    if _sha(paths.package_zip) != manifest.get("zip_sha256"):
        raise NorainError("安装包副本已损坏，无法重载修复", exit_code=EXIT_CONFLICT, module="repair",
                          hint="重新安装 Norain（pip），然后运行 norain install")
    keep = Path(tempfile.mkdtemp(prefix="norain-reload-"))
    try:
        # 卸载会删除整个状态目录，先把重装需要的东西挪到临时目录
        pkg = keep / "norain-pkg.zip"
        shutil.copy2(paths.package_zip, pkg)
        cfg_src = None
        for cand in (paths.orig_config, paths.config):
            if cand.is_file():
                cfg_src = keep / "cfg.toml"
                shutil.copy2(cand, cfg_src)
                break
        secret = paths.home / "password"
        if secret.is_file():
            shutil.copy2(secret, keep / "password")
        sb = None
        if paths.bundled_singbox.is_file():
            try:
                singbox.require(singbox.inspect(paths.bundled_singbox), need_tags={"with_quic"})
                sb = keep / paths.bundled_singbox.name
                shutil.copy2(paths.bundled_singbox, sb)
            except NorainError:
                sb = None  # 现有二进制不可信，重装时重新下载并校验

        un = install.uninstall(paths)
        rep.actions += un["done"]
        rep.problems += un["errors"]

        root = Path(manifest["package_root"])
        with zipfile.ZipFile(pkg) as z:
            for rel in z.namelist():
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                tmp = dest.with_name(dest.name + ".repair")
                tmp.write_bytes(z.read(rel))
                os.replace(tmp, dest)
        rep.actions.append(f"已从安装包副本重新解出 {len(manifest['files'])} 个程序文件")

        paths.home.mkdir(parents=True, exist_ok=True)
        if (keep / "password").is_file():
            shutil.copy2(keep / "password", secret)
            os.chmod(secret, 0o600)
        res = install.install(paths, singbox_path=sb, config_src=cfg_src, force=True, start=start)
        rep.actions += res["steps"]
        rep.actions += [f"注意：{w}" for w in res["warnings"]]
    finally:
        shutil.rmtree(keep, ignore_errors=True)
    return rep
