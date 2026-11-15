"""规则集供应（docs/decisions/0008）：sing-box 只使用本地 .srs 文件，下载、校验、替换和回滚
都由 Norain 完成。GeoIP 判断也用规则集实现（sing-box 1.12 起移除了内置 GeoIP 数据库）。

来源是 SagerNet 官方的 sing-geosite / sing-geoip 仓库的 rule-set 分支。
`<配置目录>/rules.lock.toml` 里写了某个规则集的 sha256 时强制比对；没有锁定值时只记录本次的
哈希（首次信任），并在报告里标注「未锁定」。

下载地址、.srs 的文件头和 `sing-box rule-set match` 的输出格式均未用真实环境验证。
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import time
import tomllib
import urllib.request
from pathlib import Path

from norain_core import osutil
from norain_core.state import read_json, write_json

from .model import KNOWN_RULE_SETS, ClientConfig
from .paths import Paths

SOURCES = {
    "geosite-cn": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
}
_MAGIC = b"SRS"
MAX_BYTES = 64 * 1024 * 1024


def path_of(paths: Paths, name: str) -> Path:
    return paths.rules_dir / f"{name}.srs"


def _index(paths: Paths) -> dict:
    return read_json(paths.rules_dir / "index.json") or {}


def _locked(paths: Paths) -> dict[str, str]:
    try:
        with (paths.home / "rules.lock.toml").open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return {k: str(v.get("sha256", "")).lower() for k, v in data.items() if isinstance(v, dict)}


def status(cfg: ClientConfig, paths: Paths) -> list[dict]:
    idx = _index(paths)
    out = []
    for name in cfg.routing.rule_set:
        if name not in KNOWN_RULE_SETS:
            out.append({"name": Path(name).stem, "source": "local-file", "available": Path(name).is_file()})
            continue
        f = path_of(paths, name)
        out.append({"name": name, "available": f.is_file(), **(idx.get(name) or {})})
    return out


def _download(url: str, dest: Path, proxy: tuple[str, int] | None, timeout: float) -> None:
    handlers = []
    if proxy:
        addr = f"http://{proxy[0]}:{proxy[1]}"
        handlers.append(urllib.request.ProxyHandler({"http": addr, "https": addr}))
    opener = urllib.request.build_opener(*handlers)
    total = 0
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "norain"}), timeout=timeout) as r, \
            dest.open("wb") as f:
        while chunk := r.read(1 << 16):
            total += len(chunk)
            if total > MAX_BYTES:
                raise OSError("文件超过大小上限")
            f.write(chunk)


def update(cfg: ClientConfig, paths: Paths, *, proxy: tuple[str, int] | None = None,
           timeout: float = 60.0, downloader=_download) -> dict:
    """下载到临时文件 → 校验 → 保留上一版 → 原子替换。任何一步失败都保留当前版本。

    proxy：经哪个本地入口下载（代理在运行时用 mixed-in，这样 GitHub 的地址走代理）。
    """
    paths.rules_dir.mkdir(parents=True, exist_ok=True)
    idx, locked = _index(paths), _locked(paths)
    report: dict = {"updated": [], "unchanged": [], "failed": {}, "unpinned": []}
    for name in cfg.routing.rule_set:
        if name not in KNOWN_RULE_SETS:
            continue
        dest = path_of(paths, name)
        tmp = dest.with_suffix(".srs.part")
        try:
            downloader(SOURCES[name], tmp, proxy, timeout)
            data = tmp.read_bytes()
            if len(data) < 16 or not data.startswith(_MAGIC):
                raise OSError("不是 sing-box 二进制规则集（文件头不符）")
            digest = hashlib.sha256(data).hexdigest()
            want = locked.get(name)
            if want and digest != want:
                raise OSError(f"SHA-256 与 rules.lock.toml 不符（期望 {want}，实际 {digest}）")
            if not want:
                report["unpinned"].append(name)
            if dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest() == digest:
                report["unchanged"].append(name)
                tmp.unlink(missing_ok=True)
            else:
                if dest.is_file():
                    shutil.copy2(dest, dest.with_suffix(".srs.prev"))
                os.replace(tmp, dest)
                report["updated"].append(name)
            idx[name] = {"sha256": digest, "url": SOURCES[name], "pinned": bool(want),
                         "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        except (OSError, ValueError) as e:
            tmp.unlink(missing_ok=True)
            report["failed"][name] = str(e)[:200]
    idx["_checked_at"] = time.time()
    write_json(paths.rules_dir / "index.json", idx)
    return report


def rollback(paths: Paths, name: str) -> bool:
    cur, prev = path_of(paths, name), path_of(paths, name).with_suffix(".srs.prev")
    if not prev.is_file():
        return False
    bad = cur.with_suffix(".srs.bad")
    if cur.is_file():
        os.replace(cur, bad)
    os.replace(prev, cur)
    idx = _index(paths)
    idx[name] = {"sha256": hashlib.sha256(cur.read_bytes()).hexdigest(), "rolled_back": True,
                 "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    write_json(paths.rules_dir / "index.json", idx)
    return True


def due(cfg: ClientConfig, paths: Paths) -> bool:
    """是否到了自更新的时间；规则集文件缺失时立即更新。"""
    names = [n for n in cfg.routing.rule_set if n in KNOWN_RULE_SETS]
    if not names:
        return False
    missing = any(not path_of(paths, n).is_file() for n in names)
    hours = cfg.routing.update_interval_hours
    if not missing and not hours:
        return False
    checked = _index(paths).get("_checked_at", 0)
    if not isinstance(checked, (int, float)):
        checked = 0   # 索引文件被改坏时按「从未检查过」处理，而不是抛 TypeError
    # 文件缺失（下载失败）时每 10 分钟重试一次
    return time.time() - checked > (600 if missing else hours * 3600)


class Geo:
    """用规则集回答「这个 IP / 域名是不是国内的」。规则集不可用时返回 None（不知道）。"""

    def __init__(self, binary: Path, paths: Paths) -> None:
        self.binary, self.paths = binary, paths
        self._cache: dict[tuple[str, str, int], bool | None] = {}
        self._files: dict[str, Path] = {}

    def _match(self, name: str, value: str) -> bool | None:
        f = self._files.get(name) or self._files.setdefault(name, path_of(self.paths, name))
        try:
            mtime = os.stat(f).st_mtime_ns
        except OSError:
            return None
        # 缓存键带规则集文件的修改时间：规则集更新或回滚之后，旧结论自动失效
        key = (name, value, mtime)
        if key in self._cache:
            return self._cache[key]
        proc = osutil.run([str(self.binary), "rule-set", "match", str(f), value], timeout=10)
        if proc.returncode != 0:
            result = None
        else:
            output = (proc.stdout + proc.stderr).lower()
            # Do not treat "no match" as a positive result merely because it
            # contains the word "match". Keep unknown formats conservative.
            negative = re.search(r"\b(?:no\s+match|not\s+matched?|unmatched|false)\b|"
                                 r"\bmatch\s*[:=]\s*(?:no|false|0)\b", output)
            positive = re.search(r"\b(?:matched?|match|true)\b|"
                                 r"\bmatch\s*[:=]\s*(?:yes|true|1)\b", output)
            result = False if negative else True if positive else None
        if len(self._cache) > 4096:
            self._cache.clear()
        self._cache[key] = result
        return result

    def ip_is_home(self, ip: str) -> bool | None:
        return self._match("geoip-cn", ip)

    def domain_is_home(self, domain: str) -> bool | None:
        return self._match("geosite-cn", domain)

    def any_home(self, ips: list[str]) -> bool | None:
        """有一个确定是国内就算国内；全部确定不是才算国外；否则不知道。"""
        results = [self.ip_is_home(ip) for ip in ips]
        if any(r is True for r in results):
            return True
        if results and all(r is False for r in results):
            return False
        return None
