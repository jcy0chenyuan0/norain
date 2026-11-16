"""防火墙模块：放行或关闭服务端协议端口。

原则（最初目标）：只放行配置中启用的端口；不开放无关端口；关闭协议或卸载时移除对应规则；
操作失败必须给出具体原因。Norain 只移除自己创建的规则——创建过的规则记在
`<state>/firewall.json` 里，用户原有的同端口规则不会被动到。

后端：Linux 优先 ufw，其次 firewalld，都没有时提示手动放行；Windows 用 netsh advfirewall。
ufw 后端已实测（install 放行端口、uninstall 撤回规则）；firewalld 与 netsh 未实测。
"""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass

from norain_core import osutil
from norain_core.errors import EXIT_EXTERNAL, NorainError
from norain_core.state import read_json, write_json

from .model import ServerConfig
from .paths import Paths
from .runner import firewall_ports

PREFIX = "norain-server"


@dataclass(frozen=True)
class Rule:
    proto: str   # tcp | udp
    port: int
    label: str   # hysteria2 | trojan | acme

    @property
    def key(self) -> str:
        return f"{self.port}/{self.proto}"

    @property
    def name(self) -> str:
        return f"{PREFIX}-{self.label}-{self.proto}-{self.port}"


class UfwBackend:
    name = "ufw"

    def is_open(self, r: Rule) -> bool:
        out = osutil.run(["ufw", "status"]).stdout
        return any(line.split()[:1] == [r.key] and "ALLOW" in line for line in out.splitlines())

    def active(self) -> bool:
        return "Status: active" in osutil.run(["ufw", "status"]).stdout

    def open(self, r: Rule) -> None:
        osutil.run_checked(["ufw", "allow", r.key, "comment", r.name], what=f"放行 {r.key}", module="firewall")

    def close(self, r: Rule) -> None:
        osutil.run_checked(["ufw", "delete", "allow", r.key], what=f"关闭 {r.key}", module="firewall")

    def manual(self, r: Rule, action: str) -> str:
        return f"ufw allow {r.key}" if action == "open" else f"ufw delete allow {r.key}"


class FirewalldBackend:
    name = "firewalld"

    def is_open(self, r: Rule) -> bool:
        return osutil.run(["firewall-cmd", "--permanent", f"--query-port={r.key}"]).returncode == 0

    def active(self) -> bool:
        return osutil.run(["firewall-cmd", "--state"]).returncode == 0

    def _apply(self, flag: str, r: Rule, what: str) -> None:
        osutil.run_checked(["firewall-cmd", "--permanent", f"{flag}={r.key}"], what=what, module="firewall")
        osutil.run_checked(["firewall-cmd", "--reload"], what="重载 firewalld", module="firewall")

    def open(self, r: Rule) -> None:
        self._apply("--add-port", r, f"放行 {r.key}")

    def close(self, r: Rule) -> None:
        self._apply("--remove-port", r, f"关闭 {r.key}")

    def manual(self, r: Rule, action: str) -> str:
        flag = "--add-port" if action == "open" else "--remove-port"
        return f"firewall-cmd --permanent {flag}={r.key} && firewall-cmd --reload"


class NetshBackend:
    name = "netsh"

    def is_open(self, r: Rule) -> bool:
        return osutil.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={r.name}"]).returncode == 0

    def active(self) -> bool:
        return True

    def open(self, r: Rule) -> None:
        osutil.run_checked(["netsh", "advfirewall", "firewall", "add", "rule", f"name={r.name}", "dir=in",
                            "action=allow", f"protocol={r.proto.upper()}", f"localport={r.port}"],
                           what=f"放行 {r.key}", module="firewall")

    def close(self, r: Rule) -> None:
        osutil.run_checked(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r.name}"],
                           what=f"关闭 {r.key}", module="firewall")

    def manual(self, r: Rule, action: str) -> str:
        if action == "open":
            return (f'netsh advfirewall firewall add rule name="{r.name}" dir=in action=allow '
                    f"protocol={r.proto.upper()} localport={r.port}")
        return f'netsh advfirewall firewall delete rule name="{r.name}"'


def detect():
    if osutil.IS_WINDOWS:
        return NetshBackend()
    if shutil.which("ufw"):
        return UfwBackend()
    if shutil.which("firewall-cmd"):
        return FirewalldBackend()
    return None


def wanted(cfg: ServerConfig) -> list[Rule]:
    return [Rule(proto, port, label) for proto, port, label in firewall_ports(cfg)]


def _recorded(paths: Paths) -> list[Rule]:
    data = read_json(paths.firewall_state) or {}
    return [Rule(r["proto"], int(r["port"]), r.get("label", "port")) for r in data.get("rules", [])]


def _save(paths: Paths, backend_name: str | None, rules: list[Rule]) -> None:
    if not rules:
        paths.firewall_state.unlink(missing_ok=True)
        return
    write_json(paths.firewall_state, {
        "backend": backend_name, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "rules": [{"proto": r.proto, "port": r.port, "label": r.label} for r in rules]})


def _manual_only(rules: list[Rule], action: str) -> dict:
    cmds = [f"iptables -{'I' if action == 'open' else 'D'} INPUT -p {r.proto} --dport {r.port} -j ACCEPT"
            for r in rules]
    return {"backend": None, "applied": False, "ports": [r.key for r in rules], "manual_commands": cmds,
            "note": "没有找到 ufw 或 firewalld，请手动放行（云服务器还要检查安全组）"}


def open_ports(cfg: ServerConfig, paths: Paths) -> dict:
    """放行配置中启用的端口，并移除 Norain 以前放行、现在已不需要的端口。"""
    want = wanted(cfg)
    backend = detect()
    if backend is None:
        return _manual_only(want, "open")
    osutil.require_admin("修改防火墙", module="firewall")
    recorded = _recorded(paths)
    opened, kept, closed, errors = [], [], [], []
    mine = list(recorded)
    for r in want:
        if r in recorded or backend.is_open(r):
            kept.append(r.key)  # 已经放行（可能是用户自己的规则，不记到 Norain 名下）
            continue
        try:
            backend.open(r)
            opened.append(r.key)
            mine.append(r)
        except NorainError as e:
            errors.append(e.message)
    for r in recorded:
        if r not in want:  # 协议已关闭或端口已更换
            try:
                backend.close(r)
                closed.append(r.key)
                mine.remove(r)
            except NorainError as e:
                errors.append(e.message)
    _save(paths, backend.name, mine)
    result = {"backend": backend.name, "applied": True, "ports": [r.key for r in want],
              "opened": opened, "already_open": kept, "closed_stale": closed}
    if not backend.active():
        result["note"] = f"{backend.name} 当前没有启用，规则已写入但不生效"
    if errors:
        raise NorainError("防火墙操作失败：" + "；".join(errors), exit_code=EXIT_EXTERNAL, module="firewall",
                          hint="已成功的部分保留，修正后可重新运行 firewall open")
    return result


def close_ports(paths: Paths, cfg: ServerConfig | None = None) -> dict:
    """移除 Norain 创建的全部规则。不依赖配置文件可读（卸载时配置可能已损坏）。"""
    recorded = _recorded(paths)
    backend = detect()
    if backend is None:
        return _manual_only(recorded or (wanted(cfg) if cfg else []), "close")
    if not recorded:
        return {"backend": backend.name, "applied": True, "closed": [],
                "note": "没有 Norain 创建的规则；用户自己添加的规则不会被移除"}
    osutil.require_admin("修改防火墙", module="firewall")
    closed, errors, left = [], [], []
    for r in recorded:
        try:
            if backend.is_open(r):
                backend.close(r)
            closed.append(r.key)
        except NorainError as e:
            errors.append(e.message)
            left.append(r)
    _save(paths, backend.name, left)
    if errors:
        raise NorainError("防火墙操作失败：" + "；".join(errors), exit_code=EXIT_EXTERNAL, module="firewall")
    return {"backend": backend.name, "applied": True, "closed": closed}


def status(cfg: ServerConfig, paths: Paths) -> dict:
    want = wanted(cfg)
    backend = detect()
    recorded = {r.key for r in _recorded(paths)}
    rows = []
    for r in want:
        state = None
        if backend is not None:
            try:
                state = backend.is_open(r)
            except Exception:  # noqa: BLE001 查询失败时如实标为未知
                state = None
        rows.append({"port": r.key, "purpose": r.label, "open": state, "managed_by_norain": r.key in recorded})
    return {"backend": backend.name if backend else None,
            "active": backend.active() if backend else None, "ports": rows,
            "manual_commands": [] if backend else _manual_only(want, "open")["manual_commands"]}
