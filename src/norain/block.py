"""阻断模块：代理无法维持时切断除蓝名单以外的全部出站连接，防止回落直连暴露真实 IP。

行为以最初目标为准（docs/decisions/0011 修订）：自维持模块修复失败后自动进入阻断，弹窗提醒并给出
可能原因，同时结束其他模块；启动模块运行时自动恢复；也可以用命令行手动解除（解除不代表代理已修好）。

安全措施（只防硬性故障，不改变行为）：
  - 规则放在自己的空间里：Windows 用固定前缀 `Norain-Block-` 的规则，Linux 用独立的
    nftables 表 `inet norain_block`。不改系统默认策略，不碰用户的其他规则。
  - 先写状态文件再应用规则，应用失败自动回滚。
  - 解除只读本地状态文件，不需要网络，也不依赖其他模块在运行。状态文件里写有不依赖 Norain 的
    手工恢复命令。

放行范围：回环、链路本地、DHCP/组播、（可选）局域网、代理服务器、国内 DNS、蓝名单
（routing.isolation_allowlist）、监控模块的国内检测目标（让监控在阻断期间仍能判断本地网络）。
域名在进入阻断时解析成 IP；之后对端换 IP 需要重新进入阻断才会更新。

Windows 的实现方式：阻断规则优先于放行规则，所以为「放行范围的补集」建出站阻断规则。
这两套命令均未在真实系统上验证。
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from urllib.parse import urlsplit

from norain_core import osutil
from norain_core.errors import EXIT_EXTERNAL, NorainError
from norain_core.log import Logger
from norain_core.state import read_json, write_json

from .model import ClientConfig, split_entries
from .monitor import GUESS, MEANING
from .paths import Paths

PREFIX = "Norain-Block-"
NFT_TABLE = "norain_block"
_CHUNK = 60  # 每条 Windows 规则里的地址段数量上限（控制命令行长度）

MANUAL_RESTORE = {
    "nt": "powershell -Command \"Get-NetFirewallRule -DisplayName 'Norain-Block-*' | Remove-NetFirewallRule\"",
    "posix": f"nft delete table inet {NFT_TABLE}",
}

_BASE4 = ["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/32"]
_BASE6 = ["::1/128", "fe80::/10", "ff00::/8", "::/128"]
_LAN4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
_LAN6 = ["fc00::/7"]


# ---- 放行范围 ------------------------------------------------------------------

def _resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0].split("%")[0] for ai in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def allowed(cfg: ClientConfig) -> tuple[list, list, dict]:
    """返回 (IPv4 网段, IPv6 网段, 说明)。说明里记录每个域名解析到了什么、哪些没解析出来。"""
    nets: list = [ipaddress.ip_network(n) for n in _BASE4 + _BASE6]
    if cfg.routing.allow_lan_in_isolation:
        nets += [ipaddress.ip_network(n) for n in _LAN4 + _LAN6]
    notes: dict = {"resolved": {}, "unresolved": []}

    def add_host(host: str) -> None:
        try:
            nets.append(ipaddress.ip_network(host, strict=False))
            return
        except ValueError:
            pass
        ips = _resolve(host)
        if ips:
            notes["resolved"][host] = ips
            nets.extend(ipaddress.ip_network(ip) for ip in ips)
        else:
            notes["unresolved"].append(host)

    add_host(cfg.proxy.server)
    add_host(cfg.dns.domestic)
    m = split_entries(cfg.routing.isolation_allowlist)
    for e in m.get("ip_cidr", []) + m.get("domain", []) + m.get("domain_suffix", []):
        add_host(e)
    for url in cfg.monitor.domestic_targets:  # 绕过监控模块
        host = urlsplit(url).hostname
        if host:
            add_host(host)
    v4 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 4))
    v6 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 6))
    return v4, v6, notes


def complement(nets: list, version: int) -> list[tuple[str, str]]:
    """放行网段的补集，写成 [起始地址, 结束地址] 的列表。"""
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    top = int(cls("255.255.255.255" if version == 4 else "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
    out, cursor = [], 0
    for n in sorted(nets, key=lambda n: int(n.network_address)):
        lo, hi = int(n.network_address), int(n.broadcast_address)
        if lo > cursor:
            out.append((str(cls(cursor)), str(cls(lo - 1))))
        cursor = max(cursor, hi + 1)
    if cursor <= top:
        out.append((str(cls(cursor)), str(cls(top))))
    return out


# ---- 后端 ----------------------------------------------------------------------

class WindowsBackend:
    name = "windows-firewall"

    def snapshot(self) -> dict:
        proc = osutil.powershell("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
        try:
            rows = json.loads(proc.stdout or "[]")
        except ValueError:
            rows = []
        rows = rows if isinstance(rows, list) else [rows]
        # Enabled 可能序列化成布尔、0/1 或 "True"/"False"
        return {r["Name"]: str(r.get("Enabled")).lower() in ("true", "1") for r in rows if "Name" in r}

    def apply(self, v4: list, v6: list) -> list[str]:
        names: list[str] = []
        for ver, nets in ((4, v4), (6, v6)):
            ranges = complement(nets, ver)
            for i in range(0, len(ranges), _CHUNK):
                name = f"{PREFIX}v{ver}-{i // _CHUNK}"
                remote = ",".join(a if a == b else f"{a}-{b}" for a, b in ranges[i:i + _CHUNK])
                osutil.run_checked(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                                    "dir=out", "action=block", "enable=yes", "profile=any",
                                    f"remoteip={remote}"], what="添加阻断规则", module="block")
                names.append(name)
        # 防火墙被关掉时规则不生效：记下原状态后打开，解除时还原
        osutil.run_checked(["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                           what="启用 Windows 防火墙", module="block")
        return names

    def remove(self, state: dict) -> list[str]:
        errors = []
        proc = osutil.powershell(f"Get-NetFirewallRule -DisplayName '{PREFIX}*' -ErrorAction SilentlyContinue "
                                 "| Remove-NetFirewallRule")
        if proc.returncode != 0:
            # PowerShell 不可用时逐条用 netsh 删除记录在案的规则
            for name in state.get("rules", []):
                p = osutil.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
                if p.returncode != 0 and "No rules match" not in p.stdout and "没有与" not in p.stdout:
                    errors.append(f"删除规则 {name} 失败：{(p.stderr or p.stdout).strip()[:200]}")
        for profile, enabled in (state.get("firewall_profiles") or {}).items():
            if not enabled:
                osutil.run(["netsh", "advfirewall", "set", f"{profile.lower()}profile", "state", "off"])
        return errors

    def present(self) -> bool:
        proc = osutil.powershell(f"@(Get-NetFirewallRule -DisplayName '{PREFIX}*' -ErrorAction SilentlyContinue).Count")
        return proc.returncode == 0 and proc.stdout.strip() not in ("", "0")


class NftBackend:
    name = "nftables"

    def snapshot(self) -> dict:
        return {}

    def apply(self, v4: list, v6: list) -> list[str]:
        def elems(nets) -> str:
            return ", ".join(str(n) for n in nets)
        script = (
            f"table inet {NFT_TABLE} {{}}\n"          # 保证下一行的 delete 不会因为表不存在而失败
            f"delete table inet {NFT_TABLE}\n"
            f"table inet {NFT_TABLE} {{\n"
            "  chain output {\n"
            "    type filter hook output priority -10; policy drop;\n"
            '    oifname "lo" accept\n'
            "    udp sport 68 udp dport 67 accept\n"
            + (f"    ip daddr {{ {elems(v4)} }} accept\n" if v4 else "")
            + (f"    ip6 daddr {{ {elems(v6)} }} accept\n" if v6 else "")
            + "  }\n}\n")
        proc = osutil.run(["nft", "-f", "-"], input_text=script, timeout=30)
        if proc.returncode != 0:
            raise NorainError(f"应用 nftables 规则失败：{(proc.stderr or proc.stdout).strip()[:400]}",
                              exit_code=EXIT_EXTERNAL, module="block",
                              hint="需要 root 权限和 nftables")
        return [f"inet {NFT_TABLE}"]

    def remove(self, state: dict) -> list[str]:
        proc = osutil.run(["nft", "delete", "table", "inet", NFT_TABLE])
        if proc.returncode != 0 and self.present():
            return [f"删除 nftables 表失败：{(proc.stderr or proc.stdout).strip()[:200]}"]
        return []

    def present(self) -> bool:
        return osutil.run(["nft", "list", "table", "inet", NFT_TABLE]).returncode == 0


def backend():
    return WindowsBackend() if osutil.IS_WINDOWS else NftBackend()


# ---- 状态 ----------------------------------------------------------------------

def state(paths: Paths) -> dict | None:
    return read_json(paths.block_state)


def is_active(paths: Paths) -> bool:
    return bool((state(paths) or {}).get("active"))


def status(paths: Paths) -> dict:
    st = state(paths) or {}
    return {"active": bool(st.get("active")), "engaged_at": st.get("engaged_at"), "code": st.get("code"),
            "reason": st.get("reason"), "guesses": st.get("guesses", []), "backend": st.get("backend"),
            "allowed": st.get("allowed", []), "unresolved": st.get("unresolved", []),
            "restore_command": "norain block off",
            "manual_restore": MANUAL_RESTORE["nt" if osutil.IS_WINDOWS else "posix"]}


def message(code: int, reason: str) -> str:
    guesses = GUESS.get(code, ["代理进程无法启动或反复崩溃", "配置或程序文件损坏"])
    return ("代理无法正常工作，为防止真实 IP 暴露，已切断除蓝名单以外的网络连接。\n\n"
            f"错误码：{code}（{MEANING.get(code, '代理无法维持')}）\n"
            + (f"依据：{reason}\n" if reason else "")
            + "可能原因：\n" + "".join(f"  · {g}\n" for g in guesses)
            + "\n恢复网络：在管理员终端运行  norain block off\n"
              "重新启动代理：norain start（启动时会自动解除阻断）\n"
              "注意：解除阻断不代表代理已修复，解除后流量会直连。")


# ---- 进入与解除 ----------------------------------------------------------------

def engage(cfg: ClientConfig, paths: Paths, *, code: int, reason: str, log: Logger | None = None,
           notify: bool = True) -> dict:
    """进入阻断模式。失败时回滚并抛出错误（调用方要知道阻断没有生效）。"""
    osutil.require_admin("进入阻断模式", module="block")
    be = backend()
    v4, v6, notes = allowed(cfg)
    st = {
        "active": True, "engaged_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "code": code, "reason": reason,
        "guesses": GUESS.get(code, []), "backend": be.name, "rules": [],
        "firewall_profiles": be.snapshot(),
        "allowed": [str(n) for n in v4 + v6], "resolved": notes["resolved"], "unresolved": notes["unresolved"],
        "restore_command": "norain block off",
        "manual_restore": MANUAL_RESTORE["nt" if osutil.IS_WINDOWS else "posix"],
    }
    write_json(paths.block_state, st)  # 先落盘：即使应用到一半崩溃，解除命令也知道要清理什么
    try:
        st["rules"] = be.apply(v4, v6)
    except NorainError:
        be.remove(st)
        paths.block_state.unlink(missing_ok=True)
        raise
    write_json(paths.block_state, st)
    if log:
        log.error("block.engaged", code=code, reason=reason, backend=be.name, rules=len(st["rules"]),
                  unresolved=notes["unresolved"])
    if notify:
        text = message(code, reason)
        if not osutil.popup("Norain 已进入阻断模式", text) and log:
            log.error("block.popup_unavailable", text=text)
    return st


def release(paths: Paths, *, log: Logger | None = None) -> dict:
    """解除阻断，恢复正常的防火墙放行。幂等：没有状态文件时也会清理残留规则。"""
    st = state(paths) or {}
    be = backend()
    if not st and not be.present():
        return {"was_active": False, "errors": []}
    osutil.require_admin("解除阻断", module="block")
    errors = be.remove(st)
    if errors:
        raise NorainError("解除阻断没有完全成功：" + "；".join(errors), exit_code=EXIT_EXTERNAL, module="block",
                          hint="手工恢复命令：" + MANUAL_RESTORE["nt" if osutil.IS_WINDOWS else "posix"])
    paths.block_state.unlink(missing_ok=True)
    if log:
        log.info("block.released", was_active=bool(st.get("active")))
    return {"was_active": bool(st.get("active")), "errors": []}
