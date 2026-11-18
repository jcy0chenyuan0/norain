"""norain 命令行（外控制模块）。

配置类  config validate|show|edit|path|set|protocol|mode|server|dns
        list <white|black|blue|monitor|monitor-cn> [show|add|remove] [条目…]
控制类  start | stop | restart | boot | status | logs
        module <模块> <start|stop|restart|status>
        repair <file|builtin|full|reload>     四种修复
        block <status|off|on>                  阻断模式（off = 手动解除）
        once <monitor|select|route|rules-update|rules-rollback|scan> [参数]   一次性执行某个功能
        install | uninstall
调试类  任何命令加 -t：执行后显示每个模块的运行情况和最近一次的返回结果

所有指令返回明确的退出码（norain_core.errors）。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from norain_core import apply as core_apply
from norain_core import atomic, cliutil, osutil, singbox, tomlio
from norain_core.errors import (BIZ_BINARY_MISSING, BIZ_OK, BIZ_PROCESS_EXITED, EXIT_CONFLICT,
                                EXIT_DEPENDENCY, EXIT_FAILURE, EXIT_OK, EXIT_PERMISSION,
                                EXIT_TIMEOUT, EXIT_USAGE, NorainError)
from norain_core.log import Logger, RotatingFile, new_op_id
from norain_core.state import RUNNING, STOPPED, get_desired, op_lock, read_json, set_desired

from . import block, boot, control, generate, install, maintain, model, monitor, repair, rules, runner
from .model import load_config, warnings_of
from .paths import Paths

_out, _fail = cliutil.out, cliutil.fail

LISTS = {
    "white": ("routing.proxy_domains", "白名单（强制走代理）"),
    "black": ("routing.direct_domains", "黑名单（强制直连）"),
    "blue": ("routing.isolation_allowlist", "蓝名单（阻断模式下仍允许）"),
    "monitor": ("monitor.foreign_targets", "监控测试名单（国外，走代理）"),
    "monitor-cn": ("monitor.domestic_targets", "监控测试名单（国内，直连）"),
}
_PASSIVE_HINT = {
    "block": "用 norain block status|off|on", "repair": "用 norain repair <级别>",
    "boot": "用 norain boot 或 norain config mode", "control": "用 norain start|stop|restart",
    "cli": "它就是你正在用的命令行",
}


def _logger(paths: Paths, module: str = "cli") -> Logger:
    return Logger(module, sink=RotatingFile(paths.log_file, max_bytes=20 << 20, keep=5), stderr=False)


def _running(paths: Paths) -> bool:
    return bool(runner.backend(paths).status().state == "running")


# ---- 配置类 --------------------------------------------------------------------

def cmd_config_validate(args, paths: Paths) -> int:
    prep = runner.prepare(paths, apply=False)
    data = generate.render(prep.cfg, prep.secret, prep.paths)
    core_apply.check_only(data, prep.paths.run_dir, prep.binary.path)
    warns = warnings_of(prep.cfg)
    _out(args, {"config": str(paths.config), "config_version": generate.version_of(data),
                "singbox_version": prep.binary.version, "warnings": warns},
         "配置有效（已通过 sing-box check）" + "".join(f"\n警告：{w}" for w in warns))
    return EXIT_OK


def cmd_config_show(args, paths: Paths) -> int:
    cfg = load_config(paths.config)
    doc = cfg.model_dump(by_alias=True)
    doc["proxy"]["password"] = "***" if cfg.proxy.password else ""
    try:
        s = generate.resolve_secret(cfg)
        doc["proxy"]["resolved"] = {"source": s.source, "fingerprint": s.fingerprint}
    except NorainError as e:
        doc["proxy"]["resolved"] = {"error": "; ".join(f.message for f in e.field_errors) or e.message}
    if args.json:
        _out(args, {"config": doc}, "")
    else:
        print(json.dumps(doc, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_config_path(args, paths: Paths) -> int:
    _out(args, {"config": str(paths.config), "state": str(paths.state), "log": str(paths.log_dir)},
         f"配置：{paths.config}\n状态：{paths.state}\n日志：{paths.log_dir}")
    return EXIT_OK


def _apply_running(paths: Paths) -> str:
    """配置改过之后，通知正在运行的内控制模块重新加载。"""
    if not control.read_status(paths):
        return "代理没有运行，下次启动时生效。"
    resp = control.send(paths, {"op": "reload"}, timeout=90)
    return ("已通知正在运行的代理：" + resp.get("message", "")) if resp.get("ok") else (
        "正在运行的代理没有接受新配置：" + resp.get("message", ""))


def _save_config(paths: Paths, doc: dict) -> tuple[model.ClientConfig, Path | None, bool]:
    """迁移并校验通过才写盘；写之前备份。TOML 注释不会保留。

    写盘写的是迁移后的数据：既然整个文件都要重写，顺手把 ``schema`` 补上，
    否则「缺少顶层 schema」的 warning 每次加载都会再出现一遍。
    """
    migration = model.migrate_doc(doc, source=str(paths.config))
    cfg = model.parse(migration.data, source=str(paths.config))
    saved = atomic.backup(paths.config, paths.backups) if paths.config.exists() else None
    atomic.atomic_write(paths.config, tomlio.dumps(migration.data).encode("utf-8"))
    return cfg, saved, bool(migration.warnings)


def _mutate(args, paths: Paths, changes: dict, text: str) -> int:
    doc = model.read_raw(paths.config)
    for key, value in changes.items():
        try:
            tomlio.set_path(doc, key, value)
        except KeyError:
            raise NorainError(f"{key} 不是可以设置的配置项", exit_code=EXIT_USAGE, module="config") from None
    cfg, saved, added_schema = _save_config(paths, doc)
    notes = [_apply_running(paths)]
    if added_schema:
        notes.append(f"配置里原来没有顶层 schema，已按版本 {model.SCHEMA_VERSION} 写入")
    if any(k.startswith("app.") or k == "proxy.traffic_mode" for k in changes):
        try:
            notes.append(boot.sync(paths, cfg))   # 正常模式 / 安全模式决定是否开机自启动
        except NorainError as e:
            notes.append(f"自启动项没有同步：{e.message}" + (f"（{e.hint}）" if e.hint else ""))
    _out(args, {"changed": changes, "backup": str(saved) if saved else None, "notes": notes},
         text + "\n" + "\n".join(notes))
    return EXIT_OK


def cmd_config_set(args, paths: Paths) -> int:
    value = tomlio.parse_value(args.value)
    return _mutate(args, paths, {args.key: value}, f"已设置 {args.key} = {value!r}")


def cmd_config_protocol(args, paths: Paths) -> int:
    return _mutate(args, paths, {"proxy.protocol": args.protocol},
                   f"协议已设为 {args.protocol}" + ("（按测速和连通性自适应）" if args.protocol == "auto" else ""))


def cmd_config_mode(args, paths: Paths) -> int:
    return _mutate(args, paths, {"app.mode": args.mode},
                   "已设为正常模式（开机自启动）" if args.mode == "normal" else "已设为安全模式（不开机自启动，只手动启动）")


def cmd_config_server(args, paths: Paths) -> int:
    changes: dict = {"proxy.server": args.host}
    if args.hy2_port:
        changes["proxy.hysteria2.port"] = args.hy2_port
    if args.trojan_port:
        changes["proxy.trojan.port"] = args.trojan_port
    if args.credential_ref:
        changes["proxy.credential_ref"] = args.credential_ref
    return _mutate(args, paths, changes, f"代理服务器已设为 {args.host}")


def cmd_config_dns(args, paths: Paths) -> int:
    changes = {f"dns.{k}": v for k, v in (("mode", args.mode), ("domestic", args.domestic),
                                          ("proxy", args.proxy), ("strategy", args.strategy)) if v}
    if not changes:
        cfg = load_config(paths.config)
        _out(args, {"dns": cfg.dns.model_dump()}, json.dumps(cfg.dns.model_dump(), ensure_ascii=False, indent=2))
        return EXIT_OK
    return _mutate(args, paths, changes, "DNS 配置已更新")


def cmd_config_edit(args, paths: Paths) -> int:
    """在编辑器里修改 cfg.toml。保存后先校验，通过才替换原文件。"""
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or (
        "notepad" if osutil.IS_WINDOWS else shutil.which("nano") or shutil.which("vi"))
    if not editor:
        raise NorainError("找不到编辑器", exit_code=EXIT_DEPENDENCY, module="config",
                          hint=f"设置 EDITOR 环境变量，或直接编辑 {paths.config}")
    model.read_raw(paths.config)  # 文件不存在时给出统一的错误
    fd, tmp_name = tempfile.mkstemp(prefix="cfg-", suffix=".toml", dir=str(paths.config.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(paths.config.read_bytes())
        os.chmod(tmp, 0o600)
        before = tmp.read_bytes()
        subprocess.run([*editor.split(), str(tmp)], check=False)
        if tmp.read_bytes() == before:
            _out(args, {"changed": False}, "没有修改")
            return EXIT_OK
        try:
            cfg = load_config(tmp)
        except NorainError as e:
            keep = paths.config.with_name(paths.config.name + ".rejected")
            os.replace(tmp, keep)
            e.hint = f"原配置没有被改动。你的修改保存在 {keep}"
            raise
        saved = atomic.backup(paths.config, paths.backups)
        os.replace(tmp, paths.config)
    finally:
        tmp.unlink(missing_ok=True)
    notes = [_apply_running(paths)]
    try:
        notes.append(boot.sync(paths, cfg))
    except NorainError as e:
        notes.append(f"自启动项没有同步：{e.message}")
    _out(args, {"changed": True, "backup": str(saved) if saved else None, "notes": notes},
         f"配置已保存（旧配置备份在 {saved}）。\n" + "\n".join(notes))
    return EXIT_OK


def cmd_list(args, paths: Paths) -> int:
    key, label = LISTS[args.name]
    doc = model.read_raw(paths.config)
    cfg = model.parse(doc)   # 没写在文件里的名单取默认值
    section, field = key.split(".")
    current = list(getattr(getattr(cfg, section), field))
    if args.action == "show":
        _out(args, {"list": args.name, "field": key, "entries": current},
             f"{label}  [{key}]\n" + ("\n".join(f"  {e}" for e in current) or "  （空）"))
        return EXIT_OK
    if not args.entries:
        raise NorainError("没有给出条目", exit_code=EXIT_USAGE, module="config",
                          hint=f"例如：norain list {args.name} {args.action} example.com")
    if args.action == "add":
        new = current + [e for e in args.entries if e not in current]
    else:
        missing = [e for e in args.entries if e not in current]
        if missing:
            raise NorainError("名单里没有：" + "、".join(missing), exit_code=EXIT_USAGE, module="config")
        new = [e for e in current if e not in args.entries]
    return _mutate(args, paths, {key: new},
                   f"{label}：{'已加入' if args.action == 'add' else '已移除'} {'、'.join(args.entries)}")


# ---- 控制类：生命周期 ----------------------------------------------------------

def _local_proxy_hint(cfg) -> str:
    host = f"[{cfg.local.listen}]" if ":" in cfg.local.listen else cfg.local.listen
    if cfg.proxy.traffic_mode == "tun":
        return f"全局接管（TUN）已启用。本地代理：{host}:{cfg.local.port}（HTTP 和 SOCKS5 共用）。"
    if cfg.proxy.traffic_mode == "system-proxy":
        return f"已设置系统代理。本地代理：{host}:{cfg.local.port}。只有遵守系统代理的程序才走代理。"
    return (f"本地代理：{host}:{cfg.local.port}（HTTP 和 SOCKS5 共用）。\n"
            "只有设置了这个代理的程序才会走代理；系统其他流量不受影响。")


def _preflight(prep) -> None:
    if prep.cfg.proxy.traffic_mode == "tun" and not osutil.is_admin():
        raise NorainError("TUN 模式需要管理员权限", exit_code=EXIT_PERMISSION, module="control",
                          hint="用管理员 / root 运行，或运行 norain config set proxy.traffic_mode mixed")


def _start(paths: Paths, op_id: str):
    prep = runner.prepare(paths, apply=False)   # 先在前台报出配置问题
    _preflight(prep)
    set_desired(paths.desired, RUNNING, op_id=op_id)
    try:
        runner.backend(prep.paths).start(timeout=45)
    except NorainError as e:
        # 只有「启动超时」才回滚期望状态：守护进程已经被停掉，留着 running 会被保活方
        # 反复拉起；其它失败（配置错、进程崩溃）保留 running 让 status 报出原因。
        if e.exit_code == EXIT_TIMEOUT:
            set_desired(paths.desired, STOPPED, op_id=op_id)
        raise
    return prep


def _stop(paths: Paths, op_id: str) -> None:
    set_desired(paths.desired, STOPPED, op_id=op_id)   # 先写期望状态，保证任何保活方都不会再拉起
    runner.backend(paths).stop(timeout=40)
    maintain.kill_watchdog(paths)


def cmd_start(args, paths: Paths) -> int:
    op_id = new_op_id()
    was_blocked = block.is_active(paths)
    with op_lock(paths.lock, op="start", op_id=op_id):
        prep = _start(paths, op_id)
    _out(args, {"state": "running", "op_id": op_id, "block_released": was_blocked,
                "local_proxy": {"listen": prep.cfg.local.listen, "port": prep.cfg.local.port}},
         "已启动" + ("（已自动解除阻断模式）" if was_blocked else "") + "\n" + _local_proxy_hint(prep.cfg)
         + "\n启动测试（监控）在后台进行，运行 norain status 查看结果。")
    return EXIT_OK


def cmd_boot(args, paths: Paths) -> int:
    """启动模块的入口：开机自启动项运行的就是 `norain boot --autostart`。"""
    if args.autostart and get_desired(paths.desired) != RUNNING:
        _out(args, {"state": "skipped"}, "期望状态是 stopped（用户手动停止过），不启动")
        return EXIT_OK
    return cmd_start(args, paths)


def cmd_stop(args, paths: Paths) -> int:
    op_id = new_op_id()
    with op_lock(paths.lock, op="stop", op_id=op_id):
        _stop(paths, op_id)
    _out(args, {"state": "stopped", "op_id": op_id}, "已停止")
    return EXIT_OK


def cmd_restart(args, paths: Paths) -> int:
    op_id = new_op_id()
    with op_lock(paths.lock, op="restart", op_id=op_id):
        prep = runner.prepare(paths, apply=False)  # 新配置无效时不动正在运行的代理
        _preflight(prep)
        runner.backend(prep.paths).stop(timeout=40)
        maintain.kill_watchdog(paths)
        prep = _start(paths, op_id)
    _out(args, {"state": "running", "op_id": op_id}, "已重启\n" + _local_proxy_hint(prep.cfg))
    return EXIT_OK


def cmd_run(args, paths: Paths) -> int:
    return runner.run_foreground(paths, autostart=args.autostart)


def cmd_watchdog(args, paths: Paths) -> int:
    return maintain.watchdog_main(paths)


# ---- 控制类：状态 --------------------------------------------------------------

def build_status(paths: Paths) -> dict:
    st: dict = {"updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "desired": get_desired(paths.desired)}
    business = BIZ_OK
    try:
        cfg = load_config(paths.config)
        paths = paths.with_log_dir(cfg.logging.directory)
        st["config"] = {"valid": True}
        st["proxy"] = {"protocol": cfg.proxy.protocol, "server": cfg.proxy.server,
                       "port": cfg.proxy.port, "traffic_mode": cfg.proxy.traffic_mode}
        st["local_proxy"] = {"listen": cfg.local.listen, "port": cfg.local.port}
        st["app"] = {"mode": cfg.app.mode, "auto_start": cfg.app.auto_start}
        st["warnings"] = warnings_of(cfg)
    except NorainError as e:
        business = e.business_code
        st["config"] = {"valid": False, "errors": [f.as_dict() for f in e.field_errors] or e.message}
    try:
        info = runner.locate_singbox(paths)
        st["singbox"] = {"path": str(info.path), "version": info.version,
                         "pinned": singbox.PINNED_VERSION,
                         "version_ok": info.version == singbox.PINNED_VERSION}
    except NorainError as e:
        st["singbox"] = {"error": e.message}
        business = business or BIZ_BINARY_MISSING

    svc = runner.backend(paths).status()
    st["service"] = {"state": svc.state, "pid": svc.pid}
    st["process"] = {"running": bool(svc.child_pid), "pid": svc.child_pid}
    st["restarts"] = svc.restarts
    meta = read_json(paths.meta_json) or {}
    st["config"]["version"] = meta.get("config_version")
    st["config"]["generated_at"] = meta.get("generated_at")
    last = read_json(paths.last_error)
    st["last_error"] = last
    st["block"] = block.status(paths)

    live = control.read_status(paths) or {}
    st["phase"] = live.get("phase")
    st["modules"] = live.get("modules")
    st["monitor"] = live.get("monitor")
    st["rules"] = live.get("rules")
    if live.get("protocol"):
        st.setdefault("proxy", {})["active_protocol"] = live["protocol"]["active"]

    if st["desired"] == RUNNING and svc.state != "running":
        business = (last or {}).get("business_code") or business or BIZ_PROCESS_EXITED
    elif svc.state == "running":
        business = BIZ_OK if st["process"]["running"] else BIZ_PROCESS_EXITED
        # 进程正常时，业务码取监控模块的结论（链路是否真的连通）
        if business == BIZ_OK and st["monitor"]:
            business = st["monitor"]["code"]
    st["business_code"] = business
    st["link_check"] = (st["monitor"] or {}).get("meaning") or (
        "监控还没有结论" if svc.state == "running" else "代理没有运行")
    return st


def cmd_status(args, paths: Paths) -> int:
    st = build_status(paths)
    if args.json:
        print(json.dumps(st, ensure_ascii=False, indent=2))
        return EXIT_OK
    state = {"running": "运行中", "stopped": "已停止", "failed": "失败"}[st["service"]["state"]]
    print(f"状态：{state}（期望：{'运行' if st['desired'] == RUNNING else '停止'}"
          + (f"，阶段：{st['phase']}" if st.get("phase") else "") + "）")
    if st["config"]["valid"]:
        p, local = st["proxy"], st["local_proxy"]
        active = p.get("active_protocol")
        proto = p["protocol"] + (f" → 当前 {active}" if active and p["protocol"] == "auto" else "")
        print(f"服务器：{p['server']}（{proto}），接管方式：{p['traffic_mode']}")
        print(f"本地代理：{local['listen']}:{local['port']}")
        print(f"启动模式：{'正常模式' if st['app']['mode'] == 'normal' else '安全模式'}")
    else:
        print("配置无效，运行 norain config validate 查看详情")
    if st["block"]["active"]:
        print(f"阻断模式：已启用（错误码 {st['block']['code']}，{st['block']['engaged_at']}）。"
              + ("正在修复中，只放行代理服务器。" if st["block"].get("repairing") else "")
              + f"解除：{st['block']['restore_command']}")
    if st.get("monitor"):
        print(f"链路检测：错误码 {st['monitor']['code']}（{st['monitor']['meaning']}）")
    else:
        print(f"链路检测：{st['link_check']}")
    print(f"sing-box 重启次数：{st['restarts']}")
    if st["business_code"]:
        print(f"业务码：{st['business_code']}")
    if st["last_error"]:
        print(f"最近错误：{st['last_error']['message']}（{st['last_error']['time']}）")
    for w in st.get("warnings", []):
        print(f"警告：{w}")
    return EXIT_OK


def cmd_logs(args, paths: Paths) -> int:
    try:
        paths = paths.with_log_dir(load_config(paths.config).logging.directory)
    except NorainError:
        pass
    return cliutil.tail(paths.log_file, lines=args.lines, follow=args.follow)


def _short(value, limit: int = 160) -> str:
    if value in (None, [], {}):
        return "-"
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + "…"


def print_trace(paths: Paths) -> None:
    """-t：每个模块的运行情况和最近一次的返回结果。"""
    live = control.read_status(paths)
    print("\n── 模块运行情况 " + "─" * 40, file=sys.stderr)
    if not live:
        blk = block.status(paths)
        print("内控制模块没有运行，其余模块随之停止。", file=sys.stderr)
        print(f"  block    {'blocking' if blk['active'] else 'idle':<10} {_short(blk if blk['active'] else None)}",
              file=sys.stderr)
        print(f"  watchdog {'running' if maintain.watchdog_alive(paths) else 'stopped'}", file=sys.stderr)
        last = read_json(paths.last_error)
        if last:
            print(f"  最近错误：{_short(last)}", file=sys.stderr)
        return
    print(f"阶段：{live['phase']}   协议：{live['protocol']['active']}   "
          f"监控错误码：{live['monitor']['code']}（{live['monitor']['meaning']}）", file=sys.stderr)
    for name in control.MODULES:
        m = (live.get("modules") or {}).get(name)
        if not m:
            continue
        extra = {k: v for k, v in m.items() if k not in ("state", "last_result")}
        print(f"  {name:<8} {m.get('state', '?'):<10} {_short(extra, 90)}", file=sys.stderr)
        print(f"  {'':<8} 返回结果：{_short(m.get('last_result'), 400)}", file=sys.stderr)


# ---- 控制类：模块 --------------------------------------------------------------

def cmd_module(args, paths: Paths) -> int:
    name = args.name
    if args.action == "status":
        live = control.read_status(paths)
        mod = ((live or {}).get("modules") or {}).get(name)
        if mod is None:
            mod = {"state": "stopped", "note": "内控制模块没有运行"}
            if name == "block":
                mod = {"state": "blocking" if block.is_active(paths) else "idle", "last_result": block.status(paths)}
        _out(args, {"module": name, **mod}, f"{name}：{mod.get('state')}\n"
             + json.dumps({k: v for k, v in mod.items() if k != "state"}, ensure_ascii=False, indent=2))
        return EXIT_OK
    if name in _PASSIVE_HINT:
        raise NorainError(f"{name} 模块不能单独{args.action}", exit_code=EXIT_USAGE, module="control",
                          hint=_PASSIVE_HINT[name])
    resp = control.send(paths, {"op": "module", "name": name, "action": args.action}, timeout=90)
    if not resp.get("ok"):
        raise NorainError(f"{name} {args.action} 没有执行：{resp.get('message')}", exit_code=EXIT_CONFLICT,
                          module="control", retryable=True)
    _out(args, {"module": name, "action": args.action, **resp},
         f"{name}：{resp.get('message')}（当前 {resp.get('module', {}).get('state')}）")
    return EXIT_OK


# ---- 控制类：修复 --------------------------------------------------------------

def cmd_repair(args, paths: Paths) -> int:
    op_id = new_op_id()
    level = args.level
    log = _logger(paths, "repair")
    with op_lock(paths.lock, op=f"repair-{level}", op_id=op_id, timeout=900):
        was_running = get_desired(paths.desired) == RUNNING
        if level == "file":
            rep = repair.repair_files(paths, log)
        elif level == "builtin":
            rep = repair.repair_builtin(paths, log)
            if control.read_status(paths):   # 让正在运行的代理加载复位后的配置
                control.send(paths, {"op": "reload"}, timeout=90)
        else:
            _stop(paths, op_id)              # 这两级会动用户配置和系统配置，必须先停下来
            if level == "full":
                rep = repair.repair_full(paths, log)
                if was_running and rep.ok:
                    _start(paths, op_id)
                    rep.actions.append("已重新启动")
            else:
                rep = repair.repair_reload(paths, start=was_running)
    text = "\n".join(f"· {a}" for a in rep.actions) + "".join(f"\n未修好：{p}" for p in rep.problems)
    _out(args, {**rep.as_dict(), "op_id": op_id}, text)
    return EXIT_OK if rep.ok else EXIT_FAILURE


# ---- 控制类：阻断 --------------------------------------------------------------

def cmd_block(args, paths: Paths) -> int:
    if args.action == "status":
        st = block.status(paths)
        text = "阻断模式：" + ("已启用" if st["active"] else "未启用")
        if st["active"]:
            text += (f"\n错误码：{st['code']}  原因：{st['reason']}\n进入时间：{st['engaged_at']}\n"
                     + "可能原因：\n" + "".join(f"  · {g}\n" for g in st["guesses"])
                     + f"解除：{st['restore_command']}\n不依赖 Norain 的手工恢复：{st['manual_restore']}")
        _out(args, st, text)
        return EXIT_OK
    if args.action == "off":
        res = block.release(paths, log=_logger(paths, "block"), force=bool(getattr(args, "force", False)))
        _out(args, res, ("已解除阻断，防火墙恢复正常放行。" if res["was_active"] else "当前不在阻断模式。")
             + "\n注意：这不代表代理已修复，此时代理不一定在运行；流量会直连。启动代理：norain start")
        return EXIT_OK
    # on：手动进入阻断（同自动触发时一样，结束其他所有模块）
    cfg = load_config(paths.config)
    op_id = new_op_id()
    with op_lock(paths.lock, op="block", op_id=op_id):
        st = block.engage(cfg, paths, code=0, reason="用户手动进入阻断模式", log=_logger(paths, "block"),
                          notify=False)
        _stop(paths, op_id)
    _out(args, {"active": True, "allowed": st["allowed"], "unresolved": st["unresolved"]},
         "已进入阻断模式，其他模块已停止。解除：norain block off"
         + ("\n没能解析（因此没有放行）：" + "、".join(st["unresolved"]) if st["unresolved"] else ""))
    return EXIT_OK


# ---- 控制类：一次性执行某个模块的某个功能 --------------------------------------

def cmd_once(args, paths: Paths) -> int:
    what, live = args.what, control.read_status(paths)
    if what == "monitor":
        if live:
            resp = control.send(paths, {"op": "monitor"}, timeout=120)
            _out(args, resp, resp.get("text", ""))
            return EXIT_OK
        cfg = load_config(paths.config)
        try:
            geo = rules.Geo(runner.locate_singbox(paths).path, paths)
        except NorainError:
            geo = None
        rnd = monitor.run_round(cfg, monitor.Ports(), geo)
        _out(args, {"result": rnd.as_dict(), "standalone": True},
             "（代理没有运行：只检测直连，走代理的项目一律为无返回）\n" + monitor.report_text(rnd))
        return EXIT_OK
    if what == "scan":
        res = repair.scan(paths)
        _out(args, res, f"缺失 {len(res['missing'])} 个，损坏 {len(res['damaged'])} 个，sing-box：{res['singbox']}"
             + "".join(f"\n  缺失 {f}" for f in res["missing"]) + "".join(f"\n  损坏 {f}" for f in res["damaged"])
             + ("" if res["manifest"] else "\n没有哈希清单（不是通过 norain install 安装的）"))
        return EXIT_OK
    if what == "rules-update":
        if live:
            resp = control.send(paths, {"op": "rules-update"}, timeout=180)
            rep = resp.get("result") or {}
        else:
            rep = rules.update(load_config(paths.config), paths)
        _out(args, rep, f"已更新：{'、'.join(rep.get('updated', [])) or '无'}；未变化："
             f"{'、'.join(rep.get('unchanged', [])) or '无'}"
             + "".join(f"\n失败 {k}：{v}" for k, v in (rep.get("failed") or {}).items()))
        return EXIT_FAILURE if rep.get("failed") else EXIT_OK
    if what == "rules-rollback":
        if not args.arg:
            raise NorainError("需要规则集名称", exit_code=EXIT_USAGE, module="routing",
                              hint="例如：norain once rules-rollback geoip-cn")
        if not rules.rollback(paths, args.arg):
            raise NorainError(f"{args.arg} 没有可回滚的上一版本", exit_code=EXIT_CONFLICT, module="routing")
        note = _apply_running(paths)
        _out(args, {"rolled_back": args.arg}, f"{args.arg} 已回滚到上一版本。\n{note}")
        return EXIT_OK
    # 以下两个功能需要代理在运行（要用它的本地探测入口）
    if not live:
        raise NorainError("这个功能需要代理在运行", exit_code=EXIT_CONFLICT, module="control",
                          hint="先运行 norain start")
    if what == "select":
        resp = control.send(paths, {"op": "select"}, timeout=120)
        if not resp.get("ok"):
            raise NorainError(resp.get("message", "没有执行"), exit_code=EXIT_CONFLICT, module="control")
        _out(args, resp, f"当前协议：{resp['active']}（{'已切换' if resp['switched'] else '未切换'}：{resp['reason']}）\n"
             + json.dumps(resp["result"], ensure_ascii=False, indent=2))
        return EXIT_OK
    if not args.arg:
        raise NorainError("需要域名", exit_code=EXIT_USAGE, module="routing",
                          hint="例如：norain once route example.com")
    resp = control.send(paths, {"op": "route", "domain": args.arg}, timeout=180)
    v = resp.get("result") or {}
    _out(args, resp, f"{v.get('domain')}：{v.get('decision')}"
         + ("（已更新名单，稍后自动重载）" if v.get("changed") else "")
         + "".join(f"\n  {s}" for s in v.get("steps", [])))
    return EXIT_OK


# ---- 控制类：安装与卸载 --------------------------------------------------------

def cmd_install(args, paths: Paths) -> int:
    res = install.install(
        paths, archive=Path(args.singbox_archive) if args.singbox_archive else None,
        sha256=args.singbox_sha256, singbox_path=Path(args.singbox_path) if args.singbox_path else None,
        config_src=Path(args.config) if args.config else None, server=args.server or "",
        traffic_mode=args.traffic_mode, protocol=args.protocol, force=args.force, start=not args.no_start)
    _out(args, res, "\n".join(f"· {s}" for s in res["steps"]) + "".join(f"\n注意：{w}" for w in res["warnings"])
         + f"\n\n配置文件：{res['config']}\n`norain` 命令和环境变量在新开的终端里生效。")
    if not args.no_start and not res.get("started"):
        return EXIT_FAILURE   # 装完没起来不能报成功，否则脚本会把失败当成功
    return EXIT_OK


def cmd_uninstall(args, paths: Paths) -> int:
    if not args.yes:
        if not sys.stdin.isatty():
            raise NorainError("卸载会删除全部配置和数据，需要确认", exit_code=EXIT_USAGE, module="install",
                              hint="加 --yes")
        if input("将删除 Norain 的全部配置、数据、自启动项和环境变量。输入 yes 确认：").strip().lower() != "yes":
            print("已取消")
            return EXIT_OK
    res = install.uninstall(paths)
    _out(args, res, "\n".join(f"· {d}" for d in res["done"]) + "".join(f"\n未完成：{e}" for e in res["errors"])
         + "\n" + res["note"])
    return EXIT_FAILURE if res["errors"] else EXIT_OK


# ---- 入口 ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    common.add_argument("-t", "--trace", action="store_true",
                        help="调试：执行后显示每个模块的运行情况和返回结果")
    p = argparse.ArgumentParser(prog="norain", description="Norain 客户端")
    sub = p.add_subparsers(dest="command", required=True, metavar="<命令>")

    def add(parent, name, func, help_):
        sp = parent.add_parser(name, parents=[common], help=help_)
        sp.set_defaults(func=func)
        return sp

    # 配置类
    cfg = sub.add_parser("config", help="配置").add_subparsers(dest="sub", required=True)
    add(cfg, "validate", cmd_config_validate, "校验 cfg.toml 并运行 sing-box check")
    add(cfg, "show", cmd_config_show, "显示生效配置（隐藏秘密）")
    add(cfg, "edit", cmd_config_edit, "在编辑器里修改 cfg.toml（保存后校验）")
    add(cfg, "path", cmd_config_path, "显示配置、状态、日志的位置")
    st = add(cfg, "set", cmd_config_set, "设置任意配置项，例如 config set dns.mode split")
    st.add_argument("key")
    st.add_argument("value")
    add(cfg, "protocol", cmd_config_protocol, "协议：自适应 / Hysteria2 / Trojan").add_argument(
        "protocol", choices=["auto", "hysteria2", "trojan"])
    add(cfg, "mode", cmd_config_mode, "启动模式：normal（开机自启动）/ safe（只手动启动）").add_argument(
        "mode", choices=["normal", "safe"])
    sv = add(cfg, "server", cmd_config_server, "代理服务器")
    sv.add_argument("host")
    sv.add_argument("--hy2-port", type=int)
    sv.add_argument("--trojan-port", type=int)
    sv.add_argument("--credential-ref", help="file:<密码文件> 或 env:<变量名>")
    dn = add(cfg, "dns", cmd_config_dns, "DNS（不带参数时显示当前设置）")
    dn.add_argument("--mode", choices=["local", "split", "proxy"])
    dn.add_argument("--domestic", help="国内 DNS 的 IP")
    dn.add_argument("--proxy", help="经代理访问的 DNS，https://… 或 IP")
    dn.add_argument("--strategy", choices=["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"])

    ls = add(sub, "list", cmd_list, "白名单 / 黑名单 / 蓝名单 / 监控测试名单")
    ls.add_argument("name", choices=list(LISTS))
    ls.add_argument("action", nargs="?", default="show", choices=["show", "add", "remove"])
    ls.add_argument("entries", nargs="*")

    # 控制类
    add(sub, "start", cmd_start, "启动代理（处于阻断模式时先自动解除）")
    add(sub, "stop", cmd_stop, "停止代理（之后不会被自动拉起）")
    add(sub, "restart", cmd_restart, "重启代理")
    bt = add(sub, "boot", cmd_boot, "启动模块的入口（开机自启动项调用）")
    bt.add_argument("--autostart", action="store_true", help="用户手动停止过时不启动")
    add(sub, "status", cmd_status, "查看状态")
    rn = add(sub, "run", cmd_run, "前台运行内控制模块")
    rn.add_argument("--autostart", action="store_true", help="期望状态不是 running 时直接退出")
    lg = add(sub, "logs", cmd_logs, "查看日志")
    lg.add_argument("-f", "--follow", action="store_true")
    lg.add_argument("-n", "--lines", type=int, default=50)

    md = add(sub, "module", cmd_module, "启动 / 结束 / 重启 / 查看单个模块")
    md.add_argument("name", choices=list(control.MODULES))
    md.add_argument("action", choices=["start", "stop", "restart", "status"])

    rp = add(sub, "repair", cmd_repair, "修复：file（文件）/ builtin（内置配置）/ full（完全配置）/ reload（重载）")
    rp.add_argument("level", choices=["file", "builtin", "full", "reload"])

    bk = add(sub, "block", cmd_block, "阻断模式：status / off（手动解除）/ on（手动进入）")
    bk.add_argument("action", choices=["status", "off", "on"])
    # 修复还没成功时（repairing），off 需要显式确认：放开后流量会直连
    bk.add_argument("--force", action="store_true", help="代理仍未修复时也强行解除（流量会直连）")

    on = add(sub, "once", cmd_once, "一次性执行某个模块的某个功能")
    on.add_argument("what", choices=["monitor", "select", "route", "rules-update", "rules-rollback", "scan"],
                    help="monitor 立即检测一轮；select 立即测速选协议；route <域名> 判断分流；"
                         "rules-update 更新规则集；rules-rollback <名称> 回滚；scan 扫描程序文件")
    on.add_argument("arg", nargs="?")

    ins = add(sub, "install", cmd_install, "安装：sing-box、默认配置、norain 命令、环境变量、开机自启动")
    ins.add_argument("--singbox-archive", help="本地的 sing-box 压缩包（不联网）")
    ins.add_argument("--singbox-sha256", help="压缩包的 SHA-256（默认用锁定文件里的值）")
    ins.add_argument("--singbox-path", help="直接使用已有的 sing-box 可执行文件")
    ins.add_argument("--config", help="用这份 cfg.toml 作为初始配置")
    ins.add_argument("--server", help="代理服务器域名或 IP（也可以用环境变量 NORAIN_SERVER）")
    ins.add_argument("--traffic-mode", default="system-proxy", choices=["tun", "mixed", "system-proxy"])
    ins.add_argument("--protocol", default="auto", choices=["auto", "hysteria2", "trojan"])
    ins.add_argument("--force", action="store_true", help="覆盖已有的 cfg.toml（先备份）")
    ins.add_argument("--no-start", action="store_true", help="安装后不启动")
    un = add(sub, "uninstall", cmd_uninstall, "完全卸载并清除痕迹")
    un.add_argument("--yes", action="store_true", help="不询问，直接卸载")

    add(sub, "_watchdog", cmd_watchdog, argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = Paths.from_env()
    try:
        code = args.func(args, paths)
    except NorainError as e:
        code = _fail(args, e)
    except KeyboardInterrupt:
        return 130
    if getattr(args, "trace", False) and args.command not in ("run", "_watchdog", "uninstall"):
        try:
            print_trace(paths)
        except Exception as e:  # noqa: BLE001 调试输出出错不能改变命令的退出码
            print(f"（无法读取模块状态：{e}）", file=sys.stderr)
    return code


if __name__ == "__main__":  # python -m norain.cli 也要能用；缺了它会静默退出 0
    raise SystemExit(main())
