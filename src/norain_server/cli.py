"""norain-server 命令行（外控制模块）。

配置类：config validate/show/edit、cert check/self-signed、secret generate
控制类：start/stop/restart/reload/status/run、firewall open/close/status、fix
部署类：install/update/uninstall
日志：  log [-f]

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
from norain_core import atomic, cliutil, osutil, singbox
from norain_core.errors import (BIZ_BINARY_MISSING, BIZ_OK, BIZ_PROCESS_EXITED, BIZ_RESTART_LIMIT,
                                EXIT_CONFIG, EXIT_DEPENDENCY, EXIT_FAILURE, EXIT_OK, NorainError)
from norain_core.log import new_op_id
from norain_core.redact import redact
from norain_core.secrets import generate_to_file
from norain_core.state import RUNNING, STOPPED, get_desired, op_lock, read_json, set_desired

from . import cert as certmod
from . import deploy, firewall, generate, runner
from .model import load_config
from .paths import Paths
from .service import pick_backend

_out, _fail = cliutil.out, cliutil.fail


# ---- config ----------------------------------------------------------------

def cmd_config_validate(args, paths: Paths) -> int:
    prep = runner.prepare(paths, apply=False)
    # 生成候选并跑 sing-box check，但不替换当前配置
    data = generate.render(prep.cfg, prep.secret, prep.paths)
    core_apply.check_only(data, prep.paths.run_dir, prep.binary.path)
    warnings = prep.cert.warnings
    _out(args, {"config": str(paths.config), "config_version": generate.version_of(data),
                "singbox_version": prep.binary.version, "warnings": warnings},
         "配置有效（已通过 sing-box check）" + "".join(f"\n警告：{w}" for w in warnings))
    return EXIT_OK


def cmd_config_show(args, paths: Paths) -> int:
    cfg = load_config(paths.config)
    doc = cfg.model_dump(by_alias=True)
    doc["auth"]["password"] = "***" if cfg.auth.password else ""
    try:
        secret = generate.resolve_secret(cfg)
        doc["auth"]["resolved"] = {"source": secret.source, "fingerprint": secret.fingerprint}
    except NorainError as e:
        doc["auth"]["resolved"] = {"error": "; ".join(f.message for f in e.field_errors) or e.message}
    if args.json:
        _out(args, {"config": doc}, "")
    else:
        print(json.dumps(doc, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_config_edit(args, paths: Paths) -> int:
    """在编辑器里修改 server.toml。保存后先校验，通过才替换原文件；不自动重启。"""
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or (
        "notepad" if osutil.IS_WINDOWS else shutil.which("nano") or shutil.which("vi"))
    if not editor:
        raise NorainError("找不到编辑器", exit_code=EXIT_DEPENDENCY, module="config",
                          hint=f"设置 EDITOR 环境变量，或直接编辑 {paths.config}")
    if not paths.config.exists():
        raise NorainError(f"配置文件不存在：{paths.config}", exit_code=EXIT_CONFIG, business_code=110,
                          module="config", hint="运行 norain-server install 或 norain-server fix 生成默认配置")
    fd, tmp_name = tempfile.mkstemp(prefix="server-", suffix=".toml", dir=str(paths.config.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(paths.config.read_bytes())
        os.chmod(tmp, 0o600)
        before = tmp.read_bytes()
        subprocess.run([*editor.split(), str(tmp)], check=False)
        after = tmp.read_bytes()
        if after == before:
            _out(args, {"changed": False}, "没有修改")
            return EXIT_OK
        try:
            load_config(tmp)
        except NorainError as e:
            keep = paths.config.with_name(paths.config.name + ".rejected")
            os.replace(tmp, keep)
            e.hint = f"原配置没有被改动。你的修改保存在 {keep}，修正后可覆盖 {paths.config}"
            raise
        saved = atomic.backup(paths.config, paths.backups)
        mode = paths.config.stat().st_mode & 0o777
        os.replace(tmp, paths.config)
        os.chmod(paths.config, mode)
    finally:
        tmp.unlink(missing_ok=True)
    _out(args, {"changed": True, "backup": str(saved) if saved else None},
         f"配置已保存（旧配置备份在 {saved}）。\n"
         "修改不会自动生效：运行 norain-server restart，或只换证书时运行 norain-server reload。")
    return EXIT_OK


# ---- cert / secret ---------------------------------------------------------

def cmd_cert_check(args, paths: Paths) -> int:
    cfg = load_config(paths.config)
    tags = None
    if cfg.tls.mode == "acme":
        try:
            tags = runner.locate_singbox(paths).tags
        except NorainError:
            pass
    st = runner.cert_status(cfg, paths, tags=tags, service_running=runner.service_running(paths))
    if not st.ok:
        st.raise_if_invalid()
    if st.days_left is None:
        text = f"证书模式 {cfg.tls.mode}：前置条件检查通过，证书尚未签发"
    else:
        text = f"证书有效，{st.days_left} 天后过期\nSHA-256 指纹：{st.fingerprint_sha256}"
    _out(args, {"cert": st.as_dict(), "mode": cfg.tls.mode},
         text + "".join(f"\n警告：{w}" for w in st.warnings))
    return EXIT_OK


def cmd_cert_self_signed(args, paths: Paths) -> int:
    c, k = paths.tls_dir / "self-signed.crt", paths.tls_dir / "self-signed.key"
    st, method = certmod.self_signed(args.domain, c, k, days=args.days, force=args.force)
    _out(args, {"cert": st.as_dict(), "method": method},
         f"已生成自签证书（{method}）：\n  证书：{c}\n  私钥：{k}\n"
         f"  SHA-256 指纹：{st.fingerprint_sha256}\n"
         "在 server.toml 中设置 [tls] mode = \"self-signed\" 即可使用。"
         "客户端需要拿到这张证书文件才能信任服务端。")
    return EXIT_OK


def cmd_secret_generate(args, paths: Paths) -> int:
    path = paths.secrets_dir / "password"
    secret = generate_to_file(path, force=args.force)
    _out(args, {"credential_ref": secret.source, "fingerprint": secret.fingerprint},
         f"已生成密码并写入 {path}（权限 0600）。\n"
         f"在 server.toml 中设置：[auth] credential_ref = \"{secret.source}\"\n"
         f"密码不会显示在这里；需要配置客户端时直接查看该文件。")
    return EXIT_OK


# ---- 生命周期 ----------------------------------------------------------------

def cmd_start(args, paths: Paths) -> int:
    op_id = new_op_id()
    with op_lock(paths.lock, op="start", op_id=op_id):
        runner.prepare(paths, apply=False)  # 先在前台报出配置和证书问题
        set_desired(paths.desired, RUNNING, op_id=op_id)
        backend = pick_backend(paths)
        backend.start()
    _out(args, {"state": "running", "backend": backend.name, "op_id": op_id}, "已启动")
    return EXIT_OK


def cmd_stop(args, paths: Paths) -> int:
    op_id = new_op_id()
    with op_lock(paths.lock, op="stop", op_id=op_id):
        set_desired(paths.desired, STOPPED, op_id=op_id)  # 先写期望状态，保证不会被拉起
        backend = pick_backend(paths)
        backend.stop()
    _out(args, {"state": "stopped", "backend": backend.name, "op_id": op_id}, "已停止")
    return EXIT_OK


def cmd_restart(args, paths: Paths) -> int:
    op_id = new_op_id()
    with op_lock(paths.lock, op="restart", op_id=op_id):
        runner.prepare(paths, apply=False)  # 新配置无效时不动正在运行的服务
        backend = pick_backend(paths)
        backend.stop()
        set_desired(paths.desired, RUNNING, op_id=op_id)
        backend.start()
    _out(args, {"state": "running", "backend": backend.name, "op_id": op_id}, "已重启")
    return EXIT_OK


def cmd_reload(args, paths: Paths) -> int:
    """重新检查证书并加载新配置。只重启 sing-box 子进程，不重启系统服务，也不计入失败次数。"""
    op_id = new_op_id()
    with op_lock(paths.lock, op="reload", op_id=op_id):
        prep = runner.prepare(paths, apply=True)  # 证书无效或 check 不通过时在这里中止，旧配置保留
        running = pick_backend(prep.paths).status().state == "running"
        if running:
            paths.reload_file.parent.mkdir(parents=True, exist_ok=True)
            paths.reload_file.write_text(op_id, encoding="utf-8")
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and paths.reload_file.exists():
                time.sleep(0.2)
            if paths.reload_file.exists():
                paths.reload_file.unlink(missing_ok=True)
                raise NorainError("守护进程没有响应重载请求", exit_code=6, module="daemon", retryable=True,
                                  hint="运行 norain-server restart")
    _out(args, {"reloaded": running, "config_version": prep.applied.version,
                "config_changed": prep.applied.changed, "warnings": prep.cert.warnings, "op_id": op_id},
         ("已重载" if running else "服务没有运行，只更新了配置文件")
         + "".join(f"\n警告：{w}" for w in prep.cert.warnings))
    return EXIT_OK


def cmd_run(args, paths: Paths) -> int:
    if getattr(args, "if_desired", False) and get_desired(paths.desired) != RUNNING:
        return EXIT_OK  # 用户手动 stop 过：开机自启时不拉起
    return runner.run_foreground(paths)


def cmd_fix(args, paths: Paths) -> int:
    op_id = new_op_id()
    with op_lock(paths.lock, op="fix", op_id=op_id):
        res = deploy.fix(paths)
    _out(args, {**res, "op_id": op_id},
         "\n".join(res["actions"]) + "".join(f"\n警告：{w}" for w in res["warnings"])
         + ("\n配置有变化，运行 norain-server reload 使其生效" if res["restart_needed"] else ""))
    return EXIT_OK


def _summary_text(sm: dict) -> str:
    lines = [f"域名：{sm['domain']}"]
    lines += [f"协议：{p['name']}  {p['port']}/{p['transport']}" for p in sm["protocols"]]
    tls = sm["tls"]
    lines.append(f"证书：{tls['mode']}" + (f"，SHA-256 指纹 {tls['fingerprint_sha256']}"
                                         if tls["fingerprint_sha256"] else "（尚未签发）"))
    lines.append(f"密码：来源 {sm['auth']['source']}，指纹 {sm['auth']['fingerprint']}（明文不显示）")
    lines += [f"{k}：{v}" for k, v in sm["paths"].items()]
    return "\n".join(lines)


def cmd_install(args, paths: Paths) -> int:
    op_id = new_op_id()
    paths.state.mkdir(parents=True, exist_ok=True)
    with op_lock(paths.lock, op="install", op_id=op_id, timeout=600):
        res = deploy.install(paths, force=args.force,
                             archive=Path(args.singbox_archive) if args.singbox_archive else None,
                             sha256=args.singbox_sha256,
                             singbox_path=Path(args.singbox_path) if args.singbox_path else None,
                             start=not args.no_start, open_firewall=not args.no_firewall)
    _out(args, {**res, "op_id": op_id},
         "\n".join(f"· {x}" for x in res["steps"]) + "".join(f"\n警告：{w}" for w in res["warnings"])
         + "\n\n服务端摘要\n" + _summary_text(res["summary"])
         + "\n\n环境变量在新开的终端里生效。")
    return EXIT_OK


def cmd_update(args, paths: Paths) -> int:
    op_id = new_op_id()
    with op_lock(paths.lock, op="update", op_id=op_id, timeout=600):
        res = deploy.update(paths, archive=Path(args.singbox_archive) if args.singbox_archive else None,
                            sha256=args.singbox_sha256,
                            singbox_path=Path(args.singbox_path) if args.singbox_path else None)
    _out(args, {**res, "op_id": op_id}, "\n".join(f"· {x}" for x in res["steps"]))
    return EXIT_OK


def cmd_uninstall(args, paths: Paths) -> int:
    res = deploy.uninstall(paths, purge=args.purge)
    text = "\n".join(f"· {x}" for x in res["done"])
    if res["kept"]:
        text += "\n保留（加 --purge 才删除）：" + "、".join(res["kept"])
    if res["errors"]:
        text += "".join(f"\n未完成：{e}" for e in res["errors"])
    _out(args, res, text)
    return EXIT_FAILURE if res["errors"] else EXIT_OK


def cmd_desired_is(args, paths: Paths) -> int:
    return EXIT_OK if get_desired(paths.desired) == args.state else EXIT_FAILURE


def build_status(paths: Paths) -> dict:
    status: dict = {"updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "desired": get_desired(paths.desired)}
    business = BIZ_OK
    cfg = None
    try:
        cfg = load_config(paths.config)
        paths = paths.with_log_dir(cfg.logging.directory)
        status["protocols"] = [
            {"name": n, "port": p.port, "transport": t}
            for n, p, t in (("hysteria2", cfg.protocols.hysteria2, "udp"),
                            ("trojan", cfg.protocols.trojan, "tcp")) if p.enabled]
        status["config"] = {"valid": True}
    except NorainError as e:
        business = e.business_code
        status["config"] = {"valid": False, "errors": [f.as_dict() for f in e.field_errors] or e.message}
        status["protocols"] = []

    if cfg is not None:
        st = runner.cert_status(cfg, paths, service_running=True)
        status["cert"] = {"ok": st.ok, "mode": cfg.tls.mode, "not_after": st.not_after,
                          "days_left": st.days_left, "self_signed": st.self_signed,
                          "errors": st.errors, "warnings": st.warnings}
        if not st.ok and not business:
            business = 120
    try:
        info = runner.locate_singbox(paths)
        status["singbox"] = {"path": str(info.path), "version": info.version,
                             "pinned": singbox.PINNED_VERSION,
                             "version_ok": info.version == singbox.PINNED_VERSION}
    except NorainError as e:
        status["singbox"] = {"error": e.message}
        business = business or BIZ_BINARY_MISSING

    svc = pick_backend(paths).status()
    status["service"] = {"backend": svc.backend, "state": svc.state, "pid": svc.pid,
                         "outer_restarts": svc.outer_restarts}
    status["process"] = {"running": bool(svc.child_pid), "pid": svc.child_pid}
    status["restarts"] = svc.restarts
    meta = read_json(paths.meta_json) or {}
    status["config"]["version"] = meta.get("config_version")
    status["config"]["generated_at"] = meta.get("generated_at")
    last = read_json(paths.last_error)
    status["last_error"] = last
    if status["desired"] == RUNNING and svc.state != "running":
        code = (last or {}).get("business_code")
        business = code if code else (business or BIZ_PROCESS_EXITED)
        if svc.state == "failed" and not code:
            business = BIZ_RESTART_LIMIT
    elif svc.state == "running":
        business = BIZ_OK if status["process"]["running"] else BIZ_PROCESS_EXITED
    status["business_code"] = business
    return status


def cmd_status(args, paths: Paths) -> int:
    # 最初目标：status 输出 JSON。--json 只为兼容，行为相同。
    print(json.dumps(build_status(paths), ensure_ascii=False, indent=2))
    return EXIT_OK


# ---- log / firewall --------------------------------------------------------

def cmd_log(args, paths: Paths) -> int:
    try:
        paths = paths.with_log_dir(load_config(paths.config).logging.directory)
    except NorainError:
        pass
    return cliutil.tail(paths.log_file, lines=args.lines, follow=args.follow)


def cmd_firewall(args, paths: Paths) -> int:
    if args.action == "close":
        try:
            cfg = load_config(paths.config)
        except NorainError:
            cfg = None  # 配置损坏时仍然可以移除 Norain 创建的规则
        res = firewall.close_ports(paths, cfg)
    else:
        cfg = load_config(paths.config)
        res = firewall.open_ports(cfg, paths) if args.action == "open" else firewall.status(cfg, paths)
    lines = [f"防火墙后端：{res.get('backend') or '无（未找到 ufw 或 firewalld）'}"]
    if args.action == "status":
        for row in res["ports"]:
            state = {True: "已放行", False: "未放行", None: "未知"}[row["open"]]
            lines.append(f"  {row['port']}（{row['purpose']}）：{state}"
                         + ("，由 Norain 创建" if row["managed_by_norain"] else ""))
    else:
        for key, label in (("opened", "新放行"), ("already_open", "原本已放行"),
                           ("closed_stale", "已移除不再需要的"), ("closed", "已移除")):
            if res.get(key):
                lines.append(f"  {label}：{'、'.join(res[key])}")
    if res.get("note"):
        lines.append(res["note"])
    lines += [f"  {c}" for c in res.get("manual_commands", [])]
    _out(args, res, "\n".join(lines))
    return EXIT_OK


# ---- 入口 --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    p = argparse.ArgumentParser(prog="norain-server", description="Norain 服务端")
    sub = p.add_subparsers(dest="command", required=True, metavar="<命令>")

    def add(parent, name, func, help_):
        sp = parent.add_parser(name, parents=[common], help=help_)
        sp.set_defaults(func=func)
        return sp

    cfg = sub.add_parser("config", help="配置").add_subparsers(dest="sub", required=True)
    add(cfg, "validate", cmd_config_validate, "校验 server.toml 并运行 sing-box check")
    add(cfg, "show", cmd_config_show, "显示生效配置（隐藏秘密）")
    add(cfg, "edit", cmd_config_edit, "编辑 server.toml（保存后校验，不自动重启）")

    crt = sub.add_parser("cert", help="证书").add_subparsers(dest="sub", required=True)
    add(crt, "check", cmd_cert_check, "检查证书")
    ss = add(crt, "self-signed", cmd_cert_self_signed, "生成自签证书")
    ss.add_argument("--domain", required=True)
    ss.add_argument("--days", type=int, default=365)
    ss.add_argument("--force", action="store_true")

    sec = sub.add_parser("secret", help="密码").add_subparsers(dest="sub", required=True)
    add(sec, "generate", cmd_secret_generate, "生成随机密码文件").add_argument("--force", action="store_true")

    add(sub, "start", cmd_start, "启动")
    add(sub, "stop", cmd_stop, "停止（之后不会被自动拉起）")
    add(sub, "restart", cmd_restart, "重启")
    add(sub, "status", cmd_status, "输出 JSON 状态")
    add(sub, "reload", cmd_reload, "检查证书并重新加载配置（不重启系统服务）")
    rn = add(sub, "run", cmd_run, "前台运行守护进程（供 systemd / 计划任务调用）")
    rn.add_argument("--if-desired", action="store_true", help="期望状态不是 running 时直接退出")
    add(sub, "fix", cmd_fix, "重建配置、检查证书、恢复缺失文件")

    def singbox_source(sp):
        sp.add_argument("--singbox-archive", help="本地的 sing-box 压缩包（不联网）")
        sp.add_argument("--singbox-sha256", help="压缩包的 SHA-256（默认用锁定文件里的值）")
        sp.add_argument("--singbox-path", help="直接使用已有的 sing-box 可执行文件")

    ins = add(sub, "install", cmd_install, "安装：sing-box、默认配置、开机自启、环境变量")
    singbox_source(ins)
    ins.add_argument("--force", action="store_true", help="覆盖已有的 server.toml（先备份）")
    ins.add_argument("--no-start", action="store_true", help="不做启动测试")
    ins.add_argument("--no-firewall", action="store_true", help="不修改防火墙")
    singbox_source(add(sub, "update", cmd_update, "更新 sing-box 和自启动注册（先备份配置和证书）"))
    un = add(sub, "uninstall", cmd_uninstall, "卸载（默认保留配置和日志）")
    un.add_argument("--purge", action="store_true", help="同时删除配置和日志")
    lg = add(sub, "log", cmd_log, "查看日志")
    lg.add_argument("-f", "--follow", action="store_true")
    lg.add_argument("-n", "--lines", type=int, default=50)
    fw = add(sub, "firewall", cmd_firewall, "放行 / 关闭 / 查看协议端口")
    fw.add_argument("action", choices=["open", "close", "status"])
    ds = add(sub, "_desired-state-is", cmd_desired_is, argparse.SUPPRESS)
    ds.add_argument("state", choices=[RUNNING, STOPPED])
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = Paths.from_env()
    try:
        return args.func(args, paths)
    except NorainError as e:
        return _fail(args, e)
    except KeyboardInterrupt:
        return 130
    finally:
        try:
            deploy.sync_ownership(paths)
        except OSError:
            pass
