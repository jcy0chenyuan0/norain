"""部署更新模块：install / update / uninstall / fix，以及开机自启和环境变量注册。

Linux：sing-box 装到 /usr/local/bin，配置在 /etc/norain-server，状态在 /var/lib/norain-server，
注册 systemd 单元，写 /etc/profile.d/norain-server.sh。
Windows：sing-box.exe 装到 %ProgramFiles%\\norain-server，配置在 %ProgramData%\\norain-server，
用开机计划任务自启，用 setx 写环境变量。

所有步骤幂等；重复安装不覆盖已有用户配置（除非 --force）；安装失败按相反顺序回滚。
已在真实 Ubuntu 上验证：install / reload / fix / update / uninstall，以及 systemd 开机自启（含真实重启）。
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Callable

from norain_core import fetch, osutil, singbox
from norain_core.errors import EXIT_CONFIG, EXIT_CONFLICT, EXIT_EXTERNAL, NorainError
from norain_core.log import new_op_id
from norain_core.secrets import generate_to_file
from norain_core.state import RUNNING, STOPPED, get_desired, read_json, set_desired, write_json

from . import cert as certmod
from . import firewall, generate, runner
from .model import load_config
from .paths import Paths
from .service import UNIT, pick_backend

SERVICE_USER = "norain"
TASK_NAME = "norain-server"
ENV_NAME = "norain-server"
UNIT_PATH = Path("/etc/systemd/system") / UNIT

_UNIT_TEMPLATE = """\
# 由 norain-server install 生成。职责见 docs/decisions/0012：Python 守护负责重启 sing-box，
# systemd 只在守护进程自身异常退出时把它拉起。
[Unit]
Description=Norain server (sing-box supervisor)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
User={user}
Group={user}
EnvironmentFile=-{home}/env
# 用户手动 stop 之后（期望状态为 stopped），开机时跳过启动，不算失败
ExecCondition={python} -m norain_server _desired-state-is running
ExecStart={python} -m norain_server run
Restart=on-failure
RestartSec=5
# 3=配置无效 5=缺少 sing-box 9=已达连续重启上限：这些情况再拉起也没用，避免无限循环
RestartPreventExitStatus=3 5 9
KillMode=mixed
TimeoutStopSec=20
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome={protect_home}
PrivateTmp=true
ReadWritePaths={state} {log}

[Install]
WantedBy=multi-user.target
"""


def _env_vars(paths: Paths) -> dict[str, str]:
    return {"NORAIN_SERVER_HOME": str(paths.home), "NORAIN_SERVER_CONFIG": str(paths.config),
            "NORAIN_SERVER_STATE": str(paths.state), "NORAIN_SERVER_LOG": str(paths.log_dir),
            "NORAIN_SERVER_SINGBOX": str(paths.default_singbox)}


def default_config_text(paths: Paths, env, *, secret_ref: str) -> str:
    """生成默认 server.toml。NORAIN_DOMAIN / NORAIN_HY2_PORT / NORAIN_TROJAN_PORT /
    NORAIN_CERT_MODE 在安装时写进文件，之后不依赖这些环境变量仍然存在。"""
    domain = (env.get("NORAIN_DOMAIN") or "").strip() or socket.gethostname()
    mode = (env.get("NORAIN_CERT_MODE") or "").strip() or "self-signed"
    def port_env(name: str, default: int) -> int:
        raw = (env.get(name) or "").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            raise NorainError(f"环境变量 {name} 必须是整数", exit_code=EXIT_CONFIG, module="deploy") from None

    hy2 = port_env("NORAIN_HY2_PORT", 443)
    trojan_port = env.get("NORAIN_TROJAN_PORT")
    trojan = port_env("NORAIN_TROJAN_PORT", 443) if trojan_port else 443
    def q(value: str) -> str:
        # JSON basic-string escaping is also valid TOML basic-string escaping.
        # Values come from environment variables and paths, so interpolating them
        # directly would make quotes, backslashes, or newlines corrupt the file.
        return json.dumps(str(value), ensure_ascii=False)

    lines = [
        "# 由 norain-server install 生成。修改后运行 norain-server config validate 和 norain-server restart",
        "schema = 1", "",
        "[server]", f"domain = {q(domain)}", 'listen = "::"', "",
        "[protocols.hysteria2]", "enabled = true", f"port = {hy2}", "",
        "[protocols.trojan]", f"enabled = {'true' if trojan_port else 'false'}",
        f"port = {trojan}", "",
        "[auth]", f"credential_ref = {q(secret_ref)}", "",
        "[tls]", f"mode = {q(mode)}",
    ]
    if mode == "acme" and env.get("NORAIN_ACME_EMAIL"):
        lines.append(f"email = {q(env['NORAIN_ACME_EMAIL'])}")
    lines += ["", "[service]", "check_interval_seconds = 30", "restart_limit = 3",
              "restart_backoff_seconds = 2", "",
              "[logging]", 'directory = ""', 'level = "info"', "max_size_mb = 20", "retain_files = 5", ""]
    return "\n".join(lines)


# ---- 属主与目录 ----------------------------------------------------------------

def _service_ids() -> tuple[int, int] | None:
    if os.name != "posix":
        return None
    import pwd
    try:
        pw = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        return None
    return pw.pw_uid, pw.pw_gid


def sync_ownership(paths: Paths) -> None:
    """root 执行过的命令会在状态目录留下 root 属主的 0600 文件，守护进程（norain 用户）读不到，
    表现为「start 之后服务不启动」。所以每条命令结束时把目录属主同步回服务用户。
    只在通过 install 安装过（存在安装记录）时执行。"""
    ids = _service_ids()
    if ids is None or os.geteuid() != 0 or not paths.install_record.exists():
        return
    for top in (paths.home, paths.state, paths.log_dir):
        if not top.exists():
            continue
        for root, dirs, files in os.walk(top):
            for name in (".", *dirs, *files):
                try:
                    os.chown(os.path.join(root, name), *ids)
                except OSError:
                    pass


def _ensure_user(undo: list) -> None:
    if os.name != "posix" or _service_ids() is not None:
        return
    osutil.run_checked(["useradd", "--system", "--home-dir", "/var/lib/norain-server", "--shell",
                        "/usr/sbin/nologin", SERVICE_USER], what="创建服务用户", module="deploy")
    undo.append(lambda: osutil.run(["userdel", SERVICE_USER]))


def _ensure_dirs(paths: Paths) -> None:
    for d, mode in ((paths.home, 0o750), (paths.state, 0o750), (paths.log_dir, 0o750),
                    (paths.tls_dir, 0o700), (paths.secrets_dir, 0o700), (paths.run_dir, 0o700)):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, mode)


# ---- 自启动 --------------------------------------------------------------------

def _write_unit(paths: Paths) -> None:
    exe = sys.executable
    protect = "read-only" if exe.startswith("/home/") else "true"
    UNIT_PATH.write_text(_UNIT_TEMPLATE.format(
        user=SERVICE_USER, home=paths.home, python=exe, protect_home=protect,
        state=paths.state, log=paths.log_dir), encoding="utf-8")
    env_file = paths.home / "env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in _env_vars(paths).items()), encoding="utf-8")
    os.chmod(env_file, 0o640)


def _venv_package() -> str:
    return f"python3.{sys.version_info.minor}-venv"


def _ensure_prereqs(steps: list[str], warnings: list[str]) -> None:
    """补齐运行 norain-server 需要的前置条件（Linux）。

    安装器本身已经是 Python 程序，所以“装 Python 本身”由引导脚本 scripts/bootstrap-server.sh 做；
    这里补的是 venv 模块和 pip——Debian/Ubuntu 上要单独装（python3.X-venv / python3-pip），
    否则给服务建虚拟环境、装依赖都会失败。只在有 apt-get 且是 root 时自动装，其余发行版给出命令。
    """
    if osutil.IS_WINDOWS or not shutil.which("systemctl"):
        return
    missing: list[str] = []
    if osutil.run([sys.executable, "-c", "import venv"]).returncode != 0:
        missing.append(_venv_package())
    if osutil.run([sys.executable, "-m", "pip", "--version"]).returncode != 0:
        missing.append("python3-pip")
    if not missing:
        return
    if shutil.which("apt-get") and osutil.is_admin():
        for pkg in missing:
            osutil.run_checked(["apt-get", "install", "-y", "-q", pkg],
                               what=f"安装前置依赖 {pkg}", module="deploy")
            steps.append(f"前置依赖：已安装 {pkg}")
        return
    warnings.append("缺少前置依赖：" + "、".join(missing) + "；请手动安装后重试")


def register_autostart(paths: Paths) -> str:
    if osutil.IS_WINDOWS:
        cmd = osutil.quote_cmd([sys.executable, "-m", "norain_server", "run", "--if-desired"])
        osutil.task_create(TASK_NAME, cmd, trigger="ONSTART", highest=True, as_system=True)
        return f"计划任务 {TASK_NAME}（开机时以 SYSTEM 运行）"
    if not shutil.which("systemctl"):
        raise NorainError("没有 systemd，无法注册开机自启", exit_code=EXIT_EXTERNAL, module="deploy",
                          hint="可以手动把 `norain-server run` 加到你的服务管理器")
    _write_unit(paths)
    osutil.run_checked(["systemctl", "daemon-reload"], what="重载 systemd", module="deploy")
    osutil.run_checked(["systemctl", "enable", UNIT], what="启用开机自启", module="deploy")
    return f"systemd 单元 {UNIT_PATH}"


def unregister_autostart() -> list[str]:
    done = []
    if osutil.IS_WINDOWS:
        if osutil.task_delete(TASK_NAME):
            done.append(f"删除计划任务 {TASK_NAME}")
        return done
    if UNIT_PATH.exists():
        osutil.run(["systemctl", "disable", "--now", UNIT])
        UNIT_PATH.unlink(missing_ok=True)
        osutil.run(["systemctl", "daemon-reload"])
        osutil.run(["systemctl", "reset-failed", UNIT])
        done.append(f"删除 {UNIT_PATH}")
    return done


def _check_service_user_can_run() -> str | None:
    """守护进程以 norain 用户运行，它必须能导入本程序。返回警告文字或 None。"""
    if os.name != "posix" or not shutil.which("runuser"):
        return None
    proc = osutil.run(["runuser", "-u", SERVICE_USER, "--", sys.executable, "-c", "import norain_server"],
                      timeout=30)
    if proc.returncode != 0:
        return (f"用户 {SERVICE_USER} 无法导入 norain_server（Python 装在它读不到的位置，例如 /root 下）。"
                "请把 Norain 安装到系统级位置（例如 pip install 到 /usr/local 或 /opt 下的虚拟环境）")
    return None


# ---- 安装 ----------------------------------------------------------------------

def summary(paths: Paths) -> dict:
    """部署摘要，不含密码明文。"""
    cfg = load_config(paths.config)
    secret = generate.resolve_secret(cfg)
    st = runner.cert_status(cfg, paths, service_running=True)
    return {
        "domain": cfg.server.domain,
        "protocols": [{"name": label, "port": port, "transport": proto}
                      for proto, port, label in runner.firewall_ports(cfg) if label != "acme"],
        "tls": {"mode": cfg.tls.mode, "fingerprint_sha256": st.fingerprint_sha256,
                "not_after": st.not_after, "self_signed": st.self_signed},
        "auth": {"source": secret.source, "fingerprint": secret.fingerprint},
        "paths": {"config": str(paths.config), "state": str(paths.state), "log": str(paths.log_dir),
                  "singbox": str(paths.default_singbox)},
    }


def install(paths: Paths, *, force: bool = False, archive: Path | None = None,
            sha256: str | None = None, singbox_path: Path | None = None, start: bool = True,
            open_firewall: bool = True, env=None) -> dict:
    env = os.environ if env is None else env
    osutil.require_admin("安装服务端", module="deploy")
    undo: list[Callable[[], object]] = []
    steps: list[str] = []
    warnings: list[str] = []
    fresh_state = not paths.state.exists()
    try:
        _ensure_prereqs(steps, warnings)
        # 1. 目录和服务用户
        _ensure_user(undo)
        _ensure_dirs(paths)
        if fresh_state:
            undo.append(lambda: shutil.rmtree(paths.state, ignore_errors=True))
        steps.append("目录就绪")

        # 2. sing-box（校验 SHA-256，再核对版本和构建标签）
        had_bin = paths.default_singbox.is_file()
        info = fetch.install_singbox(paths.default_singbox, paths.cache_dir, archive=archive,
                                     expected_sha256=sha256, existing=singbox_path,
                                     need_tags={"with_quic"})
        if not had_bin:
            undo.append(lambda: paths.default_singbox.unlink(missing_ok=True))
        steps.append(f"sing-box {info.version} → {paths.default_singbox}")

        # 3. 密码：NORAIN_PASSWORD 注入，否则生成；已有的密码文件不覆盖
        secret_file = paths.secrets_dir / "password"
        injected = (env.get("NORAIN_PASSWORD") or "").strip()
        if injected and (force or not secret_file.exists()):
            old = secret_file.read_bytes() if secret_file.exists() else None
            fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(injected + "\n")
            if old is None:
                undo.append(lambda: secret_file.unlink(missing_ok=True))
            else:   # --force 覆盖了已有密码：失败时还原
                undo.append(lambda old=old: (secret_file.write_bytes(old), os.chmod(secret_file, 0o600)))
            steps.append("密码取自 NORAIN_PASSWORD，已写入密码文件")
        elif not secret_file.exists():
            generate_to_file(secret_file)
            undo.append(lambda: secret_file.unlink(missing_ok=True))
            steps.append(f"已生成随机密码：{secret_file}")

        # 4. 配置：已有的用户配置不覆盖，除非 --force（覆盖前备份）
        if paths.config.exists() and not force:
            steps.append(f"保留已有配置 {paths.config}")
        else:
            if paths.config.exists():
                bak = paths.config.with_name(f"{paths.config.name}.{time.strftime('%Y%m%dT%H%M%S')}.bak")
                shutil.copy2(paths.config, bak)
                undo.append(lambda bak=bak: shutil.copy2(bak, paths.config))   # --force 失败时还原旧配置
                steps.append(f"已备份旧配置到 {bak}")
            else:
                undo.append(lambda: paths.config.unlink(missing_ok=True))
            paths.config.write_text(
                default_config_text(paths, env, secret_ref=f"file:{secret_file.as_posix()}"),
                encoding="utf-8")
            os.chmod(paths.config, 0o640)
            steps.append(f"已写入默认配置 {paths.config}")

        # 5. 证书：self-signed 模式且还没有证书时生成（模式已在配置里显式写明）
        clean_env = {k: v for k, v in env.items() if not k.startswith("NORAIN_") or k == "NORAIN_PASSWORD"}
        cfg = load_config(paths.config, env=clean_env)
        if cfg.tls.mode == "self-signed":
            c, k = generate.cert_paths(cfg, paths)
            if not (c.exists() and k.exists()):
                certmod.self_signed(cfg.server.domain, c, k, force=True)
                steps.append(f"已生成自签证书 {c}")

        # 6. 生成 sing-box.json 并用 sing-box check 校验
        prep = runner.prepare(paths, apply=True)
        steps.append(f"配置校验通过（版本 {prep.applied.version}）")

        # 7. 安装记录、属主、启动器、环境变量、自启动
        write_json(paths.install_record, {"installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                          "singbox_installed_by_norain": not had_bin or bool(
                                              (read_json(paths.install_record) or {}).get(
                                                  "singbox_installed_by_norain")),
                                          "python": sys.executable})
        sync_ownership(paths)
        launcher_dir = paths.install_dir
        if not shutil.which("norain-server"):
            osutil.write_launcher(launcher_dir, "norain-server", "norain_server")
            undo.append(lambda: osutil.remove_launcher(launcher_dir, "norain-server"))
            steps.append(f"启动器：{launcher_dir}")
        env_vars = _env_vars(paths)
        if osutil.IS_WINDOWS:  # 最初目标：Windows 用 setx 写 HOME 和 CONFIG
            env_vars = {k: env_vars[k] for k in ("NORAIN_SERVER_HOME", "NORAIN_SERVER_CONFIG")}
        steps += osutil.persist_env(env_vars, system=True, name=ENV_NAME,
                                    path_dirs=(str(launcher_dir),) if osutil.IS_WINDOWS else ())
        undo.append(lambda: osutil.unpersist_env(list(env_vars), system=True, name=ENV_NAME,
                                                 path_dirs=(str(launcher_dir),) if osutil.IS_WINDOWS else ()))
        steps.append("开机自启：" + register_autostart(paths))
        undo.append(unregister_autostart)
        warn = _check_service_user_can_run()
        if warn:
            warnings.append(warn)

        # 8. 防火墙（失败只警告：安装本身不应因为防火墙后端的问题回滚）
        if open_firewall:
            try:
                fw = firewall.open_ports(cfg, paths)
                steps.append("防火墙：" + ("已放行 " + "、".join(fw["ports"]) if fw.get("applied")
                                        else fw.get("note", "需要手动放行")))
            except NorainError as e:
                warnings.append(f"防火墙未放行：{e.message}")

        # 9. 启动测试，失败回滚
        if start:
            op_id = new_op_id()
            set_desired(paths.desired, RUNNING, op_id=op_id)
            sync_ownership(paths)
            backend = pick_backend(paths)
            undo.append(lambda: (set_desired(paths.desired, STOPPED, op_id=op_id), backend.stop()))
            backend.start()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                st = backend.status()
                if st.state == "running" and st.child_pid:
                    break
                if st.state == "failed":
                    break
                time.sleep(0.5)
            else:
                st = backend.status()
            if not (st.state == "running" and st.child_pid):
                last = (read_json(paths.last_error) or {}).get("message", "sing-box 没有进入运行状态")
                raise NorainError(f"启动测试失败：{last}", exit_code=EXIT_EXTERNAL, module="deploy",
                                  hint="已回滚本次安装所做的修改；用户配置和日志保留")
            steps.append(f"启动测试通过（{backend.name}）")
    except BaseException:
        for fn in reversed(undo):
            try:
                fn()
            except Exception:  # noqa: BLE001 回滚尽力而为，不能掩盖原始错误
                pass
        raise
    sync_ownership(paths)
    return {"steps": steps, "warnings": warnings, "summary": summary(paths)}


# ---- 更新 ----------------------------------------------------------------------

def backup_user_data(paths: Paths) -> Path:
    """更新前备份配置和证书。"""
    dest = paths.backups / f"update-{time.strftime('%Y%m%dT%H%M%S')}"
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o700)
    if paths.config.exists():
        shutil.copy2(paths.config, dest / paths.config.name)
    for src, name in ((paths.tls_dir, "tls"), (paths.secrets_dir, "secrets"), (paths.acme_dir, "acme")):
        if src.is_dir():
            shutil.copytree(src, dest / name, dirs_exist_ok=True)
    if paths.default_singbox.is_file():
        shutil.copy2(paths.default_singbox, dest / paths.default_singbox.name)
    return dest


def update(paths: Paths, *, archive: Path | None = None, sha256: str | None = None,
           singbox_path: Path | None = None) -> dict:
    """把 sing-box 换成本版本锁定的版本，重写单元和环境变量，重新生成配置。
    Python 代码本身的升级由包管理器（pip）完成，升级后再运行本命令。"""
    osutil.require_admin("更新服务端", module="deploy")
    steps = []
    backup = backup_user_data(paths)
    steps.append(f"已备份配置和证书到 {backup}")
    cfg = load_config(paths.config)
    was_running = get_desired(paths.desired) == RUNNING
    old_bin = backup / paths.default_singbox.name
    try:
        info = fetch.install_singbox(paths.default_singbox, paths.cache_dir, archive=archive,
                                     expected_sha256=sha256, existing=singbox_path,
                                     need_tags=runner.need_tags(cfg))
        steps.append(f"sing-box {info.version}")
        prep = runner.prepare(paths, apply=True)
        steps.append(f"配置校验通过（版本 {prep.applied.version}）")
        steps.append("开机自启：" + register_autostart(paths))
        sync_ownership(paths)
        if was_running:
            backend = pick_backend(paths)
            backend.stop()
            backend.start()
            steps.append("已重启服务")
    except NorainError:
        if old_bin.is_file():  # 恢复旧二进制并尽量恢复服务
            shutil.copy2(old_bin, paths.default_singbox)
            if was_running:
                try:
                    pick_backend(paths).start()
                except NorainError:
                    pass
        raise
    return {"steps": steps, "backup": str(backup), "singbox_version": singbox.PINNED_VERSION}


# ---- 卸载 ----------------------------------------------------------------------

def uninstall(paths: Paths, *, purge: bool = False) -> dict:
    """清理自启动项、环境变量、防火墙规则、二进制和状态目录。默认保留配置和日志，--purge 才删除。"""
    osutil.require_admin("卸载服务端", module="deploy")
    done: list[str] = []
    errors: list[str] = []
    clean_state = True
    try:
        set_desired(paths.desired, STOPPED, op_id=new_op_id())
        pick_backend(paths).stop()
        done.append("已停止服务")
    except (NorainError, OSError) as e:
        errors.append(f"停止服务：{e}")
        clean_state = False
    try:
        done += unregister_autostart()
    except (NorainError, OSError) as e:
        errors.append(f"清理自启动项：{e}")
        clean_state = False
    try:
        fw = firewall.close_ports(paths)
        if fw.get("closed"):
            done.append("已移除防火墙规则：" + "、".join(fw["closed"]))
    except NorainError as e:
        errors.append(e.message)
        clean_state = False
    record = read_json(paths.install_record) or {}
    launcher_dir = paths.install_dir
    try:
        done += osutil.unpersist_env(list(_env_vars(paths)), system=True, name=ENV_NAME,
                                     path_dirs=(str(launcher_dir),) if osutil.IS_WINDOWS else ())
    except NorainError as e:
        errors.append(e.message)
        clean_state = False
    if osutil.remove_launcher(launcher_dir, "norain-server"):
        done.append("已删除启动器")
    # 只有确认是 Norain 装的才删：安装记录缺失时不能假定这个二进制属于我们
    if record.get("singbox_installed_by_norain") is True and paths.default_singbox.is_file():
        paths.default_singbox.unlink(missing_ok=True)
        done.append(f"已删除 {paths.default_singbox}")
    if osutil.IS_WINDOWS and launcher_dir.is_dir() and not any(launcher_dir.iterdir()):
        launcher_dir.rmdir()
    (paths.home / "env").unlink(missing_ok=True)
    if clean_state and paths.state.exists():
        shutil.rmtree(paths.state, ignore_errors=True)
        if paths.state.exists():
            errors.append(f"删除状态目录失败：{paths.state}")
            clean_state = False
        else:
            done.append(f"已删除状态目录 {paths.state}")
    elif paths.state.exists():
        errors.append(f"服务、启动项、防火墙或环境变量未清理干净，保留状态目录 {paths.state}；"
                     "处理上面的错误后重新运行 uninstall")
    kept = []
    if purge and clean_state:
        for d in (paths.home, paths.log_dir):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
                done.append(f"已删除 {d}")
        if os.name == "posix" and _service_ids() is not None:
            osutil.run(["userdel", SERVICE_USER])
            done.append(f"已删除用户 {SERVICE_USER}")
    elif purge and not clean_state:
        errors.append("因为前面的清理失败，保留配置和日志；处理错误后重新运行 uninstall --purge")
        kept = [str(d) for d in (paths.home, paths.log_dir) if d.exists()]
    else:
        kept = [str(d) for d in (paths.home, paths.log_dir) if d.exists()]
    return {"done": done, "kept": kept, "errors": errors}


# ---- fix -----------------------------------------------------------------------

def fix(paths: Paths, *, env=None) -> dict:
    """配置重建、证书检查、缺失文件恢复（最初目标：不做客户端式的四级修复）。"""
    env = os.environ if env is None else env
    actions: list[str] = []
    problems: list[str] = []
    _ensure_dirs(paths)

    secret_file = paths.secrets_dir / "password"
    if not paths.config.exists():
        if not secret_file.exists():
            generate_to_file(secret_file)
            actions.append(f"密码文件缺失，已重新生成：{secret_file}（客户端需要换成新密码）")
        paths.config.write_text(default_config_text(paths, env, secret_ref=f"file:{secret_file}"),
                                encoding="utf-8")
        os.chmod(paths.config, 0o640)
        actions.append(f"配置文件缺失，已写入默认配置：{paths.config}")
    cfg = load_config(paths.config)  # 配置格式错误在这里抛出，带字段级错误

    ref = cfg.auth.credential_ref
    if ref.startswith("file:") and not Path(ref[5:]).expanduser().exists():
        if Path(ref[5:]).expanduser() == secret_file:
            generate_to_file(secret_file)
            actions.append(f"密码文件缺失，已重新生成：{secret_file}（客户端需要换成新密码）")
        else:
            problems.append(f"密码文件不存在：{ref[5:]}（不是 Norain 管理的路径，需要手动恢复）")

    try:
        info = runner.locate_singbox(paths)
        singbox.require(info, need_tags=runner.need_tags(cfg))
    except NorainError as e:
        if paths.singbox:
            problems.append(f"{e.message}（NORAIN_SERVER_SINGBOX 指向的文件需要手动处理）")
        else:
            info = fetch.install_singbox(paths.default_singbox, paths.cache_dir,
                                         need_tags=runner.need_tags(cfg))
            actions.append(f"sing-box 缺失或版本不符，已重新安装 {info.version}")

    st = runner.cert_status(cfg, paths, service_running=runner.service_running(paths))
    if not st.ok:
        if cfg.tls.mode == "self-signed":
            c, k = generate.cert_paths(cfg, paths)
            if c.parent == paths.tls_dir:
                certmod.self_signed(cfg.server.domain, c, k, force=True)
                actions.append("自签证书缺失或失效，已重新生成（客户端需要换成新证书）")
            else:
                problems += st.errors
        else:
            problems += st.errors
    if problems:
        raise NorainError("有问题无法自动修复：" + "；".join(problems), exit_code=EXIT_CONFLICT,
                          business_code=120 if not st.ok else 110, module="fix",
                          hint="按提示手动处理后重新运行 fix")

    prep = runner.prepare(paths, apply=True)
    actions.append(f"已重建 sing-box.json（版本 {prep.applied.version}"
                   f"{'，内容有变化' if prep.applied.changed else '，内容未变'}）")
    if paths.install_record.exists():
        missing_autostart = (not osutil.task_exists(TASK_NAME)) if osutil.IS_WINDOWS else not UNIT_PATH.exists()
        if missing_autostart and osutil.is_admin():
            actions.append("自启动项缺失，已恢复：" + register_autostart(paths))
    sync_ownership(paths)
    return {"actions": actions, "restart_needed": prep.applied.changed,
            "warnings": st.warnings}
