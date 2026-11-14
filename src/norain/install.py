"""客户端的安装与卸载（自动部署并加入环境变量）。

install：sing-box → 默认配置 → 安装包副本和哈希清单（修复模块用）→ `norain` 启动器和环境变量
         → 规则集 → 校验配置 → 开机自启动 → 启动。
uninstall：停止全部进程、解除阻断、删除自启动项、环境变量、PATH、启动器和全部文件。
           它同时是「重载修复」的前半段，也是一条独立的命令。

Python 包本身由包管理器安装（pip），卸载命令不删除它。本模块尚未在真实系统上验证。
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from norain_core import fetch, osutil
from norain_core.errors import NorainError
from norain_core.log import Logger, new_op_id
from norain_core.state import STOPPED, read_json, set_desired, write_json

from . import block, boot, repair, rules
from .model import load_config
from .paths import Paths

ENV_NAME = "norain"


def _env(paths: Paths) -> dict[str, str]:
    return {"NORAIN_HOME": str(paths.home), "NORAIN_CONFIG": str(paths.config)}


def default_config_text(paths: Paths, *, server: str, credential_ref: str, traffic_mode: str,
                        protocol: str) -> str:
    return f"""# 由 norain install 生成。修改后运行 norain config validate 和 norain restart
schema = 1

[app]
mode = "normal"            # normal：开机自启动；safe：只手动启动
auto_start = true

[local]
listen = "127.0.0.1"
port = 2080

[proxy]
protocol = "{protocol}"    # auto | hysteria2 | trojan
server = "{server}"
traffic_mode = "{traffic_mode}"   # tun：全局接管（需要管理员权限）；mixed：只有本地代理
credential_ref = "{credential_ref}"

[proxy.hysteria2]
port = 443

[proxy.trojan]
port = 443

[routing]
proxy_domains = []         # 白名单：强制走代理
direct_domains = []        # 黑名单：强制直连
isolation_allowlist = []   # 蓝名单：阻断模式下仍允许的连接

[dns]
mode = "split"
"""


def install(paths: Paths, *, archive: Path | None = None, sha256: str | None = None,
            singbox_path: Path | None = None, config_src: Path | None = None, server: str = "",
            traffic_mode: str = "tun", protocol: str = "auto", force: bool = False, start: bool = True,
            log: Logger | None = None, env=None) -> dict:
    env = os.environ if env is None else env
    steps: list[str] = []
    warnings: list[str] = []
    for d in (paths.home, paths.state, paths.bin_dir, paths.run_dir, paths.log_dir, paths.package_dir):
        d.mkdir(parents=True, exist_ok=True)
    for d in (paths.home, paths.state):
        os.chmod(d, 0o700)

    # 1. sing-box：校验 SHA-256，再核对版本和构建标签
    info = fetch.install_singbox(paths.bundled_singbox, paths.cache_dir, archive=archive,
                                 expected_sha256=sha256, existing=singbox_path, need_tags={"with_quic"})
    steps.append(f"sing-box {info.version} → {paths.bundled_singbox}")

    # 2. 配置：已有的用户配置不覆盖，除非 --force（覆盖前备份）
    if paths.config.exists() and not force:
        steps.append(f"保留已有配置 {paths.config}")
    else:
        if paths.config.exists():
            bak = paths.config.with_name(f"{paths.config.name}.{time.strftime('%Y%m%dT%H%M%S')}.bak")
            shutil.copy2(paths.config, bak)
            steps.append(f"已备份旧配置到 {bak}")
        if config_src is not None:
            shutil.copy2(config_src, paths.config)
            steps.append(f"配置取自 {config_src}")
        else:
            server = server or (env.get("NORAIN_SERVER") or "").strip()
            injected = (env.get("NORAIN_PASSWORD") or "").strip()
            secret_file = paths.home / "password"
            if injected:
                fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(injected + "\n")
                steps.append("密码取自 NORAIN_PASSWORD，已写入密码文件")
            ref = f"file:{secret_file.as_posix()}"
            if not secret_file.exists():
                warnings.append(f"还没有密码：把服务端的密码写进 {secret_file}（只写一行）")
            paths.config.write_text(default_config_text(paths, server=server, credential_ref=ref,
                                                        traffic_mode=traffic_mode, protocol=protocol),
                                    encoding="utf-8")
            steps.append(f"已写入默认配置 {paths.config}")
        os.chmod(paths.config, 0o600)

    # 3. 安装包副本、初始配置和哈希清单：文件修复、完全配置修复、重载修复都以它们为准
    if force or not paths.orig_config.exists():
        shutil.copy2(paths.config, paths.orig_config)
    repair.save_package(paths)
    steps.append(f"已保存安装包副本和哈希清单：{paths.package_dir}")

    # 4. norain 命令和环境变量
    osutil.write_launcher(paths.bin_dir, "norain", "norain")
    steps += osutil.persist_env(_env(paths), system=False, name=ENV_NAME, path_dirs=(str(paths.bin_dir),))

    # 5. 规则集（国内网络直接下载 GitHub 可能失败；代理起来之后内控制模块会经代理自动重试）
    cfg = None
    try:
        cfg = load_config(paths.config)
    except NorainError as e:
        warnings.append("配置还不能用：" + ("；".join(f"{f.path} {f.message}" for f in e.field_errors) or e.message))
    if cfg is not None:
        rep = rules.update(cfg, paths, timeout=20)
        if rep["failed"]:
            warnings.append("规则集暂时没有下载成功（代理启动后会自动重试）：" + "、".join(rep["failed"]))
        else:
            steps.append("规则集就绪：" + "、".join(rep["updated"] + rep["unchanged"]))
        if rep["unpinned"]:
            warnings.append("规则集没有锁定哈希，只记录了本次下载的哈希：" + "、".join(rep["unpinned"]))

    # 6. 安装记录
    write_json(paths.install_record, {"installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                      "bin_dir": str(paths.bin_dir), "env": list(_env(paths))})

    # 7. 开机自启动和首次启动
    started = False
    if cfg is not None:
        try:
            steps.append(boot.sync(paths, cfg))
        except NorainError as e:
            warnings.append(f"开机自启动没有注册：{e.message}" + (f"（{e.hint}）" if e.hint else ""))
        if start:
            from . import runner
            from norain_core.state import RUNNING
            try:
                runner.prepare(paths, apply=True)
                set_desired(paths.desired, RUNNING, op_id=new_op_id())
                runner.backend(paths).start(timeout=40)
                started = True
                steps.append("已启动")
            except NorainError as e:
                set_desired(paths.desired, STOPPED, op_id=new_op_id())
                warnings.append(f"没有启动成功：{e.message}" + (f"（{e.hint}）" if e.hint else "")
                                + "。修正后运行 norain start")
    if log:
        log.info("install.done", steps=steps, warnings=warnings)
    return {"steps": steps, "warnings": warnings, "started": started,
            "config": str(paths.config), "state": str(paths.state)}


def clear_system_proxy(paths: Paths) -> str | None:
    """system-proxy 模式异常退出后系统代理可能残留。只在它指向本机回环地址时才清除。"""
    if not osutil.IS_WINDOWS:
        return None
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
            enabled, _ = winreg.QueryValueEx(k, "ProxyEnable")
            server, _ = winreg.QueryValueEx(k, "ProxyServer")
            if enabled and str(server).startswith(("127.0.0.1:", "localhost:", "[::1]:")):
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                return f"已清除残留的系统代理设置（{server}）"
    except OSError:
        pass
    return None


def stop_everything(paths: Paths) -> list[str]:
    """停止内控制进程和看门狗。先写期望状态，保证任何保活方都不会再拉起。"""
    from . import maintain, runner
    done = []
    set_desired(paths.desired, STOPPED, op_id=new_op_id())
    try:
        runner.backend(paths).stop()
        done.append("已停止代理")
    except NorainError as e:
        done.append(f"停止代理时出错：{e.message}")
    if maintain.kill_watchdog(paths):
        done.append("已停止看门狗")
    return done


def uninstall(paths: Paths, *, log: Logger | None = None) -> dict:
    """完全卸载：清除注册表 / 计划任务 / 环境变量 / 防火墙规则 / 全部文件。"""
    done: list[str] = []
    errors: list[str] = []
    if paths.state.exists():
        done += stop_everything(paths)
    try:
        if block.release(paths)["was_active"]:
            done.append("已解除阻断")
    except NorainError as e:
        errors.append(f"{e.message}（{e.hint}）")
    try:
        done += boot.unregister()
    except NorainError as e:
        errors.append(e.message)
    msg = clear_system_proxy(paths)
    if msg:
        done.append(msg)
    record = read_json(paths.install_record) or {}
    bin_dir = Path(record.get("bin_dir") or paths.bin_dir)
    try:
        done += osutil.unpersist_env(list(_env(paths)), system=False, name=ENV_NAME, path_dirs=(str(bin_dir),))
    except NorainError as e:
        errors.append(e.message)
    osutil.remove_launcher(bin_dir, "norain")
    for d in (paths.state, paths.log_dir, paths.home):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            if d.exists():
                errors.append(f"没有删干净：{d}（可能有文件被占用）")
            else:
                done.append(f"已删除 {d}")
    # 这里不再写日志：日志目录刚被删除，写入会把它重新建出来
    return {"done": done, "errors": errors,
            "note": "Python 包本身没有卸载；需要时运行 pip uninstall norain"}
