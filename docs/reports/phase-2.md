# 阶段 2 交付报告：客户端最小垂直切片

- 日期：2026-11-14
- 状态：**代码完成，只经过模拟验证，且只在 Linux 上运行过。** 客户端的主要平台是 Windows，但 Windows 上一行都没有执行过。按规则，阶段 2 尚未验收。

## 输入

- 用户指示：继续写理论代码；客户端主要在 Windows 上使用；以最初目标为准，除非有硬性 bug
- ADR 0005（阶段 2 只做 mixed）、0006（DNS 只做 local）、0016（v0.1 范围）

## 已确认约束

- 只实现代理模块的最小形态：本地 mixed 代理（HTTP 和 SOCKS5 共用端口），单一固定协议
- 未命中规则的流量默认走代理（ADR 0007）；局域网和回环地址直连
- 分流、监控、自维持的互拉保活、阻断、修复、开机自启动、内控制不在本阶段

## 修改文件

| 文件 | 说明 |
|---|---|
| `src/norain_core/supervisor.py` | 从服务端守护抽出的通用监督器；新增停止请求文件 |
| `src/norain_core/daemonctl.py` | 通用的后台启动、停止、查询；兼容 Windows 的进程创建参数 |
| `src/norain_core/apply.py` | 通用的「生成 → check → 备份 → 替换」 |
| `src/norain_core/cliutil.py` | 通用的输出、错误显示、日志查看 |
| `src/norain_core/state.py` | 进程存活检查改用 psutil（原写法在 Windows 上不安全） |
| `src/norain_core/singbox.py` | 定位二进制时支持各端自己的默认位置 |
| `src/norain_server/{runner,service,generate,cli,paths}.py` | 改为使用上面的共享模块，行为不变 |
| `src/norain/{paths,model,generate,runner,cli,__main__}.py` | 客户端 |
| `examples/cfg.toml` | 客户端配置示例 |
| `tests/test_client.py`、`tests/fakes/sing-box` | 客户端测试；模拟 sing-box 支持客户端配置 |
| `pyproject.toml` | 注册 `norain` 命令 |

## 可用命令

```text
norain config validate | show
norain start | stop | restart
norain status [--json]
norain logs [-f] [-n N]
norain run
```

尚未实现：`install`、`uninstall`、`start --safe`、`module`、`repair`、`firewall`、`debug`、`config edit`。

`cfg.toml` 保留了最初目标的字段（`protocol = "auto"`、`traffic_mode = "tun"`、白/黑/蓝名单等），但写了未实现的取值时，校验会报「尚未实现」并拒绝启动，不会假装生效。

## 测试结果

```text
$ python3 -m pytest -q
37 passed
```

其中客户端 8 个：JSON 结构（两种协议）、未实现取值被拒绝、字段级错误、Windows 与 Linux 的路径规则、完整的 validate → start → status → stop 链路、只靠停止请求文件停止、端口占用（130）、重启上限（160）、崩溃后自动重启、无效配置下 restart 不影响运行中的代理。服务端的 29 个测试在重构后全部通过。

## 已验证平台

- **无真实验证。** 全部测试在 Ubuntu 24.04 x86_64、Python 3.13.18 上，使用模拟的 sing-box 运行。

## 未验证项目

1. **Windows 上的一切。** 包括：后台启动的进程创建参数、停止请求文件在 Windows 上的实际效果、`%APPDATA%` 路径、日志和配置文件的读写、psutil 的端口检查。Windows 路径规则只是在 Linux 上用假环境变量做了单元测试。
2. **Windows 上的秘密文件权限没有检查。** Linux 上会拒绝权限宽于 0600 的密码文件；Windows 上目前跳过这一检查，密码文件和生成的 `sing-box.json`（含明文密码）依赖用户目录的默认访问权限。
3. 生成的客户端 JSON 能否通过真实的 `sing-box check`。重点怀疑：路由规则 `ip_is_private` 加 `action: route` 的写法、`route.default_domain_resolver`、出站 TLS 的 `certificate_path`。
4. 真实的端到端连通：客户端经 Hysteria2 或 Trojan 连上 `norain-server`，浏览器通过本地代理访问网站。
5. 阶段 1 报告里列出的未验证项目仍然全部有效。

## 已知限制

- `status` 显示「运行中」只代表本地 sing-box 进程在运行、本地端口在监听，**不代表代理能连通**。链路检测属于监控模块（v0.5）。`status` 的输出里写明了这一点。
- 最初目标没有给客户端的进程故障定义业务码，目前沿用服务端的 110–160。监控模块的 100–606 留给 v0.5。
- 客户端的守护进程没有外层保活：守护进程自身被结束后不会恢复。最初目标里的互拉保活属于自维持模块，尚未实现。

## 验收命令

模拟验证：

```bash
cd norain && python3 -m pytest -q
```

真实验证（Windows，PowerShell；需要已安装 Python ≥ 3.11，并已把 sing-box 1.14.4 的 `sing-box.exe` 放到 `%LOCALAPPDATA%\norain\bin\`）：

```powershell
pip install .
mkdir $env:APPDATA\norain
copy examples\cfg.toml $env:APPDATA\norain\cfg.toml
# 编辑 cfg.toml：server 改成你的服务器；如果服务端是自签证书，填 certificate_path
$env:NORAIN_PASSWORD = "<服务器密码>"
norain config validate      # 关键：真实的 sing-box check
norain start
norain status
curl.exe -x http://127.0.0.1:2080 https://www.gstatic.com/generate_204 -I   # 应返回 204
norain stop
norain status               # 应为已停止
```

## 回滚方式

- 代码：删除 `src/norain/` 下除 `__init__.py` 外的文件、`tests/test_client.py`、`examples/cfg.toml`。共享模块的重构不影响服务端行为，可以保留。
- 运行环境：`norain stop`，删除配置目录和状态目录（Windows 为 `%APPDATA%\norain` 和 `%LOCALAPPDATA%\norain`），再 `pip uninstall norain`。v0.1 不修改系统代理、路由表、防火墙和注册表。
