# Norain 交接说明

- 日期：2026-11-14（第二次更新）
- 一句话状态：最初目标里两端的全部模块**代码已写完（理论代码）**，但**没有任何一行在真实环境里运行过**：
  没有跑测试、没有用过真实的 sing-box、没有在 Windows 或 Linux 上执行过任何系统命令。
  只做过语法检查（`py_compile`）、导入检查和静态名称检查（`pyflakes`）。

## 必须先知道的规则

1. **以最初目标 `docs/reference/original-goals.md` 为准，除非有硬性 bug。** 与它冲突的设计以各决策记录文末的「修订」一节为准。
2. 用户之后的明确答复优先于最初目标：ACME 用 HTTP-01；白名单 = 强制走代理，黑名单 = 直连，蓝名单 = 阻断模式下仍允许的连接；未命中名单默认走代理；全局流量 = TUN；客户端以 Windows 为主。
3. 没有实现的功能不能报告为已实现。配置里写了未实现的取值，校验必须拒绝（目前只有 `traffic_mode = "transparent"`）。
4. sing-box 锁定 1.14.4（`third_party/singbox.lock.toml`），不使用 1.14 已弃用的字段。
5. **服务端支持 Windows**（2026-11-14 用户确认保留，取代早先「服务端暂不支持 Windows」的答复，见 ADR 0001 修订）。实现包括 Windows 路径、netsh 防火墙、计划任务自启和 setx；它是全仓库验证程度最低的部分。

## 从哪里读起

| 文件 | 内容 |
|---|---|
| `docs/reference/original-goals.md` | 最初目标（最高优先级） |
| `docs/decisions/README.md` | 16 份决策记录的索引和状态 |
| `docs/pending.md` | 每个功能的实现状态和验证状态 |
| `examples/server.toml`、`examples/cfg.toml` | 配置示例（含全部字段） |
| 各模块文件开头的文档字符串 | 该模块的设计、与最初目标的对应关系、哪些地方是推定的 |

## 模块与文件

**共享 `src/norain_core/`**

| 文件 | 内容 |
|---|---|
| `supervisor.py` | sing-box 子进程监督器；新增「重载请求」（不计失败次数）和日志行回调 |
| `osutil.py`（新） | 管理员判断、外部命令、后台进程、持久环境变量和 PATH、启动器、弹窗、Windows 计划任务 |
| `tomlio.py`（新） | TOML 写出（命令行改配置用） |
| `fetch.py` | 下载、校验、解出 sing-box；新增 `install_singbox`，现在被两端的 install 调用 |
| 其余 | 退出码、脱敏、秘密引用、原子写入、日志、期望状态和操作锁、sing-box 定位和 check、后台启停 |

**服务端 `src/norain_server/`**（最初目标的八个模块）

| 模块 | 文件 |
|---|---|
| 入站、配置 | `model.py`、`generate.py` |
| 证书（manual / self-signed / acme） | `cert.py`；acme 生成顶层 `certificate_providers` |
| 守护 | `runner.py` + 共享监督器 |
| 防火墙（ufw / firewalld / netsh，真实操作） | `firewall.py`（新） |
| 状态日志 | `cli.py` 的 `status`、`log` |
| 外控制 | `cli.py` |
| 部署更新（install / update / uninstall / fix） | `deploy.py`（新） |

命令：`config validate|show|edit`、`cert check|self-signed`、`secret generate`、`start|stop|restart|reload|status|run`、`log [-f]`、`firewall open|close|status`、`fix`、`install|update|uninstall [--purge]`。

**客户端 `src/norain/`**（最初目标的九个模块）

| 模块 | 文件 | 要点 |
|---|---|---|
| 代理 | `proxy.py`、`generate.py` | 被监督的 sing-box；mixed / system-proxy / TUN |
| 分流 | `generate.py`、`routing.py`、`rules.py` | 名单 + 规则集写进 sing-box；「试连 → 改判 → 加入名单」做成事后学习 |
| 监控 | `monitor.py`、`probe.py` | 错误码 100/301/400/401/600/604/606，带防抖动 |
| 自维持 | `maintain.py` | 进程内的 Maintainer + 独立的看门狗进程互拉 |
| 阻断 | `block.py` | Windows 防火墙规则 / nftables 独立表；弹窗；手动解除 |
| 修复 | `repair.py` | file / builtin / full / reload 四级 |
| 启动 | `boot.py` | 开机自启动注册、启动时自动解除阻断、正常 / 安全模式 |
| 内控制 | `control.py` | 审批、启动测试、自适应选协议、规则集自更新、命令通道 |
| 外控制 | `cli.py` | 配置类、控制类、`-t` 调试 |
| 安装卸载 | `install.py` | `norain install|uninstall` |

命令见 `src/norain/cli.py` 开头。

## 与最初目标不完全一致的地方（都有硬性原因）

- **分流的逐请求判断**：sing-box 在进程内完成路由，Norain 无法在每个请求上介入。最初目标的第 3、4 步改为事后学习：从 sing-box 日志发现访问失败的域名，执行同样的判断流程，把结论写进学到的名单并重载。第一次访问仍按静态规则走。
- **GeoIP 数据库**：sing-box 1.12 起移除了内置 GeoIP，用 `geoip-cn` / `geosite-cn` 规则集代替，判断 IP 归属时调用 `sing-box rule-set match`。
- **模块 = 线程**：代理、分流、监控、自维持是内控制进程里的线程，不是各自独立的进程。真正跨进程的互拉只有「内控制进程 ↔ 看门狗进程」。
- **`traffic_mode = "transparent"`** 没有实现，校验会拒绝。
- **客户端的 `cache_ttl_seconds`** 只用于学到的解析结果，不控制 sing-box 自身的 DNS 缓存。

## 没有验证、最可能出错的地方

按风险从高到低：

1. **阻断模块的防火墙命令**（`block.py`）：Windows 上为「放行范围的补集」建出站阻断规则，Linux 上用 nftables。写错的后果是断网或者没挡住。只能在一次性虚拟机里验证。
2. **生成的 sing-box 配置**能否通过真实的 `sing-box check`：TUN、DNS 规则、`certificate_providers`、探测入口、规则集。字段名对照过 1.14 文档，但没有用真实二进制校验。
3. **sing-box 的日志格式**（`routing.py` 的两个正则）：是按常见输出推定的。格式对不上时分流学习不会触发，其他功能不受影响。
4. **`sing-box rule-set match` 的输出格式**（`rules.py` 的 `Geo`）：按「输出里有 match 字样即匹配」处理。不对的话 401 检测和 GeoIP 判断会失效。
5. **规则集下载地址和 `.srs` 文件头**（`rules.py`）。
6. **Windows 计划任务、setx、注册表 PATH**（`osutil.py`、`boot.py`、`deploy.py`）。
7. **systemd 单元以 `norain` 用户运行时能否导入本程序**：`deploy.py` 安装时会用 `runuser` 检查并给出警告。
8. **sing-box 压缩包的 SHA-256** 是从发布页转录的（`hashes_verified = false`），第一次真实下载时要复核；不符时可用 `--singbox-archive` 加 `--singbox-sha256`。

## 测试

`tests/` 已按新行为更新，并新增 `tests/test_modules.py`（判定表、防抖动、阻断补集、TOML、选协议）。**这些测试没有执行过。** 生命周期测试只能在 Linux 上跑（模拟的 sing-box 是带 shebang 的脚本）。

```bash
python3 -m pytest -q
```

## 已知问题和注意事项

- Windows 上不检查密码文件和运行配置（含明文密码）的访问权限。
- 阻断模式下域名在进入时解析成 IP，之后对端换 IP 需要重新进入阻断才会更新。
- 阻断模式按 IP 放行，不区分端口。
- 分流学习依赖 sing-box 的 info 级别日志；`logging.level` 调到 warn 或 error 后学习失效。
- 修复期间（`repairing` 阶段）命令行对单个模块的启停会被内控制拒绝，稍后重试即可。
- `docs/architecture-audit.md`、`docs/reports/phase-*.md` 是早期阶段的快照，里面「未实现」的描述已经过时，以 `docs/pending.md` 为准。

## 开发环境

Python ≥ 3.11，依赖 pydantic、cryptography、psutil、pytest。

```bash
pip install -e .        # 注册 norain 和 norain-server 命令
```
