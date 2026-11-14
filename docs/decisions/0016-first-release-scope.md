# 0016 首个可用版本范围

- 状态：已接受（2026-11-14，见「确认」）
- 日期：2026-11-14
- 关联：审计问题 10；全部 ADR

## 建议：v0.1（阶段 1 + 阶段 2）

**服务端**

- `server.toml` 模型（含 `schema = 1`）、字段级错误、未知字段拒绝。
- Hysteria2 和 Trojan 单独启用或同时启用；证书模式为 manual 和 self-signed。
- `config validate/show`、`cert check`、`cert self-signed`、`secret generate`、`start/stop/restart/status --json`、`run`、`log [-f]`。
- 只支持 Linux（ADR 0001）。在 Ubuntu 24.04 amd64 上真实验证 systemd 单元。
- 防火墙：只实现 `firewall status`（只读）。`open/close` 先输出 ufw/firewalld 的手动命令，不修改系统。

**客户端**

- `cfg.toml` 模型，只支持 `traffic_mode = "mixed"`、单一固定协议、`dns.mode = "local"`。
- `config validate/show`、`start/stop/status --json`、`logs`。
- Python 监督器支持有限次数重启和退避。

## v0.1 之后的里程碑顺序（推荐）

用户已确认「全局流量」= TUN，所以 TUN 排在系统代理之前。

| 里程碑 | 内容 | 理由 |
|---|---|---|
| v0.2 | 服务端：ACME（HTTP-01）、防火墙 open/close、install/update/uninstall | 服务端可以完整自动部署 |
| v0.3 | 客户端 TUN（先做你主要使用的平台）+ 配套 DNS（ADR 0006 的 TUN 草案） | 实现「全局流量」 |
| v0.4 | 白名单/黑名单分流 + rule-set | 分流必须依赖 TUN 下的 DNS 才有意义 |
| v0.5 | 监控 + 自动协议选择 | 自动选择依赖监控数据 |
| v0.6 | 隔离（只能手动触发） | 风险最高，放在 TUN 和监控都稳定之后 |
| 之后 | 修复四级、客户端开机自启动、本地控制通道、system-proxy | |

## 延后

| 功能 | 依赖的 ADR | 延后原因 |
|---|---|---|
| ACME | 0015 | v0.2 实现，默认 HTTP-01 |
| 防火墙 open/close 真实操作 | — | 需要后端适配器和回滚测试 |
| install/update/uninstall 自动部署 | 0001、0002、0012 | 需要真实下载和二进制校验 |
| 服务端 Windows 支持 | 0001 | 用户确认暂不需要 |
| 分流（名单、rule-set） | 0007、0008 | 语义未定 |
| split/proxy DNS | 0006 | 依赖 TUN |
| system-proxy、TUN、transparent | 0005 | 需要权限和清理路径 |
| 自动协议选择 | 0009 | 依赖监控 |
| 监控与业务码 | 0010 | 目标未定 |
| 隔离 | 0011 | 风险最高，独立阶段 |
| 修复四级 | — | 依赖完整的安装布局 |
| 客户端开机自启动 | 0013 | 各平台的用户级机制不同 |
| 内控制本地控制通道 | — | 传输方式和鉴权未定 |

## 需要用户确认

1. v0.1 的范围。
2. 防火墙 `open/close` 在 v0.1 只输出手动命令，不修改系统。

## 确认

- 2026-11-14，用户：v0.1 范围和后续里程碑顺序全部采纳。TUN 先做 Windows。
- 2026-11-14，用户：先写理论代码。阶段 1 代码先用模拟 sing-box 测试，真实验证留待能下载 sing-box 的环境。
