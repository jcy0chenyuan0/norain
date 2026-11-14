# 0005 客户端流量接管方式与「全局流量」的含义

- 状态：已接受（2026-11-14，见「确认」）
- 日期：2026-11-14
- 关联：审计问题 5；原稿「阶段 2」「代理模块」；ADR 0006、0011

## 背景

原稿列出 `mixed | system-proxy | tun | transparent` 四种模式，「全局流量」没有定义。四种模式需要的权限、对 DNS 的影响和故障面差别很大。

| 模式 | 接管范围 | 权限 | DNS | 主要风险 |
|---|---|---|---|---|
| mixed（本地 HTTP+SOCKS） | 只有手动配置了代理的应用 | 普通用户 | 应用通过 SOCKS5 或 HTTP CONNECT 传域名时由出站侧处理，自行解析域名的应用会走系统 DNS | 覆盖面小 |
| system-proxy | 遵守系统代理设置的应用（浏览器等） | 普通用户；需改系统设置 | 同上 | 异常退出后系统代理残留，导致断网 |
| tun | 几乎所有 IP 流量 | 管理员/root；Windows 需要 TUN 驱动 | 必须劫持 DNS | 路由表和 DNS 被改；崩溃时可能断网或泄漏 |
| transparent（Linux tproxy/redirect） | 本机或网关流量 | root；nftables/iptables | 必须劫持 DNS | 规则残留；Windows 不适用 |

## 建议

1. **阶段 2 只实现 `mixed`**：在 `127.0.0.1` 监听，校验器拒绝其他取值，默认配置中也不出现其他取值。
2. **「全局流量」定义为 TUN 模式**（sing-box `tun` inbound，开启 `auto_route` 和 `strict_route`）。这是阶段 2 之后的独立里程碑，前提是 ADR 0006（DNS）和 ADR 0011（隔离）都已接受，因为 TUN 崩溃时的流量去向与隔离的恢复路径直接相关。
3. **system-proxy** 作为 mixed 的附加选项，排在 TUN 之前。实现前要先设计异常退出后的系统代理清理路径（启动时检测残留，并提供 `norain restore-system-proxy`）。是否使用 sing-box mixed inbound 自带的 `set_system_proxy` 需要先在各平台验证。
4. **transparent** 只面向 Linux，不进入首个版本规划。

## 待验证

- `set_system_proxy` 支持哪些平台和桌面环境，以及进程被杀时是否会还原。
- Windows 上 sing-box TUN 的驱动来源和权限要求。
- TUN 选项 `stack` 在 1.15 弃用、1.17 移除。实现 TUN 时如果仍锁定 1.14，生成器不要写 `stack`，使用默认值。

## 需要用户确认

1. ~~「全局流量」的含义~~ → 已确认：TUN。
2. ~~客户端主要平台~~ → 已确认：Windows。TUN 先做 Windows。

## 确认

- 2026-11-14，用户：「全局流量」= TUN。阶段 2 先做 mixed，TUN 作为后续独立里程碑，这一安排不变。
- 2026-11-14，用户：客户端主要在 Windows 上使用。
