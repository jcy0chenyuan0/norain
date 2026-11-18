# 0006 DNS 策略、IPv4/IPv6 与防泄漏

- 状态：提议
- 日期：2026-11-14
- 关联：审计问题 6；原稿「分流模块」「监控模块」业务码 401；ADR 0005、0007

## 背景

原稿要求说明本地 DNS、代理侧 DNS、备用 DNS、缓存 TTL、IPv4/IPv6、防泄漏和失败时的默认动作，同时禁止「解析到国内 IP 就认定是国内流量」。

DNS 设计受流量接管方式约束：

- **mixed / system-proxy 模式**下，sing-box 不接收应用的 DNS 请求。应用把域名交给代理（SOCKS5 远程解析或 HTTP CONNECT）时，走代理的域名由服务端解析；应用自行解析时用系统 DNS，Norain 无法拦截。
- **TUN / transparent 模式**下，sing-box 通过 `hijack-dns` 路由动作接收全部 DNS 请求，这时 split DNS 才有意义。

sing-box 1.12 重构了 DNS server 格式，旧格式在 1.14 已移除。1.14 又弃用了若干 DNS 规则字段（ADR 0002 第 5 条）。GeoIP 数据库在 1.12 移除，改由 rule-set 提供。

## 建议

**阶段 2（仅 mixed）**

- `dns.mode` 只允许 `local`。生成 `dns.servers = [{type:"local"}]`，只用于 sing-box 自身解析代理服务器域名和直连出站的域名。
- 走代理的流量不在本地解析，域名原样交给出站，由服务端解析。
- 原稿默认配置写的 `dns.mode = "split"` 在阶段 2 没有实现，因此默认值改为 `local`。
- 解析代理服务器地址的 `domain_resolver` 使用 `prefer_ipv4`。IPv6 的行为由 ADR 0010 的监控单独测量后再决定。

**TUN 阶段（待定，以下是草案）**

| 项 | 草案 |
|---|---|
| 接收方 | sing-box 通过 `hijack-dns` 接收所有 53 端口请求 |
| 本地 DNS | 系统 DNS 或用户指定的 UDP/DoH，用于 `direct_domains` 和直连 rule-set |
| 代理侧 DNS | 经代理出站的 DoH（例如 `https://1.1.1.1/dns-query`，`detour` 指向代理出站），用于 `proxy_domains` 和默认动作 |
| 备用 DNS | 代理侧 DNS 失败时不回落到本地 DNS（防泄漏），直接返回失败 |
| 缓存 | `cache_ttl_seconds` 作为缓存时间上限，不超过上游 TTL；用 1.14 的 `store_dns` 持久化 |
| IPv4/IPv6 | 按出站分别设置策略；IPv6 链路异常（业务码 606）时，代理侧解析可降级为 `ipv4_only`，但必须记录事件 |
| 失败默认动作 | 返回 SERVFAIL，不改走直连 |

**业务码 401 的含义**：只作为诊断信号，例如一个在 `proxy_domains` 中的域名被本地 DNS 解析，说明配置或劫持有漏洞。它不会作为分流依据。

## 需要用户确认

1. 阶段 2 的 DNS 只做 `local`，默认值从 `split` 改为 `local`。
2. TUN 草案中「代理侧 DNS 失败不回落本地」的防泄漏优先原则。

## 确认

（空）

## 修订

2026-11-18：**TUN 模式下增加 fake-ip（`dns.fake_ip`，默认关闭）**

起因：Claude Desktop 走 TUN 时，服务端收不到域名，`routing.warp` 的 `domain_suffix` 匹配不到，
流量落到 `final = direct`，出口是机房 IP，被 Cloudflare 挑战；改用 mixed 入站则正常。

根因是 sing-box 1.13 移除了 `sniff_override_destination`（`inbound.sniff` /
`sniff_override_destination` 也在 1.13.0 移除）。`route` 里的 `sniff` 动作只填充
`metadata.Domain` 供规则匹配，**不会**把转发的目标地址从 IP 换成域名，所以经混合入站
（应用自带域名）不受影响，TUN（只有 IP）就丢了域名。已用 sing-box 1.14.4 实测确认这两种
旧写法都会 FATAL。

上游给的替代方案是 fake-ip（[#2407](https://github.com/SagerNet/sing-box/issues/2407)）。
实现要点：

- fake-ip 的 DNS server 与 DNS 规则**只覆盖走代理的域名**（`proxy_domains` 与学到的代理名单）。
  直连域名和未知域名必须返回真 IP，否则应用拿到 `198.18.x.x` 既连不上、也破坏直连判定。
- DNS 规则里 fakeip 必须排在 `dns-direct` 之前，否则先被直连规则吃掉。
- `route.rules` 里为 fake-ip 段加一条 `{"ip_cidr": [...], "action": "sniff"}`，
  让它先嗅探、再按域名分流，避免被后面的 `ip_cidr` 规则当成普通 IP。
- 只在 `traffic_mode = "tun"` 时生效：mixed / system-proxy 本来就能把域名交给服务端。
- `fake_ip_range_v6` 默认空（不启用 IPv6 fake-ip）；需要时显式配置 `inet6_range`。

副作用（需要知情）：fake-ip 会改变应用看到的 IP，某些按 IP 判断的逻辑（例如把连接钉死在
某个 IP 上的客户端）可能受影响，所以**默认关闭**，按需开启。服务端侧的兜底见 ADR 0008 与
`routing.warp.ip_cidr`（纯 IP 场景不依赖 fake-ip 也能命中 WARP）。
