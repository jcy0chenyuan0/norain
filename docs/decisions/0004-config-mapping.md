# 0004 TOML 到 sing-box JSON 的映射与 Schema 绑定

- 状态：提议（2026-11-14 起阶段 1 暂按本建议实现，用户未逐条确认，可随时修改）
- 日期：2026-11-14
- 关联：审计问题 4；ADR 0002、0014、0015

## 背景

sing-box 原生配置是 JSON。Norain 的 `server.toml` 和 `cfg.toml` 只是输入格式，生成器负责把它们转换成 sing-box 1.14 接受的 JSON。字段名依据 sing-box 官方配置文档（1.14 版）。

## 通用规则

1. **Schema 版本**：两个 TOML 文件顶层都加 `schema = 1`。缺失时按 1 处理并给出警告；版本更高时拒绝加载。迁移由 `norain_core.migrate` 按版本逐级执行，迁移前备份原文件。
2. **未知字段**：一律拒绝，错误中带完整字段路径（例如 `protocols.trojan.fallbak`），并在可能时给出相近字段名的建议。
3. **生成元数据**：sing-box 拒绝未知字段，所以元数据不写进 JSON，而是写到旁边的 `sing-box.json.meta.json`，内容包括生成器版本、sing-box 锁定版本、Norain Schema 版本、输入文件的 SHA-256 和生成时间。
4. **幂等**：同一输入必须生成字节级相同的 JSON（键排序固定，不写时间戳），这样才能用哈希判断配置是否变化。
5. **秘密**：生成的 JSON 中含明文密码（sing-box 要求），见 ADR 0014 的文件权限和脱敏规则。
6. **只用非弃用字段**：见 ADR 0002 第 5 条。

## 服务端映射（server.toml → sing-box.json）

| server.toml | sing-box JSON | 说明 |
|---|---|---|
| `server.listen` | 每个 inbound 的 `listen` | 原稿默认 `0.0.0.0` 只监听 IPv4。建议默认改为 `::`，同时测试双栈行为 |
| `protocols.hysteria2.port` | `inbounds[type=hysteria2].listen_port` | UDP |
| `protocols.trojan.port` | `inbounds[type=trojan].listen_port` | TCP |
| `auth.credential_ref` | 两个 inbound 的 `users[0].password` | `users[0].name` 固定为 `norain`；单用户抽象 |
| `server.domain` | `tls.server_name` | 两个 inbound 都写 |
| `tls.mode = "manual"` | `tls.certificate_path`、`tls.key_path` | sing-box 会在文件修改后自动重载 |
| `tls.mode = "self-signed"` | 同上，路径指向 Norain 生成的文件 | 见 ADR 0015 |
| `tls.mode = "acme"` | 顶层 `certificate_providers[{type:"acme", tag:"norain-acme", domain:[…], data_directory, email}]`，inbound 中写 `tls.certificate_provider = "norain-acme"` | 不使用已弃用的内联 `tls.acme` |
| `protocols.trojan.fallback` | `inbounds[type=trojan].fallback = {server, server_port}` | 原稿类型是字符串，建议改为 `{ host = "127.0.0.1", port = 8080 }`；为空时不写该字段，sing-box 关闭 fallback |
| —— | `outbounds = [{type:"direct", tag:"direct"}]` | 显式声明 |
| —— | `route = {final:"direct"}` | 服务端不做分流 |
| `logging.*` | `log = {level, timestamp:true}` | sing-box 日志输出到标准输出，由 Python 或 journald 收集和轮转，不让 sing-box 自己写文件 |

Hysteria2 inbound 的 `tls` 是必填项；未设置 `masquerade` 时，认证失败返回 404。`up_mbps`/`down_mbps`、`obfs`、`masquerade`、`realm` 在首个版本里不暴露。

生成示例（manual 证书，两个协议都启用）：

```json
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [
    {
      "type": "hysteria2", "tag": "hy2-in",
      "listen": "::", "listen_port": 443,
      "users": [{"name": "norain", "password": "<秘密>"}],
      "tls": {"enabled": true, "server_name": "example.com", "alpn": ["h3"],
              "certificate_path": "/etc/norain-server/tls/fullchain.pem",
              "key_path": "/etc/norain-server/tls/privkey.pem"}
    },
    {
      "type": "trojan", "tag": "trojan-in",
      "listen": "::", "listen_port": 443,
      "users": [{"name": "norain", "password": "<秘密>"}],
      "tls": {"enabled": true, "server_name": "example.com",
              "certificate_path": "/etc/norain-server/tls/fullchain.pem",
              "key_path": "/etc/norain-server/tls/privkey.pem"}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
```

## 客户端映射（cfg.toml → sing-box.json，阶段 2 范围）

| cfg.toml | sing-box JSON | 说明 |
|---|---|---|
| `[local] listen`、`port`（原稿缺失，需新增） | `inbounds = [{type:"mixed", tag:"mixed-in", listen:"127.0.0.1", listen_port:…}]` | 默认只监听回环地址 |
| `proxy.server` | outbound `server` | |
| `proxy.port`（原稿只有一个） | outbound `server_port` | 建议拆成 `proxy.hysteria2.port` 和 `proxy.trojan.port` |
| `proxy.credential_ref` | outbound `password` | |
| `[proxy.tls]`（原稿缺失，需新增） | outbound `tls = {enabled:true, server_name, certificate_path?}` | 自签证书时通过 `certificate_path` 信任指定证书；不提供 `insecure = true` 的默认值 |
| `proxy.protocol = hysteria2 / trojan` | 单个 outbound，`route.final` 指向它 | |
| `proxy.protocol = auto` | 暂不映射，校验器拒绝 | 见 ADR 0009 |
| `dns.mode = local` | `dns.servers = [{type:"local", tag:"local"}]`，`route.default_domain_resolver = "local"` | 1.12 起 DNS server 必须使用新格式，旧格式已在 1.14 移除 |

## 待验证（阶段 1 用真实 `sing-box check` 确认）

- Trojan 未配置 fallback 时，认证失败的连接是直接关闭还是有其他行为。
- 同一主机上 `443/udp`（Hysteria2）和 `443/tcp`（Trojan）同时监听。
- `listen = "::"` 在 Linux 上是否同时接受 IPv4（取决于 `net.ipv6.bindv6only`）；Windows 上的行为也要测。
- Hysteria2 inbound 的 `alpn` 是否需要显式写 `h3`，还是有默认值。

## 需要用户确认

1. 未知字段一律拒绝（不做「警告后忽略」）。
2. 服务端默认 `listen = "::"`。
3. `trojan.fallback` 改为表结构。
4. 客户端 `cfg.toml` 新增 `[local]`、`[proxy.tls]`，并把端口拆分到各协议。

## 确认

（空）
