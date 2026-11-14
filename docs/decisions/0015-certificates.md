# 0015 证书模式与 ACME

- 状态：已接受（2026-11-14，见「确认」）
- 日期：2026-11-14
- 关联：原稿「证书模块」；ADR 0004、0002

## 背景

原稿支持三种证书模式：`acme`、`manual`、`self-signed`。sing-box 1.14 新增了顶层 `certificate_providers`（类型包括 `acme`、`tailscale`、`cloudflare-origin-ca`），同时弃用 TLS 内联 `acme`（1.16 移除）。ACME 证书提供者需要 `with_acme` 构建标签。

## 建议

**manual（阶段 1 首选）**：读取 `tls.certificate` 和 `tls.private_key` 路径。生成配置前检查：

- 文件存在且可读；
- 私钥文件权限符合 ADR 0014；
- 证书与私钥匹配；
- SAN 包含 `server.domain`；
- 证书在有效期内：剩余不足 14 天时警告，已过期时以业务码 120 拒绝。

**self-signed（阶段 1）**：

- 必须显式执行 `norain-server cert self-signed --domain <域名>`。
- 用 Python `cryptography` 库生成 ECDSA P-256 证书，有效期 365 天，不依赖 `openssl` 命令。
- 输出证书的 SHA-256 指纹，客户端用 `[proxy.tls] certificate_path` 信任这张证书（ADR 0004）。
- `status` 标注「自签证书，仅限自用」。

**acme（阶段 1 之后）**：

- 生成顶层 `certificate_providers`，不使用内联写法。
- 运行前检查二进制带有 `with_acme` 构建标签，并且 `server.domain` 非空，否则拒绝执行。
- **挑战方式是一个关键约束**：
  - Hysteria2 只监听 UDP，无法完成 TLS-ALPN-01 挑战。
  - TLS-ALPN-01 需要 TCP 443 上的 TLS 监听，只有同时启用 Trojan 时才具备。
  - HTTP-01 需要 TCP 80 端口可访问，因此防火墙模块需要额外放行 `80/tcp`，这超出了原稿「只放行协议端口」的范围。
  - DNS-01 需要 DNS 服务商的 API 凭据。
- ACME 数据目录设为 `<state_dir>/acme`。

**reload**：证书文件更新后，sing-box 会对 `certificate_path` 和 `key_path` 自动重载。`norain-server reload` 先运行 `cert check`，再触发重载。

## 挑战方式推荐

| 方式 | 需要什么 | 适合 |
|---|---|---|
| **HTTP-01（推荐默认）** | 域名 A/AAAA 记录指向服务器；`80/tcp` 能从公网访问 | 最常见的单台 VPS，不需要额外凭据；只启用 Hysteria2 也能用 |
| TLS-ALPN-01 | Trojan 在 `443/tcp` 上运行 | 启用 Trojan 且不想开 80 端口 |
| DNS-01 | DNS 服务商的 API 令牌（又一个要保管的秘密） | 80 端口被封、需要通配符证书、服务器在 NAT 后面 |

推荐方案：

- 默认使用 HTTP-01。
- Trojan 监听 `443/tcp` 时允许同时使用 TLS-ALPN-01，两种方式互为备份。
- DNS-01 作为高级选项，在 HTTP-01 之后再实现。

这样设计的后果：

- ACME 模式下，防火墙模块需要额外管理一条 `80/tcp` 规则，规则名单独标注「ACME」。关闭 ACME 时移除这条规则。
- `cert check` 要检查 80 端口是否被其他程序（例如 nginx）占用，被占用时给出明确错误，并建议改用 TLS-ALPN-01 或 DNS-01。
- 在 v0.1 中，有域名的用户先用 manual 模式（例如自己用 certbot 签发证书），没有域名的用户用 self-signed。ACME 在 v0.1 之后的第一个里程碑实现（ADR 0016）。

## 需要用户确认

1. 阶段 1 只做 manual 和 self-signed。
2. ACME 默认 HTTP-01，Trojan 启用时可用 TLS-ALPN-01，DNS-01 后续再做。

## 确认

- 2026-11-14，用户：ACME 使用 HTTP-01。v0.1 只做 manual 和 self-signed，ACME 在 v0.2 实现。

## 修订

2026-11-14，用户：**以最初目标（docs/reference/original-goals.md）为准，除非有硬性 bug。**

自签证书按最初目标用 `openssl` 命令生成；系统里没有 `openssl` 时退回到 Python `cryptography` 库。ACME 仍然是 sing-box 内置功能，只是 1.14 把写法从 TLS 内联改成了 `certificate_providers`，这属于硬性变化，保持不变。
