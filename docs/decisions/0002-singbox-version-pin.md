# 0002 sing-box 版本锁定与二进制校验

- 状态：提议（2026-11-14 起阶段 1 暂按本建议实现，用户未逐条确认，可随时修改）
- 日期：2026-11-14
- 关联：审计问题 3；`third_party/singbox.lock.toml`

## 背景

截至 2026-11-14，sing-box 最新稳定版为 1.14.4（2026-10-24 发布），同期上游在发 1.15.0 alpha。1.14.0 是一次大版本更新，移除了此前弃用的功能；1.14 自身又弃用了一批功能，计划在 1.16.0 移除，其中包括 TLS 内联 `acme`。

上游不发布独立的 checksum 或签名文件。发布页在每个资产旁显示 SHA-256 摘要，并附一个 GitHub release attestation。

## 建议

1. 锁定 **sing-box 1.14.4**，只用稳定版，不跟 alpha/beta/rc，也不跟 `latest`。
2. 二进制只从 GitHub Releases 的固定 tag 下载，文件名和 SHA-256 写在 `third_party/singbox.lock.toml`。
3. 安装器校验顺序：
   1. 比对锁定文件里的 SHA-256；
   2. 如果系统里有 `gh`，额外执行 `gh attestation verify <文件> --repo SagerNet/sing-box`，失败即拒绝；没有 `gh` 时记录「attestation 未检查」；
   3. 解压后运行 `sing-box version`，核对版本号等于锁定版本，构建标签包含 `with_quic`；ACME 模式还要包含 `with_acme`。
4. Linux 首选不带后缀的通用包（`linux-<arch>.tar.gz`）。
5. 生成的 JSON 不得使用 1.14 已弃用、1.16 将移除的字段，避免以后升级时被迫改写配置。具体有：TLS 内联 `acme`、remote rule-set 的 `download_detour`、DNS 规则的 legacy `strategy`、`independent_cache`、`store_rdrc`。
6. 升级流程：新建 ADR 取代本记录 → 更新锁定文件 → 更新映射测试夹具 → 用新版本跑 `sing-box check` 回归。补丁版本（1.14.x）只需更新本记录。

## 后果

- Norain 的 TOML Schema 绑定 sing-box 1.14 的 JSON Schema，见 ADR 0004。
- 锁定文件里的摘要是 2026-11-14 从发布页转录的，`hashes_verified = false`。阶段 1 第一次真实下载时必须复核；复核前安装器拒绝安装。

## 待验证

- 通用包、`-glibc`、`-musl` 三种变体的区别。推测通用包是静态链接，带后缀的变体包含需要 cgo 的组件（例如 1.13 加入的 NaiveProxy 出站），但这一点尚未核实。
- 官方 Release 构建默认包含哪些构建标签，尤其是 `with_acme`。
- `sing-box version` 的输出格式，以便解析。

## 需要用户确认

1. 接受 1.14.4 作为锁定版本。
2. 是否允许依赖 `gh` 做 attestation 校验，还是只用 SHA-256？

## 确认

（空）
