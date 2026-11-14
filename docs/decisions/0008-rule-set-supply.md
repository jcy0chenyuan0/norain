# 0008 rule-set 来源、校验、缓存与回滚

- 状态：提议
- 日期：2026-11-14
- 关联：审计问题 9；ADR 0007

## 背景

sing-box 的 remote rule-set 可以按 `update_interval` 自动下载，但不支持哈希校验。另外，1.14 弃用了 `download_detour`，改为使用 `http_client`。原稿要求记录来源、版本、哈希、更新时间和失效行为。

## 建议

1. **sing-box 只使用 `type: "local"` 的 rule-set**，由 Norain 负责下载和更新。这样所有网络获取都经过 Norain 的校验和审计。
2. **来源**：SagerNet 官方的 `sing-geosite` / `sing-geoip` 仓库发布的 `.srs` 二进制规则文件，用固定 commit 的 URL 下载，不用分支 URL。
3. **锁定**：`third_party/rules.lock.toml` 记录每个规则的名称、URL（含 commit）、SHA-256 和记录日期。
4. **更新**：`norain rules update [--dry-run]` 下载到临时目录 → 校验哈希 → 运行 `sing-box rule-set` 子命令或 `sing-box check` 做格式检查 → 原子替换，并保留上一版本。
5. **失效行为**：
   - 新版本校验失败时，保留当前版本并报告错误。
   - 本地没有任何可用版本时，引用该 rule-set 的规则被移除，流量落到默认动作，同时报业务码 400。不会静默直连。
6. **缓存目录**：`<state_dir>/rules/<名称>/<sha256>.srs`，`current` 指向在用版本。
7. **回滚**：`norain rules rollback <名称>`。

## 待验证

- 上游规则仓库当前的目录结构和 commit 粒度。
- `sing-box rule-set` 子命令在 1.14 中有哪些校验能力。

## 需要用户确认

1. 规则由 Norain 管理更新，不使用 sing-box 自动更新。
2. 规则更新是否需要定时任务，还是只手动执行？

## 确认

（空）
