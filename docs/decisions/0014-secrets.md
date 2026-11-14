# 0014 秘密来源与脱敏

- 状态：提议（2026-11-14 起阶段 1 暂按本建议实现，用户未逐条确认，可随时修改）
- 日期：2026-11-14
- 关联：审计问题 8；原稿「配置契约」环境变量清单

## 背景

原稿要求密码优先来自权限受限的秘密文件或操作系统凭据存储，同时兼容环境变量。一个容易忽略的事实是：**sing-box 的 JSON 配置必须包含明文密码**，所以生成出来的运行配置本身也是秘密文件。

## 建议

**`credential_ref` 语法**：

| 形式 | 阶段 | 说明 |
|---|---|---|
| `file:/path/to/secret` | 1 | 读取第一行并去掉首尾空白。Linux 要求文件属主是运行用户、权限不宽于 0600；Windows 要求 ACL 只包含运行账户、SYSTEM 和 Administrators。不满足时拒绝启动 |
| `env:NORAIN_PASSWORD` | 1 | 兼容模式；`status` 中显示「来源：环境变量」 |
| `keyring:<服务>/<名称>` | 后续 | Windows 凭据管理器或 Linux Secret Service；服务端无头环境不适用 |

**生成的 JSON**：

- 写入 `<state_dir>/run/sing-box.json`，权限与秘密文件相同。
- 不放在用户配置目录里。
- 备份目录使用同样的权限。

**脱敏**：

- 日志写入层统一过滤：已知秘密值、私钥 PEM 块、`password`/`token`/`secret`/`key` 字段，以及带认证信息的 URL（`hy2://密码@…`、`trojan://密码@…`），都替换为 `***`。
- `sing-box check` 的错误输出先过滤再显示。
- `config show` 默认隐藏秘密，加 `--reveal` 也不显示秘密值，只显示来源和指纹（SHA-256 的前 8 位）。

**环境变量**：原稿列出的 `NORAIN_*` 变量，优先级定义为「命令行参数 > 环境变量 > TOML > 默认值」。`status --json` 输出每个生效值的来源，但不输出秘密的值。

**生成密码**：`norain-server secret generate` 用 `secrets.token_urlsafe(24)` 写入秘密文件。

## 需要用户确认

1. 首个版本只支持 `file:` 和 `env:`。
2. 环境变量优先级高于 TOML。

## 确认

（空）

## 修订

2026-11-14，用户：**以最初目标（docs/reference/original-goals.md）为准，除非有硬性 bug。**

最初目标写的是「密码必须从配置或环境变量读取」。因此除了 `credential_ref`，`server.toml` 也接受直接写 `[auth] password = "…"`。直接写密码时，要求 `server.toml` 的权限不宽于 0600，否则拒绝启动。
