# 0001 平台与 CPU 架构支持矩阵

- 状态：已接受（2026-11-14，见「确认」）
- 日期：2026-11-14
- 关联：审计问题 2；ADR 0002

## 背景

原稿只写了 Windows 和 Linux，没有版本和架构。sing-box 1.14.4 的发布资产包含 Linux amd64/arm64（通用、glibc、musl 三种变体）、Windows amd64/arm64，以及单独的 `windows-amd64-legacy-windows-7` 包。存在单独的 Windows 7 包，说明常规 Windows 包已不支持 Windows 7。

## 建议

| 平台 | 版本 | 架构 | 级别 |
|---|---|---|---|
| Ubuntu | 22.04、24.04 LTS | amd64、arm64 | 一级：CI 测试，至少一个版本真实验证 |
| Debian | 12、13 | amd64、arm64 | 二级：CI 测试，真实验证可选 |
| RHEL 系（Rocky/Alma） | 9 | amd64 | 二级 |
| Windows | 10 22H2、11 | amd64 | 一级（**仅客户端**） |
| Windows | 10/11 | arm64 | 三级（仅客户端）：只打包，不承诺验证 |

**服务端暂不支持 Windows**（用户确认）。`norain-server` 只面向上表中的 Linux 平台。

- 一级：每个阶段必须有真实验证记录。
- 二级：有自动化测试和适配器测试，真实验证缺失时在报告中标为「未验证」。
- 三级：只保证能下载到正确的二进制。
- 不支持：Windows 7/8.x、32 位系统、OpenWrt、macOS、Android。

Linux 服务端要求 systemd ≥ 243，因为 ADR 0013 使用 `ExecCondition=`。

## 后果

- 阶段 1 的真实验证平台选 Ubuntu 24.04 amd64。当前工作区正是这个平台（systemd 255），但不能下载 sing-box，见阶段 0 报告。
- 阶段 1 不再需要 Windows 服务适配器。原稿「服务端 Windows 部署」一节整体延后，见 docs/pending.md。
- 客户端代码仍须跨平台，路径、进程和权限都通过适配器处理。

## 待验证

- sing-box 1.14.x 常规 Windows 包实际支持的最低 Windows 版本。

## 需要用户确认

1. ~~服务端是否需要 Windows~~ → 已确认：暂不需要。
2. 客户端 Windows arm64：未答复，按三级处理。

## 确认

- 2026-11-14，用户：服务端暂时不需要支持 Windows。其余按建议执行。
