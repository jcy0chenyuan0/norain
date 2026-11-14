# 0003 Python 版本、构建方式与 CLI 约定

- 状态：提议（2026-11-14 起阶段 1 暂按本建议实现，用户未逐条确认，可随时修改）
- 日期：2026-11-14
- 关联：审计问题 1

## 背景

仓库从零开始，没有既有入口。原稿要求两个命令 `norain`、`norain-server`，必须有稳定退出码、JSON 输出和超时控制。

## 建议

**Python 版本**：最低 3.11（需要标准库 `tomllib`），开发和 CI 用 3.13。

**构建**：`pyproject.toml` + setuptools，`src/` 布局，一个发行包包含三个导入包：

| 包 | 职责 |
|---|---|
| `norain_core` | 共享：配置加载、秘密引用、sing-box 定位与版本检查、原子写入、日志、退出码、进程控制 |
| `norain_server` | 服务端 CLI、server.toml 模型、服务端 JSON 生成、证书、守护适配器 |
| `norain` | 客户端 CLI、cfg.toml 模型、客户端 JSON 生成 |

分发方式：阶段 1/2 用 wheel + `pipx install`。Windows 是否打包成内嵌 Python 或单文件可执行程序，延后决定。

**运行依赖（候选）**：

| 依赖 | 用途 | 不用它的代价 |
|---|---|---|
| `pydantic>=2` | 配置模型、字段级错误路径 | 需要手写校验和错误路径 |
| `cryptography` | 自签证书、证书与私钥匹配、SAN 和有效期检查 | 依赖外部 `openssl` 命令并解析其输出 |
| `psutil` | 进程和端口监听检查，跨平台 | 需要分别实现 `/proc` 与 Windows API |

CLI 用标准库 `argparse`，不引入 click/typer，以减少依赖。

**CLI 进程退出码**（与业务码分开）：

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 未分类的运行失败 |
| 2 | 命令行用法错误 |
| 3 | 配置无效（字段级错误见输出） |
| 4 | 权限不足 |
| 5 | 依赖缺失（sing-box 二进制、构建标签不符） |
| 6 | 超时 |
| 7 | 状态冲突（操作锁被占用、期望状态不允许） |
| 8 | 外部组件失败（`sing-box check` 失败、服务管理器报错） |

带 `--json` 时，标准输出只输出一个 JSON 对象，日志一律写到标准错误。JSON 至少包含 `ok`、`exit_code`、`business_code`、`error_id`、`module`、`retryable`、`detail`、`hint`。

## 待验证

- 目标 Linux 发行版自带的 Python 版本是否满足 3.11。Ubuntu 22.04 自带 3.10，不满足；Debian 12 自带 3.11。如果 Ubuntu 22.04 是一级平台，需要 pipx 配合 deadsnakes PPA 或 uv 管理的 Python。

## 需要用户确认

1. 接受 pydantic、cryptography、psutil 三个运行依赖。
2. 如果 Ubuntu 22.04 必须支持，最低 Python 版本是否降到 3.10（需要额外依赖 `tomli`）？

## 确认

（空）
