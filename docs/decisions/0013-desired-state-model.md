# 0013 期望状态：自启动、自动恢复与手动停止

- 状态：提议（2026-11-14 起阶段 1 暂按本建议实现，用户未逐条确认，可随时修改）
- 日期：2026-11-14
- 关联：原稿「守护模块」「自维持模块」「启动模块」；ADR 0012

## 背景

原稿要求手动 `stop` 写入期望状态 `stopped`，监督器和服务管理器都必须尊重它。自启动、自动恢复和手动停止之间的关系需要定义清楚。

## 建议

三个相互独立的状态：

| 状态 | 取值 | 存放位置 | 修改者 |
|---|---|---|---|
| `desired` | `running` / `stopped` | `<state_dir>/desired-state.json` | 只有用户命令 `start` / `stop` |
| `autostart` | `enabled` / `disabled` | 服务管理器（服务端为 systemd enable，客户端为用户级自启动项） | 只有 `install` 和 `autostart enable/disable` |
| `actual` | `running` / `starting` / `stopped` / `failed` | 从服务管理器和进程查询，不持久化 | 运行时 |

规则：

1. `stop`：先写 `desired=stopped`，再请求服务管理器停止。systemd 的 `Restart=on-failure` 在正常停止后不会重启。
2. `start`：先写 `desired=running`，再请求服务管理器启动。如果单元处于 failed 状态，先执行 `reset-failed`。
3. **开机时**：`autostart=enabled` 只会让服务管理器尝试启动。systemd 的 `ExecCondition=` 检查 `desired`：如果是 `stopped`，单元被跳过，不算失败。所以「手动停止」在重启后仍然有效，直到用户再次执行 `start`。
4. **自动恢复**只发生在 `desired=running` 并且进程异常退出时。重启次数达到上限后，`actual=failed`，`desired` 保持 `running` 不变。这样 `status` 能区分「用户停止」和「失败停止」。
5. **修复和更新**期间持有操作锁 `<state_dir>/op.lock`，锁里记录操作 ID 和超时时间。持锁期间 `ExecCondition` 视为不满足，避免和服务管理器的自动启动竞争。锁超时后视为失效，由下一个操作接管并记录事件。
6. **客户端**没有系统服务。Python 监督器自己拥有重启权（`restart_limit` 和 `backoff_seconds`），并遵守同样的 `desired` 规则。

服务端只在 Linux 上运行（ADR 0001），规则 3 依赖 systemd。客户端在 Windows 上没有系统服务，开机自启动的机制（例如登录时运行的计划任务）延后设计。设计时同样要在启动时检查 `desired`：如果是 `stopped`，就直接以成功状态退出。

## 需要用户确认

1. 手动停止在重启后仍然有效。
2. 「失败」不会把 `desired` 改为 `stopped`。

## 确认

（空）

## 修订

2026-11-14，用户：**以最初目标（docs/reference/original-goals.md）为准，除非有硬性 bug。**

- 服务端：规则不变，但自动恢复由 Python 守护执行（ADR 0012 修订）。
- 客户端：自维持模块按最初目标实现，包括与代理/分流模块互相拉起的保活。手动停止必须先写 `desired=stopped`，所有保活方在拉起前检查它，否则会出现停不掉的硬性问题。
