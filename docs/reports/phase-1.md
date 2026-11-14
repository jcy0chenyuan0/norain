# 阶段 1 交付报告：服务端最小垂直切片

- 日期：2026-11-14
- 状态：**代码完成，只经过模拟验证。阶段 1 的验收条件尚未满足**（缺少真实 sing-box 和真实 systemd 的验证），按规则保持在阶段 1。

## 输入

- 《Norain 开发代理提示词》与最初目标（`docs/reference/`）
- 用户指示：以最初目标为准，除非有硬性 bug；先写理论代码；服务端暂不支持 Windows；v0.1 范围采纳

## 已确认约束

- 服务端只支持 Linux（ADR 0001）
- 证书 v0.1 只做 manual 和 self-signed；ACME 用 HTTP-01，在 v0.2 实现（ADR 0015）
- Python 守护负责重启 sing-box，systemd 做外层保活（ADR 0012 修订）
- 防火墙在 v0.1 只输出命令，不修改系统（ADR 0016）

## 修改文件

| 文件 | 说明 |
|---|---|
| `src/norain_core/errors.py` | 退出码、业务码、统一异常 |
| `src/norain_core/redact.py` | 脱敏 |
| `src/norain_core/secrets.py` | `file:` / `env:` 秘密引用、权限检查、密码生成 |
| `src/norain_core/atomic.py` | 原子写入、备份轮换 |
| `src/norain_core/log.py` | JSON Lines 日志、按大小轮转 |
| `src/norain_core/state.py` | 期望状态、操作锁 |
| `src/norain_core/singbox.py` | 二进制定位、版本和构建标签检查、`check` 包装 |
| `src/norain_server/paths.py` | 路径和环境变量 |
| `src/norain_server/model.py` | `server.toml` 模型、字段级错误、环境变量覆盖 |
| `src/norain_server/generate.py` | JSON 生成、生成→check→备份→替换 |
| `src/norain_server/cert.py` | 证书检查、自签证书 |
| `src/norain_server/runner.py` | 守护：预检、健康检查、重启上限 |
| `src/norain_server/service.py` | systemd 后端和后台进程后端 |
| `src/norain_server/cli.py` | 命令行 |
| `deploy/norain-server.service` | systemd 单元示例 |
| `examples/server.toml` | 配置示例 |
| `tests/` | 29 个测试和模拟 sing-box（`tests/fakes/sing-box`） |
| `docs/decisions/` | 按用户答复和「以最初目标为准」修订 |

## 可用命令

```text
norain-server config validate | show
norain-server cert check | self-signed --domain <域名>
norain-server secret generate
norain-server start | stop | restart | status | run
norain-server log [-f] [-n N]
norain-server firewall open | close | status     （只输出命令，不改系统）
```

每个命令都支持 `--json`。`status` 按最初目标始终输出 JSON。

尚未实现（见 `docs/pending.md`）：`install`、`update`、`uninstall`、`reload`、`config edit`、`fix`、ACME、防火墙真实操作。

## 测试结果

```text
$ python3 -m pytest -q
29 passed
```

覆盖内容：字段级错误（未知字段、端口越界、缺协议、缺证书路径、秘密缺失、TOML 语法）、环境变量覆盖、JSON 结构和 `users[]` 映射、生成幂等、校验失败不覆盖当前配置、备份、证书（匹配、SAN、过期、缺失）、脱敏、日志轮转、操作锁、版本锁定，以及用模拟 sing-box 走通的 start / status / stop、崩溃后自动重启、重启上限（业务码 160）、端口未监听、fatal 日志、端口占用（130）、缺少二进制（150）、无效配置下 restart 不影响运行中的服务、手动停止后不被拉起。

## 已验证平台

- **无真实验证。** 全部测试在 Ubuntu 24.04 x86_64、Python 3.13.18 上，使用**模拟的 sing-box** 运行。

## 未验证项目

这些都需要真实的 sing-box 1.14.4 才能确认，任何一项都可能要求改代码：

1. 生成的 JSON 能否通过真实的 `sing-box check`。字段来自官方文档，重点怀疑：Hysteria2 的 `alpn: ["h3"]` 是否需要显式写、`listen` 写 `::` 时的双栈行为。
2. `sing-box version` 的输出格式。现在的解析规则（`sing-box version X` 和 `Tags: …` 行）是推定的。
3. sing-box 的 fatal 日志格式。现在匹配 `FATAL` 和 `panic:`。
4. Trojan 不配置 fallback 时对认证失败连接的处理。
5. `443/udp` 和 `443/tcp` 同时监听。测试里用的是两个不同的高位端口。
6. `deploy/norain-server.service`：没有在真实 systemd 上安装过。`ExecCondition`、`RestartPreventExitStatus`、以非 root 用户绑定 443 都未验证。systemd 后端只用模拟的 `systemctl` 测过。
7. `third_party/singbox.lock.toml` 中的 SHA-256 还没有对真实文件复核。
8. 真实客户端能否连上（协议层面的端到端连通）。

## 与阶段 1 完成条件的对照

| 条件 | 状态 |
|---|---|
| 有效配置能生成并通过目标版本的 `sing-box check` | **未满足**（只通过了模拟 check） |
| 各类错误给出字段级错误 | 满足（「不支持字段」由未知字段拒绝覆盖） |
| 校验失败不覆盖上一份可用配置 | 满足 |
| `start`、`stop`、`status` 至少在一个目标平台真实验证 | **未满足** |
| 手动停止后没有其他组件自动重启进程 | 模拟环境下满足；systemd 下未验证 |

## 验收命令

模拟验证（现在就能运行）：

```bash
cd norain && python3 -m pytest -q
```

真实验证（需要一台 Ubuntu 24.04、root 权限，并已把 sing-box 1.14.4 装到 `/usr/local/bin/sing-box`）：

```bash
pip install .                       # 或 pipx install .
install -d -m 0750 /etc/norain-server /var/lib/norain-server /var/log/norain-server
cp examples/server.toml /etc/norain-server/server.toml && chmod 600 /etc/norain-server/server.toml
norain-server secret generate
norain-server cert self-signed --domain <你的域名或 IP>
# 编辑 server.toml：domain 改成上面的值；[tls] mode = "self-signed"，删除 certificate / private_key 两行
norain-server config validate       # 关键：真实的 sing-box check
norain-server start
norain-server status
ss -lnptu | grep sing-box
norain-server stop && sleep 40 && norain-server status   # 应保持 stopped
```

## 回滚方式

- 代码：本阶段只新增文件，并修改了 `pyproject.toml`。删除 `src/norain_core/*.py`（保留 `__init__.py`）、`src/norain_server/*.py`（保留 `__init__.py`）、`deploy/`、`examples/` 和新增的测试即可回到阶段 0。
- 运行环境：`norain-server stop`，然后删除 `/etc/norain-server`、`/var/lib/norain-server`、`/var/log/norain-server`，再 `pip uninstall norain`。v0.1 不修改防火墙、不注册服务、不写环境变量。
