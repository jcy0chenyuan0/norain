# Norain 架构审计（阶段 0）

> 本报告是阶段 0 的快照。之后用户指示「以最初目标为准，除非有硬性 bug」，与本报告冲突的地方以 `docs/decisions/` 各记录的「修订」一节为准，例如守护的重启职责、阻断的触发方式和分流流程。

- 日期：2026-11-14
- 输入：《Norain 开发代理提示词》（以下称「原稿」）
- 结论：仓库从零开始，没有可审计的既有代码。本报告回答原稿的十个审计问题，列出原稿中的矛盾和缺口，并给出建议的 Schema 修订。所有决策都处于「提议」状态，等待确认，见 [decisions/](decisions/README.md)。

## 1. 审计环境

| 项 | 值 |
|---|---|
| 主机 | 云端工作区 Ubuntu 24.04.5 LTS，x86_64 |
| Python | 3.13.18 |
| systemd | 255 |
| 已有的 Python 包 | pydantic 2.13.5、cryptography 50.0.1、psutil 7.2.2、pytest 9.1.1、setuptools 84.0.0 |
| sing-box | **未安装**。工作区禁止下载，阶段 0 也不允许安装 |
| Windows 环境 | 无 |

sing-box 的版本、字段和弃用信息来自官方文档与 GitHub 发布页，没有经过真实的 `sing-box check` 验证。凡是标为「待验证」的条目，都必须在阶段 1 用真实二进制确认。

## 2. 十个审计问题

| # | 问题 | 结论 | ADR |
|---|---|---|---|
| 1 | 仓库根目录、Python 版本、构建方式、CLI 入口 | 新仓库 `norain/`，`src/` 布局，三个包 `norain_core`、`norain`、`norain_server`。Python ≥ 3.11，构建用 setuptools，CLI 用 argparse。阶段 0 不注册 CLI 入口 | 0003 |
| 2 | 支持的系统版本和 CPU 架构 | 服务端只支持 Linux，一级平台为 Ubuntu 22.04/24.04（amd64、arm64）。客户端还支持 Windows 10 22H2/11（amd64）。**已接受** | 0001 |
| 3 | sing-box 版本、来源、校验 | 锁定 1.14.4 稳定版，从 GitHub Releases 的固定 tag 下载。校验 SHA-256（锁定文件），可选 attestation，最后用 `sing-box version` 核对版本和构建标签 | 0002 |
| 4 | TOML 到 JSON Schema 的映射 | 见 ADR 0004 的字段映射表。ACME 使用 1.14 的 `certificate_providers`，DNS server 使用 1.12 起的新格式 | 0004 |
| 5 | 客户端流量接管方式 | 阶段 2 只做 mixed。「全局流量」= TUN（**已接受**），作为后续独立里程碑 | 0005 |
| 6 | DNS 由谁接收、IPv4/IPv6 | mixed 模式下 sing-box 不接收应用的 DNS 请求，只用 `local` 解析自身需要的域名；走代理的域名由服务端解析。split DNS 和防泄漏要等 TUN | 0006 |
| 7 | 服务端最终重启权 | 属于 systemd（服务端只支持 Linux）。Python 的 `run` 只做预检和健康检查，发现故障后退出，不自行重启 | 0012、0013 |
| 8 | 秘密来源 | 秘密文件（`file:`）优先，兼容环境变量（`env:`），凭据存储延后。生成的 sing-box JSON 含明文密码，按秘密文件对待 | 0014 |
| 9 | 分流规则来源 | 由 Norain 下载 SagerNet 官方 `.srs` 规则，锁定 commit 和 SHA-256；sing-box 只读本地文件 | 0008 |
| 10 | 首个可用版本范围 | v0.1 = 服务端最小切片 + 客户端 mixed 最小切片，其余延后 | 0016 |

## 3. 建议的模块布局

```text
src/norain_core/
  config/        TOML 加载、schema 版本、迁移、字段级错误
  secrets.py     credential_ref 解析、权限检查、脱敏过滤器
  singbox/       二进制定位、版本与构建标签检查、check 包装、进程控制
  atomic.py      临时写入、fsync、原子替换、备份轮换
  state.py       desired-state、操作锁、操作 ID
  logging.py     结构化日志（JSON Lines），统一脱敏
  exitcodes.py   CLI 退出码与业务码
src/norain_server/
  model.py  generate.py  cert.py  service/{systemd,windows,null}.py  firewall/  cli.py
src/norain/
  model.py  generate.py  supervisor.py  cli.py
```

平台相关的操作（服务管理、防火墙、文件权限）都通过适配器接口实现，每个适配器配一个模拟后端用于测试。

## 4. 原稿中的矛盾与缺口

下表按影响程度排序。每一项都对应一个 ADR 或待定项。

| # | 位置 | 问题 | 建议 |
|---|---|---|---|
| G1 | `cfg.toml` 默认值 | `protocol = "auto"`、`dns.mode = "split"` 在阶段 2 都没有实现，违反原稿自己的「没有对应实现的模式不能出现在默认配置中」 | 默认值改为 `hysteria2` 和 `local`（ADR 0006、0009） |
| G2 | `cfg.toml` | 只有一个 `port`，但两个协议可能使用不同端口，`auto` 模式需要两个端口 | 拆分到 `[proxy.hysteria2]` 和 `[proxy.trojan]`（ADR 0004） |
| G3 | `cfg.toml` | 没有 TLS 段：缺 `server_name`、自签证书的信任方式；也没有本地监听地址和端口 | 新增 `[proxy.tls]` 和 `[local]`（ADR 0004） |
| G4 | 证书模块 | TLS 内联 `acme` 在 sing-box 1.14 已弃用、1.16 移除 | 使用 `certificate_providers`（ADR 0015） |
| G5 | 证书模块与防火墙模块 | 只启用 Hysteria2（UDP）时无法完成 TLS-ALPN-01 挑战；HTTP-01 需要 80/tcp，超出防火墙模块「只放行协议端口」的范围 | 由用户选择挑战方式（ADR 0015） |
| G6 | 秘密 | 原稿要求秘密不落入日志，但没有提到生成的 JSON 本身含明文密码 | 运行配置按秘密文件处理（ADR 0014） |
| G7 | `server.toml` | `listen = "0.0.0.0"` 只监听 IPv4 | 默认改为 `::` 并测试（ADR 0004） |
| G8 | `server.toml` | `trojan.fallback` 是字符串，但 sing-box 需要 `{server, server_port}` | 改为表结构（ADR 0004） |
| G9 | 守护模块 | 「最大连续重启次数 3」没有时间窗口 | 600 秒内 3 次（ADR 0012） |
| G10 | 守护模块 | 健康检查要看「最近的 fatal 日志」，但没有定义日志来源和匹配方式 | 由 `run` 包装进程收集 sing-box 标准输出，匹配 `FATAL`/`panic`（ADR 0012） |
| G11 | 环境变量 | 列出了 `NORAIN_*` 变量，但没有定义它们与 TOML 的优先级 | 命令行 > 环境变量 > TOML > 默认值（ADR 0014） |
| G12 | 监控业务码 401 | 依赖「DNS 解析位置」，而 GeoIP 数据库在 sing-box 1.12 已移除；同时原稿禁止用解析结果决定分流 | 401 只作诊断信号（ADR 0006） |
| G13 | 名单 | 白/黑/蓝名单没有定义 | 已确认：白名单 = `proxy_domains`，黑名单 = `direct_domains`；蓝名单待确认（ADR 0007） |
| G14 | 「全局流量」 | 没有定义 | 已确认为 TUN（ADR 0005） |
| G15 | 客户端 `auto_start` | 客户端是用户级进程，开机自启动需要各平台的用户级机制（Windows 计划任务或启动项，Linux systemd --user 或 XDG autostart），原稿没有区分 | 延后（ADR 0016） |
| G16 | 内控制模块 | 本地控制通道的传输方式和鉴权未定 | 延后；自动协议选择需要用到 sing-box 本地控制 API 时，要求绑定回环地址并设置密钥（ADR 0009） |
| G17 | 服务端 Windows | 单用户自用的服务端通常跑在 Linux VPS 上，Windows 服务端会显著增加工作量 | 已确认：暂不支持（ADR 0001） |

## 5. 建议修订后的配置契约

只列出与原稿不同的部分。

```toml
# server.toml
schema = 1

[server]
domain = "example.com"
listen = "::"

[protocols.trojan]
enabled = false
port = 443
# 不配置即关闭 fallback
# fallback = { host = "127.0.0.1", port = 8080 }

[auth]
credential_ref = "file:/etc/norain-server/secrets/password"

[tls]
mode = "manual"        # manual | self-signed；acme 等 ADR 0015 确认后开放
```

```toml
# cfg.toml
schema = 1

[local]
listen = "127.0.0.1"
port = 2080

[proxy]
protocol = "hysteria2"   # 阶段 2：hysteria2 | trojan
server = "example.com"
credential_ref = "file:~/.config/norain/password"
traffic_mode = "mixed"   # 阶段 2 只允许 mixed

[proxy.hysteria2]
port = 443

[proxy.trojan]
port = 443

[proxy.tls]
server_name = "example.com"
# 自签证书时设置
# certificate_path = "~/.config/norain/server.crt"

[dns]
mode = "local"           # 阶段 2 只允许 local
```

`[routing]`、`[monitor]` 段在对应功能实现之前，校验器只接受空值或默认值，并给出「功能未实现」的警告。

## 6. 参考实现的借鉴点

| 项目 | 借鉴 | 不照搬 |
|---|---|---|
| sing-box 官方文档 | 字段、弃用表、`check` 命令 | —— |
| v2rayN | 核心进程管理与配置生成分层；生成配置后再启动核心 | 多核心支持、订阅系统 |
| Hiddify App | 把 Proxy、System Proxy、VPN/TUN 划分为独立运行模式 | 移动端、订阅、自动更新 |

本次审计没有阅读这两个项目的源码，只采纳了原稿中描述的分层思路。

## 7. 阶段 1 启动前必须完成

1. 用户确认 ADR 0002、0003、0004、0012、0013、0014、0015、0016（0001 已接受）。
2. 准备一台可以下载 sing-box 的 Ubuntu 24.04 环境，可以是你自己的机器，也可以是开放网络的工作区。
3. 复核 `third_party/singbox.lock.toml` 中的 SHA-256，并核实 ADR 0002 的「待验证」项。
