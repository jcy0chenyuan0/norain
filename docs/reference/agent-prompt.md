# Norain 开发代理提示词

## 任务定位

你负责设计、实现和维护 Norain。Norain 分为客户端 `norain` 和服务端 `norain-server`，控制层使用 Python，代理数据面使用 sing-box，目标平台为 Windows 和 Linux，协议包括 Hysteria2 和 Trojan。

原始产品目标包含客户端九个功能模块、服务端八个功能模块、自动部署、开机启动、配置管理、监控、修复和命令行控制。本提示词保留这些目标，同时要求先完成技术审计和架构决策，再按里程碑交付。没有经过决策的实现细节不能被代理自行假定。

## 工作规则

每次只完成一个可验收的里程碑。开始工作前先检查仓库根目录、已有代码、依赖、测试、CI、配置、服务文件和运行环境。

默认先完成阶段 0 的审计。阶段 0 只读代码和环境，形成报告与决策记录，不安装软件，不启动服务，不注册自启动，不写系统环境变量，不修改防火墙，不删除用户数据。

除非用户明确要求真实部署，代理只提交代码、测试、示例配置、决策记录和部署说明。需要管理员或 root 权限的操作必须提供回滚步骤和验收命令。

每个阶段的交付报告必须包含输入、已确认约束、修改文件、测试结果、已验证平台、未验证项目、验收命令和回滚方式。

优先级按以下顺序处理：正确性和数据安全、可恢复性、跨平台一致性、可观测性、性能和便利性。

## 阶段 0  需求审计和技术决策

先生成 `docs/architecture-audit.md` 和 `docs/decisions/` 下的决策记录。审计必须回答以下问题：

1. 仓库根目录、Python 版本、构建方式和现有 CLI 入口是什么。
2. 支持哪些 Windows 和 Linux 版本，发布哪些 CPU 架构。
3. 使用哪个固定版本的 sing-box，二进制从哪里取得，如何校验哈希或签名。
4. `cfg.toml` 和 `server.toml` 如何映射到该 sing-box 版本的 JSON Schema。
5. 客户端采用本地 HTTP/SOCKS 或 mixed 代理、系统代理、TUN 还是透明代理。
6. DNS 请求由 sing-box 接收、系统接收还是外部服务接收，IPv4 和 IPv6 如何处理。
7. 服务端由 systemd、Windows Service、计划任务还是 Python 子进程监督器负责最终自动重启。
8. 密码、证书私钥和其他秘密来自秘密文件、操作系统凭据存储还是环境变量。
9. 分流规则来自固定版本的 rule-set、手工域名列表还是其他来源，如何下载、校验、缓存和回滚。
10. 哪些功能属于首个可用版本，哪些功能必须延后。

阶段 0 要把以下内容标记为决策项，不能直接写死：

- “全局流量”对应的实际接管方式。
- “白名单、黑名单、蓝名单”的精确定义和优先级。
- DNS 分类和分流的策略。
- 自动协议选择的测速目标、阈值和冷却时间。
- 监控目标、预期结果和误报处理。
- 阻断模块的默认状态、恢复路径和允许连接。
- systemd、Windows Service 与 Python 监督器的职责边界。
- 自启动、自动恢复和手动停止之间的状态关系。

没有完成决策的功能进入待定清单。代理不得把待定功能报告为已实现。

## 阶段 1  服务端最小垂直切片

先完成服务端一条可运行链路，读取 Norain 配置，生成版本匹配的 sing-box JSON，校验配置，启动一个 sing-box 进程，查询状态并停止进程。

阶段 1 实现以下能力：

- `server.toml` 配置模型和字段校验。
- sing-box JSON 配置生成器。
- `sing-box check -c <配置>` 校验。
- 配置临时写入、原子替换和旧版本备份。
- `norain-server config validate`。
- `norain-server start`。
- `norain-server stop`。
- `norain-server status --json`。
- 结构化日志和稳定的 CLI 退出状态。

先为一个协议建立完整测试夹具，再扩展第二个协议。协议字段必须依据锁定版本的官方 Schema。Hysteria2 的 TLS、Trojan 的 TLS 和可选 fallback、认证字段、端口和证书行为都要通过版本能力检查确认。

阶段 1 的完成条件如下：

- 有效配置能生成并通过目标版本的 `sing-box check`。
- 缺少协议、端口错误、证书无效、秘密缺失和不支持字段都能给出字段级错误。
- 校验失败不会覆盖上一份可用配置。
- `start`、`stop` 和 `status --json` 至少在一个目标平台真实验证，另一个平台完成适配器测试。
- 手动停止后，没有其他组件自动重新启动进程。

## 阶段 2  客户端最小垂直切片

客户端先支持一种明确的流量接管方式。默认建议从本地 HTTP/SOCKS 或 mixed 代理开始，先验证协议、配置、状态和 CLI。需要全局接管时，必须先完成 TUN 或透明代理的决策，再实现平台权限、路由表、DNS 劫持和 IPv6 行为。

阶段 2 实现以下能力：

- `cfg.toml` 配置模型和 sing-box JSON 生成器。
- 从配置读取服务器地址、端口、秘密引用、流量模式和协议。
- 单个协议的启动、停止、状态查询和配置快照。
- 本地代理入口的端口冲突检查。
- `norain config validate`。
- `norain start`。
- `norain stop`。
- `norain status --json`。

分流、自动协议选择、网站探测、自动修复和网络隔离不作为阶段 2 的完成条件。

## 客户端功能范围

客户端最终包含以下九个模块。每个模块的具体实现必须服从阶段边界和已确认的决策。

### 代理模块

代理模块负责调用 sing-box，读取 `cfg.toml`，生成运行配置并管理代理进程。配置至少包含代理服务器地址和端口、秘密引用、流量接管方式和协议选择。

支持 `auto`、`hysteria2` 和 `trojan` 三种协议选择模式。自动选择只能依据已记录的连通性、延迟、失败率、优先级和冷却时间，不能凭单次请求切换。

配置生成成功后执行目标版本的 `sing-box check`。进程标准输出和标准错误进入统一日志，退出时记录退出码和脱敏的最后错误。

### 分流模块

分流模块负责规则、DNS 和出站选择。产品中的列表名称必须在决策记录中固定语义，建议使用以下配置字段：

- `proxy_domains` 代表强制经代理访问的域名。
- `direct_domains` 代表强制直连的域名。
- `isolation_allowlist` 代表隔离模式仍允许的连接。
- `monitor_targets` 代表健康检测目标。

决策顺序由阶段 0 确认，至少要说明显式规则、缓存、DNS 规则、rule-set、默认动作的优先级。GeoIP 或 DNS 返回的地理位置不能单独决定最终分流。规则下载必须记录来源、版本、哈希、更新时间和失效行为。

DNS 设计必须说明本地 DNS、代理侧 DNS、备用 DNS、缓存 TTL、IPv4/IPv6、DNS 请求防泄漏和 DNS 失败时的默认动作。不能用“查询到国内 IP”直接推导目标必然属于国内流量。

### 监控模块

监控模块负责检测代理、网络、DNS 和 IPv4/IPv6 链路。每次探测记录目标、直连或代理路径、解析结果、耗时、协议、IP 版本和错误原因。恢复和故障都要使用连续成功或连续失败阈值，避免网络抖动引发误判。

保留原稿中的业务诊断码：

- `100` 表示本地互联网未连接。
- `301` 表示部分网络可用但主要目标失败。
- `400` 表示分流或检测链路异常。
- `401` 表示 DNS 解析位置与策略不一致。
- `600` 表示代理服务器或服务器链路不可用。
- `604` 表示 IPv4 代理链路异常。
- `606` 表示 IPv6 代理链路异常。

业务诊断码与 CLI 进程退出码分开。结构化结果至少包含 `error_id`、业务码、模块、是否可重试、错误详情和恢复建议。

### 自维持模块

自维持模块负责正常的服务监督、有限次数重启、退避和故障上报。它不隐藏进程，不绕过系统控制，不对手动停止的服务持续拉起。

监督对象包括代理、分流、监控和控制服务。模块需要处理启动、停止、更新、修复之间的互斥关系。修复期间暂停同一故障的重复告警，达到重启上限后进入失败状态并保留诊断信息。

### 阻断模块

阻断模块负责在代理链路失效时保护用户免于意外直连。它属于后续独立阶段，默认状态和自动触发条件必须经过决策记录确认。

实现前必须具备管理员或 root 权限检查、防火墙规则快照、事务式修改、独立恢复命令、恢复路径测试和模拟后端测试。恢复命令不能依赖已经被阻断的代理连接。进入隔离模式前记录原因、影响范围、规则版本和恢复方法，并提供用户可见提醒。

### 修复模块

修复模块提供四个级别：

1. 文件修复。扫描文件、校验哈希并恢复缺失或损坏的运行文件。
2. 内置配置修复。恢复 Norain 内置配置，同时保留用户配置副本。
3. 完全配置修复。按用户确认重建代理、DNS、服务和 Norain 创建的系统规则。
4. 重载修复。执行完整卸载后重装，卸载部分必须是独立命令。

每个级别支持 `--dry-run`、备份、结果摘要和回滚信息。删除配置、证书、日志、注册表项或防火墙规则前，必须列出目标并要求显式确认。

### 启动模块

启动模块负责正常模式、安全模式和用户启用的开机自启动。启动时检查配置、依赖、权限、服务状态和隔离状态，再按已确定的顺序启动分流、代理和监控。

安全模式只启动诊断所需的最小组件。隔离模式是否在启动时自动恢复由阶段 0 决策，安全默认值为保持隔离并等待用户执行恢复命令。

### 内控制模块

内控制模块负责跨模块编排、运行参数和状态转换。启动、停止、重启、修复、协议切换和隔离操作都经过统一控制器，并使用操作锁、操作 ID、超时和幂等检查。

本地控制通道必须明确传输方式、访问权限、鉴权方式和审计日志。不能只写“需要审批”而不定义审批主体和状态来源。

### 外控制模块

外控制模块提供配置、控制和调试命令。至少包括：

```text
norain install [--force]
norain uninstall [--purge]
norain start [--safe] [--restore-isolation]
norain stop
norain restart
norain status [--json]
norain logs [-f]
norain config <validate|show|edit>
norain module <start|stop|restart|status> <name>
norain repair <file|builtin-config|full-config|reinstall> [--dry-run]
norain firewall <status|isolate|restore> [--dry-run]
norain debug [--json]
```

CLI 必须提供稳定退出码、统一帮助、超时控制和 JSON 输出。配置展示和调试输出不得回显密码、私钥、令牌或完整认证 URL。

## 服务端功能范围

服务端 `norain-server` 以一个配置输入、一个 sing-box 数据面进程、一个服务监督者和一个 CLI 为基本形态。服务端支持单用户自用场景，不实现多用户、配额、流量统计、复杂服务端分流、客户端式修复体系和客户端网络隔离。

### 入站模块

入站模块读取 `server.toml`，决定启用的协议、监听地址、端口、认证秘密和 TLS 证书。

- Hysteria2 使用 UDP 入站，默认端口为 `443/udp`。
- Trojan 使用 TCP 入站，默认端口可以是 `443/tcp` 或独立配置的 TCP 端口。
- 两种协议可以同时启用，也可以单独启用。
- 认证成功后统一交给显式声明的 `direct` 出站，服务端不做复杂分流。
- Trojan fallback 为可选配置。未配置时按版本支持的默认拒绝行为处理，不强制伪装成网站。
- 单用户抽象必须在生成 JSON 时映射为目标版本要求的 `users[]`，密码不能硬编码。

TCP 443 和 UDP 443 属于不同传输协议，是否可同时使用要通过目标平台监听和防火墙测试确认，不能仅凭数字端口判断冲突。

### 配置模块

配置模块把用户可读的 `server.toml` 转换为版本匹配的 `sing-box.json`。

处理顺序如下：

1. 解析 TOML 并校验类型、必填项和未知字段策略。
2. 校验至少启用一个协议、端口合法、秘密可读取、证书模式和路径有效。
3. 根据协议和证书能力生成入站、显式 `direct` 出站和日志配置。
4. 生成临时 JSON，记录生成器版本、sing-box 版本和 Schema 版本。
5. 执行目标版本的 `sing-box check`。
6. 校验成功后原子替换当前配置并保留上一版本。
7. 校验失败时保留当前可用配置并输出字段级错误。

配置生成必须幂等。修改配置不自动重启，重载或重启由已确定的控制者执行。`config show` 默认隐藏秘密字段，`config edit` 使用安全的临时文件流程。

### 证书模块

支持 `acme`、`manual` 和显式开启的 `self-signed` 三种模式。具体字段必须根据锁定的 sing-box 版本检查。

- `acme` 没有域名或无法完成能力检查时拒绝执行。
- `manual` 读取用户指定的证书和私钥路径。
- `self-signed` 使用 openssl 或等价库生成自签证书，并在状态中标记用途。
- 每次生成配置前检查文件存在、证书与私钥匹配、域名匹配和有效期。
- 证书更新后提供 `norain-server reload`，不重启操作系统。

至少提供以下命令：

```text
norain-server cert check
norain-server cert self-signed --domain <域名>
```

### 守护模块

服务端只能有一个组件拥有最终自动重启权。若由 systemd 或 Windows Service 负责重启，Python 组件只负责配置检查、状态查询和控制请求。若由 Python 子进程监督器负责重启，外部服务管理器不得再设置无限重启。

无论采用哪种方案，都需要检查进程状态、端口监听和最近的 fatal 日志。默认检查间隔为 30 秒，最大连续重启次数为 3 次，均可配置。达到上限后停止重启，保留日志、配置版本和故障摘要。

手动 `stop` 必须写入期望状态 `stopped`，监督器和服务管理器都要尊重该状态。`norain-server run` 只能启动已通过配置和证书检查的进程。

服务端业务状态码保留原稿约定：

- `0` 表示正常。
- `110` 表示配置缺失或格式错误。
- `120` 表示证书无效。
- `130` 表示端口被占用。
- `140` 表示 sing-box 进程退出。
- `150` 表示 sing-box 二进制缺失或不可执行。
- `160` 表示连续重启失败。

业务状态码与 CLI 进程退出码分开。`status --json` 至少包含服务状态、进程状态、协议、端口、证书状态、配置版本、重启次数、最近错误和更新时间。

### 防火墙模块

防火墙模块只管理 Norain 创建的协议端口规则。

- Hysteria2 放行 UDP 端口。
- Trojan 放行 TCP 端口。
- Linux 优先适配 ufw 或 firewalld，没有可用后端时返回手动操作说明。
- Windows 使用 Windows 防火墙规则并记录规则名称和版本。
- `open`、`close` 和 `status` 必须幂等。
- 关闭协议或卸载时只移除 Norain 创建的规则，不能删除用户已有规则。
- 防火墙操作失败时输出具体后端错误。

至少提供：

```text
norain-server firewall open
norain-server firewall close
norain-server firewall status
```

### 状态日志模块

支持以下能力：

- `norain-server status --json` 查询统一状态。
- `norain-server log` 查看日志。
- `norain-server log -f` 持续跟踪日志。
- 按大小或时间轮转日志，并保留可配置份数。

日志事件包含时间、级别、模块、操作 ID、事件名和脱敏详情。密码、私钥、令牌和完整认证 URL 不得出现在日志中。

### 外控制模块

服务端至少提供以下命令：

```text
norain-server install [--force]
norain-server update [--version <版本>] [--dry-run]
norain-server uninstall [--purge]
norain-server start
norain-server stop
norain-server restart
norain-server reload
norain-server run
norain-server status --json
norain-server config <validate|show|edit>
norain-server cert check
norain-server cert self-signed --domain <域名>
norain-server firewall <open|close|status>
norain-server log [-f]
norain-server fix [--dry-run]
```

`fix` 只做配置重建、证书检查和缺失文件恢复。`uninstall` 默认保留日志、备份和用户配置，只有 `--purge` 且经过确认后才删除。

## 配置契约

### 客户端 `cfg.toml`

至少定义以下输入概念，并为每项提供类型、默认值、迁移方式和未知字段策略：

```toml
[app]
mode = "normal"                 # normal | safe
auto_start = false

[proxy]
protocol = "auto"               # auto | hysteria2 | trojan
server = "example.com"
port = 443
credential_ref = ""
traffic_mode = "mixed"           # mixed | system-proxy | tun | transparent

[routing]
proxy_domains = []
direct_domains = []
isolation_allowlist = []
rule_set = []

[dns]
mode = "split"                  # local | split | proxy
cache_ttl_seconds = 300

[monitor]
interval_seconds = 30
failure_threshold = 3
recovery_threshold = 2

[supervisor]
restart_limit = 3
backoff_seconds = 5

[paths]
state_dir = ""
log_dir = ""
```

`traffic_mode`、DNS 规则、隔离恢复策略和 `protocol = "auto"` 的具体行为必须有决策记录。没有对应实现的模式不能出现在默认配置中。

### 服务端 `server.toml`

至少定义以下输入概念：

```toml
[server]
domain = "example.com"
listen = "0.0.0.0"

[protocols.hysteria2]
enabled = true
port = 443

[protocols.trojan]
enabled = false
port = 443
fallback = ""

[auth]
credential_ref = ""

[tls]
mode = "manual"                 # acme | manual | self-signed
certificate = ""
private_key = ""

[service]
check_interval_seconds = 30
restart_limit = 3

[logging]
directory = ""
max_size_mb = 20
retain_files = 5
```

密码优先来自权限受限的秘密文件或操作系统凭据存储。兼容环境变量时，支持以下变量引用，但不在状态和日志中回显值：

```text
NORAIN_SERVER_HOME
NORAIN_SERVER_CONFIG
NORAIN_SERVER_LOG
NORAIN_SERVER_SINGBOX
NORAIN_HY2_PORT
NORAIN_TROJAN_PORT
NORAIN_DOMAIN
NORAIN_CERT_MODE
NORAIN_PASSWORD
```

## 部署、更新和卸载

### Linux

1. 识别架构并取得固定版本的 sing-box。
2. 校验哈希或签名后安装到目标路径。
3. 创建配置、状态、证书和日志目录并设置最小权限。
4. 注册明确声明运行用户、依赖和重启策略的 systemd 服务，或使用已经选定的 Python 监督方案。
5. 生成环境变量文件，不能只依赖交互式 shell。
6. 执行配置校验和启动冒烟测试，失败时恢复上一版本。

### Windows

1. 识别架构并取得固定版本的 `sing-box.exe`。
2. 校验哈希或签名后安装到 `%ProgramFiles%\norain-server\` 或用户确认的目录。
3. 配置目录使用 `%ProgramData%\norain-server\`，用户数据和日志目录可独立配置。
4. 注册 Windows Service 或计划任务，明确运行账户、启动方式和停止行为。
5. 更新机器级环境变量时说明新进程生效条件，并提供查看实际生效值的命令。
6. 执行配置校验和启动冒烟测试，失败时恢复上一版本。

### 共同要求

- 安装、更新和卸载必须幂等。
- 重复安装不得覆盖用户配置，除非显式使用 `--force`。
- 更新前备份二进制、配置、证书引用、服务文件和 Norain 创建的防火墙规则。
- 只有配置校验和启动测试成功后才切换版本。
- 卸载只清理 Norain 创建的内容，默认保留日志和用户数据。
- 每次变更输出版本、摘要、备份位置和恢复命令，不输出秘密。

## 测试和验收

### 自动化测试

- 配置解析、默认值、迁移、未知字段和字段级错误。
- TOML 到 sing-box JSON 的生成、`users[]` 映射和显式 `direct` 出站。
- 配置原子替换、旧版本保留和校验失败回滚。
- Hysteria2 和 Trojan 单独启用以及同时启用。
- 证书模式、端口占用、二进制缺失和 sing-box 启动失败。
- 进程状态、手动停止抑制、重启上限、退避和操作锁。
- 规则优先级、DNS 缓存、rule-set 失效和 IPv4/IPv6 分离。
- 防火墙适配器的幂等性、规则范围和恢复流程，测试使用模拟后端。
- 日志脱敏、路径遍历防护、命令参数安全和权限检查。
- Windows 与 Linux 的路径、服务和环境变量适配。

### 阶段验收

每个阶段至少提供一条从配置校验到状态查询的命令链。验收记录要说明：

- 使用的 sing-box 版本和 Schema 版本。
- 使用的 Python 版本和操作系统。
- 运行的命令和关键输出。
- 真实验证与模拟验证的边界。
- 失败时的恢复命令。

网络隔离、系统代理、TUN、透明代理和真实防火墙操作必须在明确的支持矩阵中单独列出。没有实际验证的组合标记为未验证。

## 参考实现

参考官方 sing-box 仓库和文档确定 JSON Schema、协议字段、路由、DNS、rule-set、`check` 和服务管理行为。sing-box 原生配置是 JSON，Norain 的 TOML 只作为输入格式。不要追踪 `latest`，要固定版本并绑定对应 Schema。

参考 v2rayN 的核心管理、配置生成、配置快照、测速配置和平台适配分层。参考 Hiddify App 对 Proxy、System Proxy、VPN/TUN 的运行模式划分以及多平台测试配置组织。参考这些项目的边界和验证方法，不复制其内部代码或默认产品范围。

- [sing-box 官方仓库](https://github.com/SagerNet/sing-box)
- [sing-box 配置文档](https://sing-box.sagernet.org/configuration/)
- [sing-box 路由规则文档](https://sing-box.sagernet.org/configuration/route/rule/)
- [sing-box Linux 包和服务管理](https://sing-box.sagernet.org/installation/package-manager/)
- [v2rayN](https://github.com/2dust/v2rayN)
- [Hiddify App](https://github.com/hiddify/hiddify-app)

## 最终交付格式

每个阶段交付变更说明、决策记录、可运行入口、配置样例、必要测试、验收命令、未验证能力、外部依赖和回滚方式。

阶段验收条件未满足时，保持当前阶段并报告缺口。后续阶段的代码、命令或文档不能被当成已经完成的功能。
