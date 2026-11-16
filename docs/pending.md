# 实现状态清单

「代码」一栏为「已写」表示实现已经在仓库里；「验证」一栏说明它在真实环境里验证到了什么程度。
2026-11-15 起区分两类验证：**用例**（pytest，模拟 sing-box，只验证控制逻辑）和**实测**
（真实 sing-box 1.14.4 + 真实 Windows 命令 + 真实服务器）。实测范围见文末「2026-11-15 真实环境实测」：
客户端与服务端生成的配置、TUN 路由、防火墙阻断、计划任务、系统代理、真实隧道都已跑通；
Linux 侧、真实 ACME、监控错误码、自维持互拉仍未验证。

## 服务端

| 功能 | 最初目标的模块 | 代码 | 验证 |
|---|---|---|---|
| server.toml 模型、Hysteria2 / Trojan 入站生成 | 入站、配置 | 已写 | 5 种组合（含 Trojan 443/18443）通过真实 `sing-box check` |
| 证书 manual / self-signed | 证书 | 已写 | 自签（openssl 后端）生成 + 配置通过真实 check |
| 证书 acme（HTTP-01，`certificate_providers`） | 证书 | 已写 | 生成的配置通过真实 check；真实签发未验证（需公网 80） |
| 守护、重启上限、手动 stop 不拉起 | 守护 | 已写 | 早期版本用模拟 sing-box 测过；systemd 未做 |
| `reload`（只重启 sing-box 子进程） | 证书、守护 | 已写 | 未验证 |
| 防火墙 open / close / status（ufw、firewalld、netsh） | 防火墙 | 已写 | 未验证 |
| `status` JSON、`log [-f]`、轮转 | 状态日志 | 已写 | 早期版本测过 |
| `config edit`、`fix` | 外控制 | 已写 | 未验证 |
| install / update / uninstall、systemd 注册、profile.d | 部署更新 | 已写 | 未验证 |
| Windows：路径、计划任务自启、setx、netsh | 部署更新 | 已写 | 未验证；用户已确认保留（ADR 0001 修订） |

## 客户端

| 功能 | 最初目标的模块 | 代码 | 验证 |
|---|---|---|---|
| mixed 本地代理、单协议 | 代理 | 已写 | 真实 sing-box check + 本地端到端隧道实测通过 |
| TUN 全局接管、system-proxy | 代理 | 已写 | 均实测：TUN 建接口/接管默认路由/退出还原；system-proxy 真实写注册表并还原 |
| 白 / 黑名单、规则集、默认动作、split / proxy DNS | 分流 | 已写 | 生成的 6 种组合通过真实 check（含 .srs）；逐条路由结果未验证 |
| 规则集下载、校验、自更新、回滚 | 分流 | 已写 | 未验证（只验证了本地 .srs 的加载） |
| 「试连 → 改判 → 加入名单」的事后学习 | 分流 | 已写 | 未验证；`_CONN` 对真实日志匹配通过，`_ERR` 在真实 info 日志里未能触发 |
| 错误码 100 / 301 / 400 / 401 / 600 / 604 / 606 | 监控 | 已写 | 未验证 |
| 模块掉线拉起、修复升级、看门狗互拉 | 自维持 | 已写 | 未验证 |
| 阻断：防火墙、弹窗、手动解除、启动时自动解除 | 阻断 | 已写 | 真实 Windows 防火墙实测通过：蓝名单内 200 / 名单外阻断 / 解除后还原 |
| 修复四级、独立的卸载命令 | 修复 | 已写 | 未验证 |
| 开机自启动、正常 / 安全模式 | 启动 | 已写 | 计划任务创建/查询/删除实测通过；install 的 setx/PATH/开机项未测 |
| 审批、启动测试、自适应选协议（auto） | 内控制 | 已写 | 未验证 |
| 配置类 / 控制类 / `-t` 调试 | 外控制 | 已写 | `config show/validate`、`status`、`start`、`stop` 实测（真实二进制） |
| install / uninstall、环境变量、`norain` 命令 | 部署 | 已写 | 未跑完整 install；用真实二进制 + 真实服务器 `start` 实测通过 |

## 没有实现

| 功能 | 说明 |
|---|---|
| `traffic_mode = "transparent"` | Linux 的 tproxy / redirect。校验时拒绝。全局接管用 TUN |
| 逐请求的分流判断 | sing-box 在进程内完成路由，无法逐请求介入；用事后学习代替（见 HANDOFF.md） |
| ACME 的 DNS-01 挑战 | 只支持 HTTP-01；Trojan 监听 443/tcp 时额外保留 TLS-ALPN-01 |
| 规则集的固定 commit 和预置哈希 | 目前从分支地址下载，首次信任并记录哈希；`rules.lock.toml` 里写了哈希才强制比对 |
| Windows 上的文件权限（ACL）检查 | 密码文件和运行配置的访问权限不检查 |
| 多用户、配额、流量统计、服务端分流 | 最初目标明确不做 |

## 建议的验证顺序

1. Linux 上跑 `python3 -m pytest -q`，修掉回归。
2. ~~两端生成的配置过真实的 `sing-box check`~~ 已于 2026-11-15 完成（客户端 6 种、服务端 5 种）。
3. ~~客户端在 Windows 上真实启动~~ 已于 2026-11-15 完成（真实服务器、真实隧道、出口 IP 校验）。
4. 服务端在一台 Linux VPS 上 `install` → 客户端连它。
5. 客户端监控错误码、自维持互拉、分流学习闭环（真实日志下）。
6. 修复模块，在一次性虚拟机里。

## 2026-11-15 真实环境实测（Windows 11 · sing-box 1.14.4）

环境：真实 sing-box 1.14.4、真实服务器、真实 Windows 防火墙 / 计划任务 / 注册表 / TUN。

**已通过**

| 项目 | 结论 |
|---|---|
| 客户端配置生成 | 6 种组合（mixed / system-proxy / TUN × 单协议 / auto × split / proxy / local DNS）全部通过 `sing-box check`，加载真实 `.srs` |
| 服务端配置生成 | 5 种组合（Hy2 单开、Hy2+Trojan 443/18443、self-signed、ACME 结构）全部通过 |
| 本地端到端隧道 | 真实 sing-box 服务端 + norain 生成配置，经客户端代理取回内容成功（强制走隧道） |
| 真实服务器启动 | `norain start` 后 google / chatgpt 200，出口 IP 与预期一致，国内直连正常 |
| TUN 接管 | 建出 `norain0`(172.19.0.1)、默认路由被 172.19.0.2 接管、优雅退出后接口与路由完整还原 |
| 防火墙阻断 | 进入阻断后蓝名单内 200、名单外 000；解除后规则归零、网络恢复 |
| 计划任务 | `schtasks` 创建 / 查询 / 删除往返成功 |
| 系统代理 | 运行期写 `ProxyEnable=1`、`ProxyServer=http://127.0.0.1:1082`；`norain stop` 后还原为原值 |

**实测中发现并已修的两个缺陷**

1. `Geo._match` 调 `rule-set match` 时缺 `-f binary`：真实二进制对 `.srs` 直接 FATAL（exit 1），
   「是否国内」永远为未知。另外命中时输出 `match rules.[0]: …`、未命中时**输出为空且 exit 0**，
   原实现把空输出当「未知」而不是「不命中」。(已修 + 回归测试 `tests/test_sysproxy_geo.py`)
2. `set_system_proxy` 的还原不可靠：sing-box 被硬终止时**什么都不还原**（系统代理留在死端口，整机断网）；
   正常退出也只把 `ProxyEnable` 置 0，不回填原 `ProxyServer`。而客户端停子进程用的就是
   `terminate()`（Windows 上即硬杀）。已在客户端侧加注册表快照/还原（`norain_core/sysproxy.py`），
   快照落盘、强杀后下次启动先还原。(已修 + 回归测试)

**服务端真实部署（2026-11-16）**

- Ubuntu + Python 3.12 venv 安装 `norain-server`，接管 443：Hysteria2（UDP）+ Trojan（TCP）同时服务；
  systemd 单元、防火墙放行、启动测试全部通过
- 原有的 proxy-suite 客户端直接连新服务端：google 200、出口 IP 正确（trojan 与 hysteria2 都验证过）
- 客户端 trojan 多路复用默认关闭：sing-box 1.7+ 要求服务端**入站**开启 multiplex，
  原来那套服务端没开，实测开 mux 时 trojan 立刻失败（000），关闭后正常（200）
- 新增 `[routing.warp]`：指定域名走本机 socks5（Cloudflare WARP），其余直连，
  与旧服务端的 hysteria `acl` 一致（claude.ai / claude.com / anthropic.com / claudeusercontent.com → warp）。
  部署后日志确认 `outbound/socks[warp]: outbound connection to claude.ai:443`，
  浏览器实测 claude.ai 正常打开（已登录）；`api.anthropic.com` 返回 401（可达）
- 注意：用 `curl` 直测 `claude.ai` 会得到 403（Cloudflare 按 UA/TLS 指纹拦命令行客户端），
  这不代表出口被封，判断要按浏览器或 API 的实测结果
- `fix`、`update`、`reload` 均实测：fix 重建配置后服务保持 active；update 备份→复用现有二进制→
  校验→重注册自启动→重启，服务恢复后客户端请求 200、出口 IP 正确
- **abyssrain.top 真实部署（2026-11-16）**：`norain-server install` 自动下载并校验 sing-box 1.14.4、
  生成配置、注册 systemd、放行 443/udp 与 80/tcp、启动测试通过
- **真实 ACME 签发成功**：Let's Encrypt 为 abyssrain.top 签发证书（日志 `certificate obtained successfully`），
  客户端用 `insecure = false` 做真实证书校验即可连通（google 200，出口 IP = 服务器 IP）
- **与 nginx 共存**：Hysteria2 用 UDP 443、nginx 继续占 TCP 80/443
- **开机自启动经真实重启验证**：`systemctl reboot` 后 `norain-server` 与 `nginx` 均 active，
  网站 200、代理 google 200 全部恢复
- 验证完成后已用 `norain-server uninstall --purge` 卸载（那台机器是网站服务器，保留 nginx）；
  这一节记录的是验证结论，不代表仍在部署
- 客户端 `NftBackend`（Linux 阻断）在真实 `nft` 上实测通过，见「仍未验证」里的说明

**仍未验证**

- ~~nftables 后端~~：2026-11-16 在服务器的 Linux（Ubuntu 24.04，真实 `nft`）上直接运行客户端的
  `NftBackend` 验证通过——建出 `inet norain_block`（output policy drop）、非白名单目标被阻断
  （1.1.1.1 → 000）、SSH 因白名单放行而保持连接、`release` 后表被删除、网络恢复（301）。
  放行清单含基础段 + 局域网 + 代理服务器 + 国内 DNS + 监控国内目标，属设计内行为
- ~~真实 ACME 签发~~：2026-11-16 在 abyssrain.top 上验证通过（见上文），续期仍待时间验证
- 真实 ACME 签发（需要公网 80/tcp）
- 监控错误码在真实环境下的触发与防抖
- 自维持模块与看门狗互拉、修复四级
- 分流学习「试连 → 改判」闭环：`_CONN` 已对真实日志验证匹配，`_ERR` 尚未在真实日志中出现
- `install` 的 `setx` / PATH / 开机自启写用户环境（未动）
- 客户端 `auto` 双协议：现有环境的 hysteria2 与 trojan **口令不同**，而配置模型只有一个
  `credential_ref`，因此实测只用单协议 hysteria2；双协议需要按协议分别配置口令（待设计）
