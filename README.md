# Norain

基于 sing-box 的 Hysteria2 / Trojan 代理：客户端 `norain` 和服务端 `norain-server`，Python 做控制层，
sing-box 做数据面，兼容 Windows 和 Linux。

**当前状态：最初目标里两端的全部模块代码已写完，但还没有在真实环境里验证过——没有跑过测试，
没有用过真实的 sing-box，没有在任何系统上执行过安装、防火墙或阻断命令。** 详见
[HANDOFF.md](HANDOFF.md) 和 [docs/pending.md](docs/pending.md)。

优先级：以最初目标 [docs/reference/original-goals.md](docs/reference/original-goals.md) 为准，除非有硬性 bug。

## 客户端（九个模块）

代理、分流、监控、自维持、阻断、修复、启动、内控制、外控制。

```bash
norain install --server example.com     # 部署：sing-box、配置、norain 命令、环境变量、开机自启动
norain start | stop | restart | status
norain config protocol auto             # 自适应 / hysteria2 / trojan
norain config mode safe                 # 安全模式：不开机自启动
norain list white add example.com       # 白名单 / black 黑名单 / blue 蓝名单 / monitor 监控名单
norain module monitor restart           # 启动 / 结束 / 重启单个模块
norain repair file|builtin|full|reload  # 四种修复
norain block status|off                 # 阻断模式；off = 手动解除
norain once monitor                     # 一次性执行某个模块的某个功能
norain status -t                        # -t：显示每个模块的运行情况和返回结果
norain uninstall
```

## 服务端

干净机器上可以直接用引导脚本（系统依赖 → 虚拟环境 → 安装包 → `norain-server install`）：

```bash
sudo ./scripts/bootstrap-server.sh
```

已经装好 Python 与 venv 时，照常手动安装：

```bash
NORAIN_DOMAIN=example.com NORAIN_PASSWORD=… norain-server install
norain-server start | stop | restart | reload | status
norain-server config validate|show|edit
norain-server cert check | cert self-signed --domain <域名>
norain-server firewall open|close|status
norain-server fix
norain-server update | uninstall [--purge]
```

## 文档

- 交接说明和未验证项目：[HANDOFF.md](HANDOFF.md)
- 实现状态清单：[docs/pending.md](docs/pending.md)
- 决策记录：[docs/decisions/](docs/decisions/README.md)
- 配置示例：[examples/server.toml](examples/server.toml)、[examples/cfg.toml](examples/cfg.toml)
- sing-box 锁定版本：[third_party/singbox.lock.toml](third_party/singbox.lock.toml)（1.14.4）

## 开发

需要 Python ≥ 3.11，以及 pydantic、cryptography、psutil。

```bash
pip install -e ".[dev]"
python3 -m pytest -q
```
