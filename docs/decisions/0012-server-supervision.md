# 0012 服务端监督职责边界

- 状态：已接受（2026-11-14，按最初目标修订，见文末）
- 日期：2026-11-14
- 关联：审计问题 7；原稿「守护模块」；ADR 0013

## 背景

原稿要求只有一个组件拥有最终自动重启权，并定义了检查间隔 30 秒、连续重启上限 3 次。

## 建议

**最终重启权属于 systemd**。Python 组件不自行重启 sing-box。

`norain-server run` 是服务管理器调用的前台包装进程：

1. 执行预检：配置校验、证书检查、二进制版本检查。失败时以对应业务码退出，例如 110、120、150。
2. 以子进程方式启动 `sing-box run -c <当前配置>`，转发停止信号，收集标准输出和标准错误写入日志。
3. 每 `check_interval_seconds`（默认 30）秒检查一次：子进程是否存活、端口是否在监听（UDP 和 TCP 分别检查）、最近日志中是否有 `FATAL` 或 `panic`。
4. 任何一项检查失败，就终止子进程，并以非零退出码退出（业务码 140 或 130），由服务管理器决定是否重启。
5. 自身绝不循环重启子进程。

**Linux（systemd 单元草案）**：

```ini
[Unit]
Description=Norain server (sing-box)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=3

[Service]
Type=simple
User=norain
ExecCondition=/usr/bin/norain-server _desired-state-is running
ExecStart=/usr/bin/norain-server run
ExecReload=/usr/bin/norain-server reload --from-service
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/norain-server /var/log/norain-server

[Install]
WantedBy=multi-user.target
```

- 「连续重启 3 次」解释为 600 秒内最多启动 3 次。超过后单元进入 failed 状态，`status` 报业务码 160。
- 以非 root 用户运行，用 `CAP_NET_BIND_SERVICE` 绑定 443 端口。
- `ExecCondition=` 的作用见 ADR 0013。

**Windows**：服务端暂不支持 Windows（ADR 0001 已接受），因此不设计 Windows Service。以后恢复支持时另立 ADR。

**不使用服务管理器的情况**：用户直接在终端运行 `norain-server run` 时，进程退出即结束，没有任何自动重启。

**reload**：先校验新配置，通过后切换并通知 sing-box 重载。sing-box 是否支持 SIGHUP 重载需要验证；不支持时 `reload` 改为由服务管理器重启。

## 待验证

- sing-box 1.14 是否支持通过 SIGHUP 重载配置。
- 官方 Linux 软件包自带的 `sing-box.service` 内容。Norain 不复用这个单元，但安装时需要检测它是否存在并运行，避免端口冲突。

## 需要用户确认

1. 最终重启权属于 systemd，Python 只做预检和健康检查后退出。
2. 「连续重启 3 次」的时间窗口取 600 秒。

## 确认

（空）

## 修订（取代上文「建议」中冲突的部分）

2026-11-14，用户：**以最初目标（docs/reference/original-goals.md）为准，除非有硬性 bug。**

最初目标的写法：Python 守护在 sing-box 退出时记录日志并尝试重启，连续失败达到上限后停止；Linux 用 systemd `Restart=on-failure` 做外层保活；手动 `stop` 后不自动拉起。

按此实现：

1. **`norain-server run` 自己重启 sing-box。** 子进程退出或健康检查失败时重启，连续重启次数超过 `restart_limit`（默认 3）后停止，报业务码 160。子进程稳定运行一段时间后，连续计数清零。
2. **systemd 只保活 Python 守护本身**（`Restart=on-failure`），防止守护进程被杀或崩溃。
3. **硬性 bug 的修正**：如果守护因为「达到重启上限」「配置无效」「缺少 sing-box」退出后又被 systemd 拉起，就会无限循环，重启上限失去意义。所以这三种情况使用专门的退出码（9、3、5），并在单元里写 `RestartPreventExitStatus=9 3 5`。
4. 手动 `stop` 时守护收到停止信号，正常退出（退出码 0），`on-failure` 不会重启。

上文中「Python 组件不自行重启 sing-box」「任何一项检查失败就退出」两条作废。
