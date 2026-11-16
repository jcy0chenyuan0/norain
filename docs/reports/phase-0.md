# 阶段 0 交付报告

> **历史快照，保留原样。** 当前的实现与验证状态以 [docs/pending.md](../pending.md) 为准。

- 日期：2026-11-14
- 状态：**交付完成，等待决策确认**。阶段 1 在关键 ADR 接受之前不开始。

## 输入

- 《Norain 开发代理提示词》
- 用户确认：从零开始，没有既有代码

## 已确认约束

- 控制层用 Python，数据面用 sing-box，协议为 Hysteria2 和 Trojan，平台为 Windows 和 Linux（来自原稿）
- 阶段 0 不安装软件、不启动服务、不改系统（来自原稿）
- 仓库从零开始（用户确认）

## 修改文件

| 文件 | 说明 |
|---|---|
| `pyproject.toml` | 构建配置；没有运行依赖，CLI 入口已注释 |
| `src/norain_core/`、`src/norain/`、`src/norain_server/` | 只有包声明和版本号 |
| `third_party/singbox.lock.toml` | sing-box 1.14.4 锁定文件，四个目标平台的 SHA-256 |
| `tests/test_singbox_lock.py` | 锁定文件结构测试 |
| `docs/architecture-audit.md` | 审计报告 |
| `docs/decisions/README.md`、`0001`–`0016` | 决策记录，全部为「提议」 |
| `docs/pending.md` | 待定清单 |
| `docs/reports/phase-0.md` | 本报告 |
| `README.md`、`.gitignore` | —— |

## 测试结果

```text
$ python3 -m pytest -q
3 passed
```

## 已验证平台

- 无。阶段 0 没有可运行的功能。锁定文件测试在 Ubuntu 24.04 x86_64、Python 3.13.18 上通过。

## 未验证项目

- 锁定文件中的 SHA-256 是从发布页转录的，没有对真实文件计算过（`hashes_verified = false`）。
- 所有 sing-box 字段和行为都来自文档，没有经过 `sing-box check`。具体清单见各 ADR 的「待验证」一节。
- Windows 相关的所有结论。

## 验收命令

```bash
cd norain
python3 -m pytest -q
ls docs/decisions/
grep -L '状态：提议' docs/decisions/0*.md   # 应无输出：全部为提议
```

## 回滚方式

阶段 0 只新增文件，不涉及系统。删除 `norain/` 目录即可完全回滚。
