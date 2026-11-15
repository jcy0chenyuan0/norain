"""两个实测缺陷的回归测试：rule-set match 的二进制格式，以及系统代理快照还原。

2026-11-15 用真实 sing-box 1.14.4 测出：
* `rule-set match` 不带 `-f binary` 时对 .srs 直接 FATAL，Geo 永远拿不到结论；
  命中输出 "match rules.[0]: ..."，未命中输出为空且 exit 0。
* sing-box 的 set_system_proxy 被硬杀时不还原、正常退出也不回填 ProxyServer。

测试进程里有 NORAIN_NO_SYSTEM_CHANGES=1，sysproxy 的 supported() 为 False，
所以这里全部用 monkeypatch 替换注册表读写。
"""

import subprocess
from pathlib import Path

import pytest

import norain_core.sysproxy as sp
from norain.proxy import ProxyModule
from norain.rules import Geo
from norain.paths import Paths


def make_paths(tmp_path: Path, name: str = "geosite-cn") -> Paths:
    state = tmp_path / "state"
    (state / "rules").mkdir(parents=True)
    (state / "rules" / f"{name}.srs").write_bytes(b"\x00binary")
    return Paths(tmp_path, tmp_path / "cfg.toml", state, state / "log", False, None, "nt")


def geo_with(tmp_path, monkeypatch, *, rc: int, stdout: str = "", stderr: str = "", suffix: str = ".srs"):
    state = tmp_path / "state"
    (state / "rules").mkdir(parents=True, exist_ok=True)
    rs = state / "rules" / f"geosite-cn{suffix}"
    rs.write_bytes(b"rule-set")
    paths = Paths(tmp_path, tmp_path / "cfg.toml", state, state / "log", False, None, "nt")
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append([str(a) for a in args])
        return subprocess.CompletedProcess(args, rc, stdout, stderr)

    monkeypatch.setattr("norain.rules.osutil.run", fake_run)
    return Geo(Path("sing-box.exe"), paths), calls


def test_rule_set_match_uses_binary_format(tmp_path, monkeypatch):
    geo, calls = geo_with(tmp_path, monkeypatch, rc=0,
                          stdout="match rules.[0]: domain/domain_suffix=<binary> domain_regex=[x]")
    assert geo.domain_is_home("baidu.com") is True
    assert calls and calls[0][3:5] == ["-f", "binary"], calls


def test_rule_set_empty_output_means_no_match(tmp_path, monkeypatch):
    geo, _ = geo_with(tmp_path, monkeypatch, rc=0, stdout="")
    assert geo.domain_is_home("openai.com") is False


def test_rule_set_failure_is_unknown(tmp_path, monkeypatch):
    geo, _ = geo_with(tmp_path, monkeypatch, rc=1, stderr="FATAL unexpected end of JSON comment")
    assert geo.domain_is_home("baidu.com") is None


def test_rule_set_unrecognised_output_is_unknown(tmp_path, monkeypatch):
    geo, _ = geo_with(tmp_path, monkeypatch, rc=0, stdout="something new from sing-box")
    assert geo.domain_is_home("baidu.com") is None


def test_missing_rule_set_is_unknown(tmp_path, monkeypatch):
    """规则集文件还没下载：不调用 sing-box，直接返回不知道（不能当成“境外”）。"""
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):  # pragma: no cover - 不应该被调用
        calls.append([str(a) for a in args])
        return subprocess.CompletedProcess(args, 0, "", "")

    paths = Paths(tmp_path, tmp_path / "cfg.toml", tmp_path / "state", tmp_path / "log", False, None, "nt")
    monkeypatch.setattr("norain.rules.osutil.run", fake_run)
    assert Geo(Path("sing-box.exe"), paths).domain_is_home("baidu.com") is None
    assert calls == []


# ---- 系统代理快照 -------------------------------------------------------------

ORIGINAL = {"ProxyEnable": 0, "ProxyServer": "127.0.0.1:1082",
            "ProxyOverride": "*zhihu.com;localhost", "AutoConfigURL": None}


@pytest.fixture
def registry(monkeypatch):
    """内存里的假注册表；返回记录写入的列表。"""
    live = dict(ORIGINAL)
    writes: list[dict] = []

    def fake_read():
        return dict(live)

    def fake_write(values):
        writes.append(dict(values))
        live.update({k: v for k, v in values.items() if v is not None})
        return True

    monkeypatch.setattr(sp, "read", fake_read)
    monkeypatch.setattr(sp, "write", fake_write)
    monkeypatch.setattr(sp, "notify", lambda: None)
    return live, writes


def test_snapshot_is_restored_after_singbox_clobbers_registry(tmp_path, registry):
    live, writes = registry
    path = tmp_path / "sysproxy.json"
    module = ProxyModule(lambda: None, sysproxy_state=path)

    module._save_snapshot()
    assert path.exists()
    live.update({"ProxyEnable": 1, "ProxyServer": "http://127.0.0.1:18086"})  # sing-box 干的事

    module._restore_snapshot()
    assert writes[-1]["ProxyEnable"] == 0
    assert writes[-1]["ProxyServer"] == "127.0.0.1:1082"
    assert not path.exists()


def test_stale_snapshot_is_restored_before_start(tmp_path, registry):
    live, writes = registry
    path = tmp_path / "sysproxy.json"
    sp.save(path, dict(ORIGINAL))                      # 启动前的原样
    live.update({"ProxyEnable": 1, "ProxyServer": "http://127.0.0.1:18086"})   # sing-box 写的

    ProxyModule(lambda: None, sysproxy_state=path)._restore_stale()
    assert writes and writes[-1]["ProxyEnable"] == 0
    assert not path.exists()


def test_failed_start_does_not_leave_the_registry_changed(tmp_path, registry):
    live, writes = registry
    path = tmp_path / "sysproxy.json"

    def boom():
        raise RuntimeError("spec failed")

    module = ProxyModule(boom, sysproxy_state=path)
    with pytest.raises(RuntimeError):
        module.start()
    assert writes and not path.exists()


def test_no_snapshot_without_system_proxy_mode(tmp_path, registry):
    live, writes = registry
    module = ProxyModule(lambda: None, sysproxy_state=None)
    module._save_snapshot()
    module._restore_snapshot()
    assert writes == []
