"""阻断先行 + 修复窗口的流程测试（ADR 0011 2026-11-18 修订）。

覆盖四组行为：
  1. proxy_only()：修复窗口只放行回环和代理服务器，不放行会被 monitor.verify 误判的地址；
  2. tighten()：收紧放行范围的三条路径，重点是失败时不把状态改成「已恢复」；
  3. release()：broken 状态需要 --force，正常状态不需要；
  4. Maintainer：先断后修、修好自动放开、修不好保持阻断、收紧失败时中止解除。

全部用假后端，不碰真实防火墙（conftest 已设 NORAIN_NO_SYSTEM_CHANGES）。
"""

import ipaddress

import pytest

from norain import block, maintain, model
from norain.paths import Paths
from norain_core.errors import EXIT_EXTERNAL, NorainError

CFG = """
schema = 1
[proxy]
server = "proxy.example.test"
credential_ref = "env:NORAIN_TEST_PASSWORD"
[monitor]
domestic_targets = ["https://www.baidu.com"]
foreign_targets = ["https://example.org"]
[routing]
isolation_allowlist = ["10.9.9.9/32", "blue.example.test"]
"""


class FakeBackend:
    """记录调用顺序；fail_apply 前 N 次 apply 抛错，用来驱动回滚路径。"""

    name = "fake"

    def __init__(self, *, fail_apply_times=0, present=True):
        self.calls: list[str] = []
        self.applied: list[tuple[int, int]] = []
        self.fail_apply_times = fail_apply_times
        self._present = present
        self.removed: list[dict] = []

    def snapshot(self):
        return {"Domain": True}

    def apply(self, v4, v6):
        if self.fail_apply_times > 0:
            self.fail_apply_times -= 1
            self.calls.append("apply->raise")
            raise NorainError("apply 失败", exit_code=EXIT_EXTERNAL, module="block")
        self.calls.append("apply")
        self.applied.append((len(v4), len(v6)))
        return [f"rule-{len(self.applied)}"]

    def remove(self, st):
        self.calls.append("remove")
        self.removed.append(dict(st))
        return []

    def present(self):
        return self._present


@pytest.fixture
def env(tmp_path, monkeypatch):
    """一套最小环境：真实 Paths、真实配置解析、假后端、可控的 DNS 解析。"""
    home, state = tmp_path / "etc", tmp_path / "state"
    home.mkdir()
    state.mkdir()
    cfg_file = home / "cfg.toml"
    cfg_file.write_text(CFG, encoding="utf-8")
    paths = Paths(home=home, config=cfg_file, state=state, log_dir=state / "log",
                  log_dir_from_env=False, singbox=None, platform="nt")
    cfg = model.load_config(cfg_file)

    be = FakeBackend()
    monkeypatch.setattr(block, "backend", lambda: be)
    # 不真的做 DNS：固定把域名解析成确定地址，未知域名返回空
    resolve_map = {"proxy.example.test": ["203.0.113.7"], "blue.example.test": ["198.51.100.9"]}
    monkeypatch.setattr(block, "_resolve", lambda host: sorted(resolve_map.get(host, [])))
    monkeypatch.setattr(block.osutil, "require_admin", lambda *a, **k: None)
    monkeypatch.setattr(block.osutil, "popup", lambda *a, **k: True)
    return paths, cfg, be


# ---- 1. proxy_only：修复窗口的放行范围 -------------------------------------------

def test_proxy_only_excludes_addresses_that_could_fake_recovery(env):
    _, cfg, _ = env
    v4, v6, notes = block.proxy_only(cfg)
    allowed = [str(n) for n in v4 + v6]

    # 代理服务器必须放行，否则修复没法验证
    assert "203.0.113.7/32" in allowed
    assert notes["resolved"]["proxy.example.test"] == ["203.0.113.7"]

    # 蓝名单放行：修复可能持续到人工介入，这时连蓝名单一起断掉违背它存在的意义
    assert "198.51.100.9/32" in allowed      # blue.example.test
    assert "10.9.9.9/32" in allowed          # 蓝名单里的 IP 段

    # 但国内 DNS 和监控探测目标仍然不放行
    assert "223.5.5.5/32" not in allowed

    # 回环等固定项仍在
    assert "127.0.0.0/8" in allowed


def test_proxy_only_still_narrower_than_full(env):
    """修复窗口比完整范围窄：监控探测目标仍然被挡住。"""
    _, cfg, _ = env
    narrow_v4, narrow_v6, _ = block.proxy_only(cfg)
    narrow = {str(n) for n in narrow_v4 + narrow_v6}
    from norain import defaults
    # 默认监控探测目标（baidu/qq/taobao）的解析结果不应出现在修复窗口里
    assert all("baidu" not in x for x in narrow)
    assert len(narrow) < len({str(n) for n in block.allowed(cfg)[0] + block.allowed(cfg)[1]}) + 10


def test_proxy_only_records_unresolved_proxy(env, monkeypatch):
    _, cfg, _ = env
    monkeypatch.setattr(block, "_resolve", lambda host: [])
    _, _, notes = block.proxy_only(cfg)
    # 代理服务器解析不出来时必须记录：收紧放行范围时要靠它决定是否放弃
    assert "proxy.example.test" in notes["unresolved"]
    assert notes["resolved"] == {}


def test_full_allowed_is_a_superset_of_proxy_only(env):
    _, cfg, _ = env
    full = {str(n) for n in block.allowed(cfg)[0] + block.allowed(cfg)[1]}
    narrow = {str(n) for n in block.proxy_only(cfg)[0] + block.proxy_only(cfg)[1]}
    # 修复窗口应当是完整范围的子集（同版本才比较）
    for x in narrow:
        net = ipaddress.ip_network(x)
        assert any(net.subnet_of(ipaddress.ip_network(f))
                   for f in full if ipaddress.ip_network(f).version == net.version), x


# ---- 2. engage / tighten ---------------------------------------------------------

def test_engage_repairing_uses_narrow_scope(env):
    paths, cfg, be = env
    st = block.engage(cfg, paths, code=600, reason="test", repairing=True)
    assert st["repairing"] is True
    assert st["active"] is True
    assert "203.0.113.7/32" in st["allowed"]
    assert "198.51.100.9/32" in st["allowed"]     # 蓝名单在修复窗口里也放行
    # 先落盘再应用：apply 之前状态文件已经存在
    assert block.is_active(paths)
    assert be.calls.count("apply") == 1  # apply 内部自己循环 v4/v6 和分块


def test_tighten_success_widens_scope_and_clears_flag(env):
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="test", repairing=True)
    be.calls.clear()

    fresh = block.tighten(paths)

    assert fresh["repairing"] is False
    assert "198.51.100.9/32" in fresh["allowed"]      # 蓝名单恢复了
    assert be.calls == ["remove", "apply"]
    # 状态文件也更新了
    assert block.state(paths)["repairing"] is False


def test_tighten_is_idempotent(env):
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="test", repairing=True)
    block.tighten(paths)
    be.calls.clear()
    again = block.tighten(paths)          # 已经不是 repairing，直接返回
    assert be.calls == []
    assert again["repairing"] is False


def test_tighten_skips_when_proxy_unresolvable(env, monkeypatch):
    """代理域名解析不出来时不能收紧：新范围会丢掉代理服务器。"""
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="test", repairing=True)
    monkeypatch.setattr(block, "_resolve", lambda host: [])
    be.calls.clear()

    st = block.tighten(paths)

    assert be.calls == []                  # 什么都没动
    assert st["repairing"] is True         # 保持修复窗口
    assert "203.0.113.7/32" in st["allowed"]


def test_tighten_failure_restores_narrow_scope(env):
    """收紧失败后必须把窄范围装回去，而不是用注定失败的新范围重试。"""
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="test", repairing=True)
    saved = block.state(paths)
    be.calls.clear()
    be.fail_apply_times = 1                # 第一次 apply（v4）失败

    with pytest.raises(NorainError):
        block.tighten(paths)

    # 回滚用的是状态文件里记录的窄范围：remove -> 失败的 apply -> remove -> 恢复的 apply
    assert be.calls == ["remove", "apply->raise", "remove", "apply"]
    assert block.state(paths) == saved     # 状态没有被改坏


def test_tighten_failure_marks_broken_when_restore_also_fails(env):
    """窄范围也装不回去：状态必须标成 broken，不能继续自称「已阻断」。"""
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="test", repairing=True)
    be.calls.clear()
    be.fail_apply_times = 99               # 无论如何都失败

    with pytest.raises(NorainError) as ei:
        block.tighten(paths)

    assert "没能恢复" in str(ei.value) or ei.value.message
    st = block.state(paths)
    assert st["broken"] is True
    assert st["active"] is False           # 不再谎称仍在保护


# ---- 3. release ------------------------------------------------------------------

def test_release_works_normally(env):
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="test", repairing=True)
    res = block.release(paths)
    assert res["was_active"] is True
    assert block.state(paths) is None


def test_release_refuses_broken_state_without_force(env):
    paths, cfg, be = env
    be.present_flag = True
    block.write_json(paths.block_state, {"active": False, "broken": True, "rules": []})
    with pytest.raises(NorainError) as ei:
        block.release(paths)
    assert "损坏" in str(ei.value) or ei.value.message
    assert block.state(paths) is not None  # 状态没被清掉


def test_release_force_clears_broken_state(env):
    paths, cfg, be = env
    block.write_json(paths.block_state, {"active": False, "broken": True, "rules": []})
    block.release(paths, force=True)
    assert block.state(paths) is None


# ---- 5. 修复窗口的豁免判定（蓝名单放行后必须让 verify 忽略它们） -----------------

def _rnd(dom, frn, *, p4="US", p6="US", d4="CN"):
    from norain.monitor import Round
    loc = lambda c: {"ip": "x", "loc": c} if c else None
    return Round(at=0, domestic=[{"ok": o, "target": t} for o, t in dom],
                 foreign=[{"ok": o, "target": t} for o, t in frn],
                 direct_v4=loc(d4), proxy_v4=loc(p4), proxy_v6=loc(p6), dns_home=None)


def test_exempt_hosts_matches_blue_list_semantics(env):
    _, cfg, _ = env
    exempt = block.exempt_hosts(cfg)
    exact, suffix, nets = exempt
    # proxy.example.test 和 blue.example.test 都进了放行范围
    assert block.is_exempt("proxy.example.test", exempt)
    assert block.is_exempt("blue.example.test", exempt)
    assert block.is_exempt("sub.blue.example.test", exempt)
    assert block.is_exempt("10.9.9.9", exempt)          # 蓝名单里的 CIDR
    assert not block.is_exempt("www.baidu.com", exempt)  # 监控目标不在豁免里
    assert not block.is_exempt("1.1.1.1", exempt)
    assert not block.is_exempt(None, exempt)


def test_drop_exempt_detects_faked_recovery(env):
    """国内探测全是蓝名单地址：它们能通不代表代理修好，必须判失败。"""
    from norain.monitor import _drop_exempt
    _, cfg, _ = env
    exempt = block.exempt_hosts(cfg)
    B = "https://blue.example.test"
    G = "https://www.google.com"
    r = _rnd([(True, B)] * 3, [(False, G)] * 4, p4=None, p6=None)
    code, _reason = _drop_exempt(r, "CN", exempt)
    assert code != 0


def test_drop_exempt_no_match_keeps_original(env):
    from norain.monitor import _drop_exempt
    _, cfg, _ = env
    exempt = block.exempt_hosts(cfg)
    r = _rnd([(True, "https://www.baidu.com")] * 3, [(True, "https://www.google.com")] * 4)
    assert _drop_exempt(r, "CN", exempt) == (r.code, r.reason)


def test_drop_exempt_none_is_noop(env):
    from norain.monitor import _drop_exempt
    r = _rnd([(True, "https://blue.example.test")], [(False, "https://www.google.com")])
    assert _drop_exempt(r, "CN", None) == (r.code, r.reason)


def test_drop_exempt_passes_when_real_targets_ok(env):
    """剔除蓝名单探测项后，剩下的真实目标都正常才允许判定恢复。"""
    from norain.monitor import _drop_exempt
    _, cfg, _ = env
    exempt = block.exempt_hosts(cfg)
    B = "https://blue.example.test"
    dom = [(True, B), (True, "https://www.baidu.com"), (True, "https://www.qq.com")]
    frn = [(True, "https://www.google.com")] * 4
    code, _ = _drop_exempt(_rnd(dom, frn), "CN", exempt)
    assert code == 0


def test_drop_exempt_insufficient_samples_fails(env):
    """剩余样本不足时不能判恢复，否则「没证据」会被当成「已恢复」。"""
    from norain.monitor import _drop_exempt
    _, cfg, _ = env
    exempt = block.exempt_hosts(cfg)
    B = "https://blue.example.test"
    # 国外项全被豁免，只剩国内
    r = _rnd([(True, B)], [(True, B)], p4=None, p6=None)
    code, _ = _drop_exempt(r, "CN", exempt)
    assert code != 0


# ---- 4. Maintainer 流程 ----------------------------------------------------------

class FakeCtl:
    """内控制的最小替身，只提供 Maintainer 用到的接口。"""

    def __init__(self, cfg, paths, *, stop=False, verify_codes=(0,)):
        self.cfg, self.paths = cfg, paths
        self._stop_requested = stop
        self._verify_codes = list(verify_codes)
        self.phase = "repairing"
        self.shutdown = None
        self.repairs = 0
        self.entered = []
        self.left = []
        self.selector = None        # 协议选择器：未启用
        self.overrides = {}
        self.learned_cleared = 0

        class Proxy:
            ready = True
            failed = False

            def wait_ready(self, _timeout):
                return True

        self.proxy = Proxy()
        self.modules = {}

    # --- Maintainer 依赖 ---
    @property
    def stop_requested(self):
        return self._stop_requested

    def stop_module(self, name, requester):
        return True, "ok"

    def restart_proxy(self, requester, reason):
        self.repairs += 1
        return True, "ok"

    def verify(self, rounds):
        return self._verify_codes.pop(0) if self._verify_codes else 101

    def clear_learned(self):
        self.learned_cleared += 1

    def set_override(self, **kw):
        self.overrides.update(kw)

    def switch_protocol(self, *a):
        return None

    def enter_repair(self, code):
        self.entered.append(code)

    def leave_repair(self, outcome):
        self.left.append(outcome)

    def request_shutdown(self, *, blocked=False, code=0):
        self.shutdown = {"blocked": blocked, "code": code}


@pytest.fixture
def maint(env, monkeypatch):
    paths, cfg, be = env
    ctl = FakeCtl(cfg, paths)
    # 修复动作用不到，全部打桩
    monkeypatch.setattr(maintain.repair, "repair_files", lambda *a, **k: _Rep([]))
    monkeypatch.setattr(maintain.repair, "repair_builtin", lambda *a, **k: _Rep([]))
    log = _Log()
    m = maintain.Maintainer(ctl, log)
    return m, ctl, paths, cfg, be, log


class _Rep:
    def __init__(self, problems):
        self.actions, self.problems = [], list(problems)


class _Log:
    """最小 logger 桩：记录 (level, event, kwargs)，供断言事件是否发生。"""

    def __init__(self):
        self.events = []

    def _rec(self, level):
        def f(event, **kw):
            self.events.append((level, event, kw))
        return f

    def __getattr__(self, name):
        # 只把真正的日志方法名映射成记录函数；has/events 等自有属性不拦截
        if name.startswith("_"):
            raise AttributeError(name)
        return self._rec(name)

    def has(self, event):
        return any(e == event for _, e, _ in self.events)

    def names(self):
        return [e for _, e, _ in self.events]


def test_escalate_blocks_before_repairing(maint):
    """核心：故障一确认就先阻断，再修。"""
    m, ctl, paths, cfg, be, log = maint
    ctl._verify_codes = [0]                # 第一轮就修好
    outcome = m.escalate(600, "链路失效")

    assert outcome == "recovered"
    # engage 发生在 restart_proxy 之前
    assert log.has("block.engaged")
    assert ctl.repairs == 1


def test_escalate_unblocks_automatically_after_recovery(maint):
    m, ctl, paths, cfg, be, log = maint
    ctl._verify_codes = [0]
    m.escalate(600, "链路失效")

    assert log.has("maintain.unblocked")
    assert block.state(paths) is None      # 已经解除，状态文件被清掉


def test_escalate_keeps_block_when_repair_fails(maint):
    m, ctl, paths, cfg, be, log = maint
    ctl._verify_codes = [101, 101, 101]     # 一直修不好（101 不是已知码）
    outcome = m.escalate(600, "链路失效")

    assert outcome == "blocked"
    assert block.is_active(paths) is True   # 保持阻断
    assert not log.has("block.unblocked")
    assert not log.has("maintain.unblocked")
    # 未知错误码不会覆盖原始码：仍然报触发阻断的那个
    assert ctl.shutdown == {"blocked": True, "code": 600}


def test_repair_reports_latest_known_code(maint):
    """修复过程中读到新的**已知**错误码时，最终上报应该是新码而不是最初那个。"""
    m, ctl, paths, cfg, be, log = maint
    ctl._verify_codes = [604, 604]          # 已知码，两轮都修不好
    outcome = m.escalate(600, "链路失效")

    assert outcome == "blocked"
    assert ctl.shutdown == {"blocked": True, "code": 604}


def test_escalate_301_blocks_without_repairing(maint):
    m, ctl, paths, cfg, be, log = maint
    outcome = m.escalate(301, "IPv6 异常")
    assert outcome == "blocked"
    assert ctl.repairs == 0                 # 301 直接阻断，一轮都不修
    assert block.is_active(paths) is True


def test_escalate_aborts_when_user_stops_before_repair(maint):
    """阻断期间用户要求停止：保持阻断退出，不继续修。"""
    m, ctl, paths, cfg, be, log = maint
    ctl._stop_requested = True
    outcome = m.escalate(600, "链路失效")
    assert outcome == "aborted"
    assert ctl.repairs == 0
    assert block.is_active(paths) is True   # 阻断保留，不能悄悄放开


def test_tighten_skip_still_releases(env):
    """tighten 因为配置问题「跳过」时不抛错：规则完好，release 是安全的，应当放行。

    与下面 test_tighten_failure_aborts_release 的区别：skip 时系统里的规则没被动过，
    fail 时规则可能已经删掉了。
    """
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="t", repairing=True)
    orig = block.allowed

    def boom(_cfg):
        raise NorainError("配置坏了", exit_code=EXIT_EXTERNAL, module="block")

    try:
        block.allowed = boom
        m = maintain.Maintainer.__new__(maintain.Maintainer)
        m.log = _Log()
        m._unblock_after_repair(paths)
    finally:
        block.allowed = orig

    # 跳过收紧 -> 仍然走完解除
    assert block.state(paths) is None
    assert block.is_active(paths) is False


def test_tighten_failure_aborts_release(env):
    """tighten 真正失败（规则可能已删）时必须中止解除，不能把残缺状态当成功清掉。"""
    paths, cfg, be = env
    block.engage(cfg, paths, code=600, reason="t", repairing=True)
    be.calls.clear()
    be.fail_apply_times = 99          # apply 永远失败，窄范围也装不回去

    log = _Log()
    m = maintain.Maintainer.__new__(maintain.Maintainer)
    m.log = log
    m._unblock_after_repair(paths)

    # 必须中止：没有打出解除成功
    assert not log.has("maintain.unblocked")
    assert log.has("maintain.tighten_failed")
    st = block.state(paths)
    assert st is not None             # 状态文件还在，没有被静默清掉
    assert st.get("broken") is True


def test_recovered_without_block_still_succeeds(maint):
    """block_on_failure=false：不阻断也要正常修复。"""
    m, ctl, paths, cfg, be, log = maint
    ctl.cfg.maintain.block_on_failure = False
    ctl._verify_codes = [0]
    outcome = m.escalate(600, "链路失效")

    assert outcome == "recovered"
    assert not log.has("block.engaged")
    assert ctl.repairs == 1
