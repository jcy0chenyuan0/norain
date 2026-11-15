"""v0.2 新增模块里不依赖系统和网络的部分：监控判定表、去抖动、阻断放行范围的补集、
TOML 写出、协议选择、分流名单匹配。

注意：这些测试随代码一起写出，尚未执行过（用户要求先写理论代码，暂不测试）。
"""

import ipaddress
import tomllib

from norain import block
from norain.control import Selector
from norain.model import parse, split_entries
from norain.monitor import Debounce, Round, decide
from norain.routing import Learned, covered
from norain_core import tomlio


def rnd(dom, frn, d4="CN", p4="US", p6="US", dns=False):
    def loc(c):
        return {"ip": "x", "loc": c} if c else None
    return Round(at=0, domestic=[{"ok": x} for x in dom], foreign=[{"ok": x} for x in frn],
                 direct_v4=loc(d4), proxy_v4=loc(p4), proxy_v6=loc(p6), dns_home=dns)


def test_monitor_decision_table():
    T, F = True, False
    assert decide(rnd([T, T], [T, T]), "CN")[0] == 0
    assert decide(rnd([F, F], [F, F], d4=None, p4=None, p6=None), "CN")[0] == 100
    assert decide(rnd([T, T], [F, F], p4=None, p6=None), "CN")[0] == 600
    assert decide(rnd([T, F, F], [F, F, F], d4=None, p4=None, p6=None), "CN")[0] == 301
    assert decide(rnd([T, T], [T, T], p4="CN", p6="US"), "CN")[0] == 604
    assert decide(rnd([T, T], [T, T], p4="US", p6="CN"), "CN")[0] == 606
    assert decide(rnd([T, T], [T, T], p4="CN", p6="CN"), "CN")[0] == 400
    assert decide(rnd([T, T], [T, T], p4="CN", p6=None), "CN")[0] == 400
    assert decide(rnd([T, T], [T, T], dns=True), "CN")[0] == 401
    # 没有 IPv6 出口不算故障
    assert decide(rnd([T, T], [T, T], p6=None), "CN")[0] == 0


def test_debounce():
    d = Debounce(fail_n=3, ok_n=2)
    assert [d.feed(600) for _ in range(3)] == [False, False, True] and d.current == 600
    assert d.feed(0) is False and d.current == 600      # 一次正常不解除
    assert d.feed(0) is True and d.current == 0
    assert [d.feed(c) for c in (600, 400, 600)] == [False, False, False]  # 不连续的错误码不上报
    d.reset()
    assert d.current == 0


def test_block_complement_covers_everything_but_allowed():
    nets = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "192.0.2.7/32", "10.0.0.0/8")]
    ranges = block.complement(nets, 4)
    total = sum(int(ipaddress.ip_address(b)) - int(ipaddress.ip_address(a)) + 1 for a, b in ranges)
    assert total == 2 ** 32 - sum(n.num_addresses for n in nets)
    for a, b in ranges:  # 补集里不能包含任何放行地址
        for n in nets:
            assert not (int(ipaddress.ip_address(a)) <= int(n.network_address) <= int(ipaddress.ip_address(b)))
    assert block.complement([], 4) == [("0.0.0.0", "255.255.255.255")]


def test_tomlio_roundtrip():
    doc = {"schema": 1, "proxy": {"server": "a.b", "tls": {"insecure": False}, "hysteria2": {"port": 443}},
           "routing": {"proxy_domains": ["x.com", 'q"uote'], "update_interval_hours": 1.5}}
    assert tomllib.loads(tomlio.dumps(doc)) == doc
    tomlio.set_path(doc, "dns.mode", "split")
    assert tomlio.get_path(doc, "dns.mode") == "split"
    assert tomlio.parse_value("443") == 443 and tomlio.parse_value("true") is True
    assert tomlio.parse_value("example.com") == "example.com"
    assert tomlio.parse_value('["a", "b"]') == ["a", "b"]


def test_list_entries_and_coverage():
    assert split_entries(["Example.com", "full:a.b", "10.0.0.0/8", "1.2.3.4"]) == {
        "domain": ["a.b"], "domain_suffix": ["example.com"], "ip_cidr": ["10.0.0.0/8", "1.2.3.4"]}
    assert covered("www.example.com", ["example.com"]) and covered("example.com", ["example.com"])
    assert not covered("notexample.com", ["example.com"])
    assert covered("a.b", ["full:a.b"]) and not covered("x.a.b", ["full:a.b"])
    assert Learned().for_generator() == {"proxy": [], "direct": [], "hosts": {}}


def test_protocol_selection(tmp_path):
    from norain.paths import Paths
    cfg = parse({"proxy": {"protocol": "auto", "server": "s.example", "credential_ref": "env:X"}})
    paths = Paths.from_env({"NORAIN_HOME": str(tmp_path), "NORAIN_STATE": str(tmp_path)}, platform="posix")
    sel = Selector(cfg, paths, log=None)
    # 当前协议连续失败、另一个可用 → 立即切换
    sel.fail_streak["hysteria2"] = 3
    sel.samples["trojan"].append(80.0)
    assert sel.decide("hysteria2")[0] == "trojan"
    # 延迟差距不够大 → 保持
    sel.fail_streak["hysteria2"] = 0
    for p, ms in (("hysteria2", 120.0), ("trojan", 100.0)):
        sel.samples[p].clear()
        sel.samples[p].extend([ms] * 3)
    assert sel.decide("hysteria2")[0] is None
    # 差到 1.3 倍且超过 100 ms → 切换
    sel.samples["hysteria2"].clear()
    sel.samples["hysteria2"].extend([400.0] * 3)
    assert sel.decide("hysteria2")[0] == "trojan"
    # 冷却期内不切换
    import time
    sel.switched_at = time.time()
    assert sel.decide("hysteria2") == (None, "冷却中")
