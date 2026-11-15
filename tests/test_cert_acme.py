"""ACME 前置条件检查：80/tcp 被占用时的分级。对应 docs/decisions/0015 的修订。

用 monkeypatch 顶替 `_port80_busy`，测试不去真的绑定 80 端口。
"""

import pytest

from norain_core.errors import BIZ_CERT, NorainError
from norain_server import cert

TAGS = frozenset({"with_acme"})


@pytest.fixture
def port80_busy(monkeypatch):
    monkeypatch.setattr(cert, "_port80_busy", lambda: True)


def test_port80_busy_without_fallback_is_error(port80_busy, tmp_path):
    st = cert.acme_status("example.test", tmp_path, tags=TAGS, service_running=False)
    assert not st.ok
    assert any("80/tcp" in e for e in st.errors)


def test_port80_busy_with_tls_alpn01_is_only_warning(port80_busy, tmp_path):
    st = cert.acme_status("example.test", tmp_path, tags=TAGS, service_running=False,
                          tls_alpn01=True)
    assert st.ok
    assert any("TLS-ALPN-01" in w for w in st.warnings)
    assert not any("80/tcp" in e for e in st.errors)


def test_port80_free_is_not_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(cert, "_port80_busy", lambda: False)
    st = cert.acme_status("example.test", tmp_path, tags=TAGS, service_running=False)
    assert st.ok
    assert not any("已被其他程序占用" in w for w in st.warnings)


def test_running_service_skips_port80_probe(port80_busy, tmp_path):
    # 服务在跑时 80/tcp 由 sing-box 自己持有，不能算冲突
    st = cert.acme_status("example.test", tmp_path, tags=TAGS, service_running=True)
    assert st.ok
    assert not any("已被其他程序占用" in e for e in st.errors)


def test_raise_for_mode_reports_acme_precondition_not_cert(port80_busy, tmp_path):
    st = cert.acme_status("example.test", tmp_path, tags=TAGS, service_running=False)
    with pytest.raises(NorainError) as e:
        cert.raise_for_mode("acme", st)
    assert e.value.business_code == BIZ_CERT
    assert "ACME 前置条件不满足" in e.value.message
    assert "自签" not in e.value.hint          # 不再给 manual 模式的建议
