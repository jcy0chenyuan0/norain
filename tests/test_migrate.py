"""Schema 迁移的版本策略。对应 docs/decisions/0004 通用规则 1。

只测纯逻辑（字典进、字典出）和配置加载后的 warning 挂载，不碰真实 sing-box
和系统命令。
"""

import pytest

from norain_core.errors import NorainError
from norain_core.migrate import SCHEMA_VERSION, migrate

MINIMAL = {"proxy": {"server": "s.example", "credential_ref": "env:X"}}


def test_missing_schema_is_version_1_and_warns():
    result = migrate(MINIMAL, current=1, source="cfg.toml")
    assert result.data["schema"] == 1
    assert "schema" not in MINIMAL            # 输入字典不被就地修改
    assert len(result.warnings) == 1
    assert "缺少顶层 schema" in result.warnings[0]


def test_current_version_passes_through_without_warning():
    doc = {"schema": 1, "proxy": {"server": "s.example"}}
    result = migrate(doc, current=1)
    assert result.data is doc
    assert result.warnings == ()


def test_newer_version_is_rejected_before_field_validation():
    # 版本更高且带新字段：必须报「不支持的配置版本」，而不是「未知字段」
    with pytest.raises(NorainError) as e:
        migrate({"schema": 2, "unknown_field": 1}, current=1)
    assert [f.path for f in e.value.field_errors] == ["schema"]
    assert "不支持的配置版本 2" in e.value.field_errors[0].message


def test_negative_version_is_rejected():
    with pytest.raises(NorainError):
        migrate({"schema": -1}, current=1)


def test_non_integer_version_is_left_to_field_validation():
    result = migrate({"schema": "1"}, current=1)
    assert result.data["schema"] == "1"       # 不改写，交给 pydantic 报类型错误
    assert result.warnings == ()


def test_client_parse_attaches_migration_warning():
    from norain.model import parse, warnings_of

    cfg = parse({"proxy": {"server": "s.example", "credential_ref": "env:X"}})
    assert any("缺少顶层 schema" in w for w in warnings_of(cfg))


def test_client_migrate_doc_does_not_validate():
    from norain.model import migrate_doc

    doc = {"proxy": {"server": "s.example"}}
    result = migrate_doc(doc)
    assert result.data["schema"] == SCHEMA_VERSION
    assert "schema" not in doc


def test_server_load_config_attaches_migration_warning(tmp_path):
    from norain_core.migrate import migration_warnings
    from norain_server.model import load_config

    cfg_path = tmp_path / "server.toml"
    cfg_path.write_text('[server]\ndomain = "example.com"\n\n[auth]\ncredential_ref = "env:TEST_PASSWORD"\n\n[tls]\nmode = "self-signed"\n',
                        encoding="utf-8")
    cfg = load_config(cfg_path, env={})
    assert any("缺少顶层 schema" in w for w in migration_warnings(cfg))
