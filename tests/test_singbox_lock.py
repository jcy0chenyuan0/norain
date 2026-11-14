"""阶段 0 唯一的自动化测试：保证 sing-box 锁定文件结构有效、版本固定。"""

import re
import tomllib
from pathlib import Path

LOCK = Path(__file__).resolve().parents[1] / "third_party" / "singbox.lock.toml"
REQUIRED_TARGETS = {"linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"}


def load():
    with LOCK.open("rb") as f:
        return tomllib.load(f)["singbox"]


def test_version_is_pinned_stable():
    sb = load()
    assert re.fullmatch(r"\d+\.\d+\.\d+", sb["version"]), "必须是确切的 x.y.z 版本"
    assert sb["channel"] == "stable"
    assert "latest" not in sb["release_url"]


def test_assets_cover_targets_and_have_sha256():
    sb = load()
    assets = sb["assets"]
    assert REQUIRED_TARGETS <= set(assets)
    for target, asset in assets.items():
        assert sb["version"] in asset["file"], target
        assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), target


def test_hash_verification_flag_present():
    # 阶段 1 复核后改为 True；在此之前安装器必须拒绝使用这些摘要以外的任何来源。
    assert isinstance(load()["hashes_verified"], bool)
