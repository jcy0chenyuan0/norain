"""版本号一致性：三个包的 __version__ 必须与 pyproject 声明一致。"""

import pathlib
import tomllib

from norain import __version__ as client_version
from norain_core import __version__ as core_version
from norain_server import __version__ as server_version


def test_all_versions_match_pyproject():
    root = pathlib.Path(__file__).resolve().parents[1]
    declared = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert client_version == core_version == server_version == declared
