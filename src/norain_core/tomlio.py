"""最小的 TOML 写出器（标准库只有读取）。只支持 Norain 配置用到的类型：
字符串、整数、浮点数、布尔、标量列表、表、表数组。注释不会保留，改写前调用方要先备份。"""

from __future__ import annotations

import json
import re

_BARE = re.compile(r"^[A-Za-z0-9_-]+$")


def _key(k: str) -> str:
    return k if _BARE.match(k) else json.dumps(k, ensure_ascii=False)


def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)  # JSON 字符串转义是 TOML 基本字符串的子集
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_scalar(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{_key(k)} = {_scalar(x)}" for k, x in v.items()) + " }"
    raise TypeError(f"TOML 不支持的类型：{type(v).__name__}")


def _is_table_array(v) -> bool:
    return isinstance(v, list) and bool(v) and all(isinstance(x, dict) for x in v)


def _emit(table: dict, prefix: str, out: list[str]) -> None:
    for k, v in table.items():
        if v is None or isinstance(v, dict) or _is_table_array(v):
            continue
        out.append(f"{_key(k)} = {_scalar(v)}")
    for k, v in table.items():
        name = f"{prefix}.{_key(k)}" if prefix else _key(k)
        if isinstance(v, dict):
            out.append("")
            out.append(f"[{name}]")
            _emit(v, name, out)
        elif _is_table_array(v):
            for item in v:
                out.append("")
                out.append(f"[[{name}]]")
                _emit(item, name, out)


def dumps(doc: dict) -> str:
    out: list[str] = []
    _emit(doc, "", out)
    return "\n".join(out).strip("\n") + "\n"


def parse_value(text: str):
    """把命令行上的值按 TOML 字面量解析；不是合法字面量时当作字符串。"""
    import tomllib
    try:
        return tomllib.loads(f"v = {text}")["v"]
    except tomllib.TOMLDecodeError:
        return text


def set_path(doc: dict, dotted: str, value) -> None:
    keys = dotted.split(".")
    node = doc
    for k in keys[:-1]:
        nxt = node.setdefault(k, {})
        if not isinstance(nxt, dict):
            raise KeyError(dotted)
        node = nxt
    node[keys[-1]] = value


def get_path(doc: dict, dotted: str, default=None):
    node = doc
    for k in dotted.split("."):
        if not isinstance(node, dict) or k not in node:
            return default
        node = node[k]
    return node
