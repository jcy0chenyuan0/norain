#!/usr/bin/env bash
# 从零把 norain-server 装到一台干净的 Linux 机器上：系统依赖 → 虚拟环境 → 包 → 安装。
#
#   sudo ./scripts/bootstrap-server.sh [norain-server install 的参数...]
#
# 环境变量：
#   NORAIN_VENV    虚拟环境目录（默认 /opt/norain-venv）
#   NORAIN_PKG     安装源（默认本脚本所在仓库；也可以写 git 地址或 PyPI 包名）
#   NORAIN_PYTHON  指定解释器（默认 python3）
#
# 幂等：已装好的依赖不会重复装，虚拟环境会复用。
set -euo pipefail

VENV="${NORAIN_VENV:-/opt/norain-venv}"
PY="${NORAIN_PYTHON:-python3}"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname -- "$HERE")"
PKG="${NORAIN_PKG:-$ROOT}"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行（安装 systemd 单元、写 /etc 需要权限）"
command -v "$PY" >/dev/null 2>&1 || die "找不到 $PY：先装 Python 3.11+ 再运行本脚本"

PYVER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "需要 Python >= 3.11，当前是 $("$PY" -V 2>&1)"

install_apt() {
  export DEBIAN_FRONTEND=noninteractive
  local pkgs=(python3 python3-pip)
  if apt-cache show "python3.${PYVER#*.}-venv" >/dev/null 2>&1; then
    pkgs+=("python3.${PYVER#*.}-venv")
  else
    pkgs+=("python3-venv")
  fi
  log "安装系统依赖：${pkgs[*]}"
  apt-get update -qq
  apt-get install -y -q "${pkgs[@]}"
}

ensure_prereqs() {
  if command -v apt-get >/dev/null 2>&1; then
    install_apt
  elif command -v dnf >/dev/null 2>&1; then
    log "安装系统依赖：python3 python3-pip"
    dnf install -y -q python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    log "安装系统依赖：python3 python3-pip"
    yum install -y -q python3 python3-pip
  elif command -v apk >/dev/null 2>&1; then
    log "安装系统依赖：python3 py3-pip"
    apk add --no-cache python3 py3-pip
  else
    log "没有识别到包管理器；跳过系统依赖（假定 Python/venv/pip 已就绪）"
  fi
  "$PY" -c 'import venv' 2>/dev/null || die "$PY 缺少 venv 模块，请先安装（例如 python3-venv）"
  "$PY" -m pip --version >/dev/null 2>&1 || die "$PY 缺少 pip，请先安装（例如 python3-pip）"
}

ensure_venv() {
  if [ ! -x "$VENV/bin/python" ]; then
    log "创建虚拟环境 $VENV"
    "$PY" -m venv "$VENV"
  else
    log "复用虚拟环境 $VENV"
  fi
  "$VENV/bin/pip" install -q --upgrade pip
}

log "安装源：$PKG"
ensure_prereqs
ensure_venv
log "安装 norain-server 到 $VENV"
"$VENV/bin/pip" install -q "$PKG"
command -v norain-server >/dev/null 2>&1 || ln -sf "$VENV/bin/norain-server" /usr/local/bin/norain-server

log "执行 norain-server install"
exec "$VENV/bin/norain-server" install "$@"
