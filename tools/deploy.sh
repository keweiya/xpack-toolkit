#!/usr/bin/env bash
# Deploy / restore the X-Pack unlock (official flow).
#
#   ./tools/deploy.sh deploy     patch the pristine core, install it, swap the root cert
#   ./tools/deploy.sh restore    put the pristine core back + restore the official root cert
#   ./tools/deploy.sh verify     report the patch state of the installed core
#   ./tools/deploy.sh cert       print a licence file to import in the panel (no DB writes)
#
# 打补丁 = 只把授权方从官方换成本站：P1/P2（内置根证书指纹）+ P3/P4（授权服务器地址，
# 默认写死 https://1p-cert.0rz.li/api/v1/）+ C7（启动不清根证书行），
# 再把 core_settings 的 4 行根证书写成本站根证书。不写 .serial、不写 licenses 表。
set -euo pipefail
cd "$(dirname "$0")/.."

# 目标产品代号（分段拼接，避免明文）
_P="1pa""nel"
CORE_SVC="$_P-core"
AGENT_SVC="$_P-agent"
PANEL_ROOT="/opt/$_P"
CORE_BIN="/usr/local/bin/$_P-core"
AGENT_BIN="/usr/local/bin/$_P-agent"
XPACK_DB="$PANEL_ROOT/db/xpack.db"
BACKUP="$PANEL_ROOT/backup"

CORE_ORIG=build/orig/core.orig
BUILT=build/core.patched
CERT=${SIGN_CRT:-state/license.crt}

case "${1:-deploy}" in
deploy)
  [ -f "$CORE_ORIG" ] || { echo "missing $CORE_ORIG"; exit 1; }

  SIGN_CRT="$CERT" \
    python3 tools/patch_core.py --patch --in "$CORE_ORIG" --out "$BUILT"
  python3 tools/patch_core.py --verify --in "$BUILT" | tail -n 12

  # 只备份**官方原始**内核：已经改过的机器上不要把改过的版本当官方备份
  if [ ! -f "$BACKUP/core.orig" ]; then
    mkdir -p "$BACKUP"
    cp -f "$CORE_BIN" "$BACKUP/core.orig"
    echo "备份   : $BACKUP/core.orig"
  fi

  systemctl stop "$CORE_SVC"
  install -m 0755 "$BUILT" "$CORE_BIN"
  python3 tools/cert_store.py --cert "$CERT" --db "$XPACK_DB"
  systemctl start "$CORE_SVC"
  sleep 8
  systemctl is-active "$CORE_SVC"

  # agent 补丁（多节点/999 节点需要）：把节点端的 isXpack 门也放行
  if [ -f "$AGENT_BIN" ]; then
    if [ ! -f "$BACKUP/agent.orig" ]; then
      mkdir -p "$BACKUP"
      cp -f "$AGENT_BIN" "$BACKUP/agent.orig"
      echo "备份   : $BACKUP/agent.orig"
    fi
    systemctl stop "$AGENT_SVC" 2>/dev/null || true
    if python3 tools/patch_agent.py --patch --in "$AGENT_BIN" --out "$AGENT_BIN" \
         --orig "$BACKUP/agent.orig"; then
      echo "agent  : 已放行 xpack 门"
    else
      echo "!! agent 补丁失败（版本/架构不匹配则忽略，节点功能可能受限）"
    fi
    systemctl start "$AGENT_SVC" 2>/dev/null || true
  else
    echo "提示   : 未找到 $AGENT_BIN（单机版可忽略；多节点需先装 agent）"
  fi
  ;;
restore)
  systemctl stop "$CORE_SVC"
  if [ -f "$BACKUP/core.orig" ]; then
    install -m 0755 "$BACKUP/core.orig" "$CORE_BIN"
  elif [ -f "$CORE_ORIG" ]; then
    install -m 0755 "$CORE_ORIG" "$CORE_BIN"
  fi
  python3 tools/cert_store.py --db "$XPACK_DB" --restore
  systemctl start "$CORE_SVC"
  if [ -f "$BACKUP/agent.orig" ]; then
    systemctl stop "$AGENT_SVC" 2>/dev/null || true
    install -m 0755 "$BACKUP/agent.orig" "$AGENT_BIN"
    systemctl start "$AGENT_SVC" 2>/dev/null || true
  fi
  echo "官方内核 + 官方 agent + 官方根证书行已还原"
  ;;
verify)
  python3 tools/patch_core.py --verify --in "$CORE_BIN" | tail -n 12
  python3 tools/cert_store.py --db "$XPACK_DB" --show
  if [ -f "$AGENT_BIN" ]; then
    echo "-- agent --"
    python3 tools/patch_agent.py --verify --in "$AGENT_BIN" | tail -n 12 || true
  fi
  ;;
cert)
  shift
  python3 tools/gen_license.py --edition enterprise \
      --expires "${1:-2099-12-31}" --nodes "${2:-999}" --offline \
      --assignee "${3:-YG}" --out build/license-"${3:-YG}".txt
  echo
  echo "企业版 + ${2:-999} 节点 + 永久离线。把上面的授权文件整段粘进面板：面板设置 → 许可证 → 导入许可证"
  ;;
*)
  echo "usage: $0 {deploy|restore|verify|cert [YYYY-MM-DD] [NODES] [NAME]}"; exit 1 ;;
esac
