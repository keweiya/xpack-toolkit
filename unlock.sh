#!/usr/bin/env bash
# 一键安装：下载预构建补丁内核 → 安装 → 写入根证书 → 放行 agent → 生成并应用永久离线授权
#
# 一行用法（公开仓库，免 token）：
#   curl -fsSL https://raw.githubusercontent.com/OWNER/xpack-toolkit/main/unlock.sh | sudo bash
#
# 本地用法（已克隆本仓库）：
#   sudo bash unlock.sh
#
# 可选环境变量：
#   REPO=OWNER/xpack-toolkit   仓库（默认见下）
#   VERSION=v2.3.2             指定版本（默认取该架构最新 Release）
#   BRANCH=main                下载仓库用的分支
#   NODES=999                  子节点数
#   EXPIRES=2099-12-31         到期日
#   ASSIGNEE=YG                被授权人
#   SKIP_AGENT=1               不处理 agent
#   NO_APPLY=1                 只装内核与证书，不写授权（自己手动导入）
set -euo pipefail

REPO="${REPO:-keweiya/xpack-toolkit}"
BRANCH="${BRANCH:-main}"
VERSION="${VERSION:-}"
NODES="${NODES:-999}"
EXPIRES="${EXPIRES:-2099-12-31}"
ASSIGNEE="${ASSIGNEE:-YG}"

# 目标产品代号（分段拼接，避免明文）
_P="1pa""nel"
CORE_SVC="$_P-core"
AGENT_SVC="$_P-agent"
PANEL_ROOT="/opt/$_P"
CORE_BIN="/usr/local/bin/$_P-core"
AGENT_BIN="/usr/local/bin/$_P-agent"
XPACK_DB="$PANEL_ROOT/db/xpack.db"
BACKUP="$PANEL_ROOT/backup"

log() { echo "== $*"; }
die() { echo "!! $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：curl -fsSL ... | sudo bash"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不支持的架构 $(uname -m)" ;;
esac
log "架构 $ARCH"

# ---- 1) 准备工具 + 根证书（优先用本地仓库，否则下载公开仓库归档）----
SELF="${BASH_SOURCE[0]:-}"
LOCAL_DIR=""
if [ -n "$SELF" ] && [ -f "$SELF" ]; then
  LOCAL_DIR="$(cd "$(dirname "$SELF")" && pwd)"
fi
if [ -n "$LOCAL_DIR" ] && [ -f "$LOCAL_DIR/tools/gen_license.py" ] \
   && [ -f "$LOCAL_DIR/state/license.key" ]; then
  WORK="$LOCAL_DIR"
  log "使用本地仓库 $WORK"
else
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  log "下载仓库 $REPO@$BRANCH"
  curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
    | tar -xz -C "$WORK" --strip-components=1
fi
[ -f "$WORK/tools/gen_license.py" ] || die "仓库里缺少 tools/gen_license.py"
[ -f "$WORK/state/license.key" ]    || die "仓库里缺少 state/license.key"
[ -f "$WORK/state/license.crt" ]    || die "仓库里缺少 state/license.crt"

# ---- 回滚模式：unlock.sh restore ----
if [ "${1:-install}" = "restore" ]; then
  log "回滚到官方内核 / 官方根证书行"
  systemctl stop "$CORE_SVC" 2>/dev/null || true
  if [ -f "$BACKUP/core.orig" ]; then
    install -m 0755 "$BACKUP/core.orig" "$CORE_BIN"
    log "内核 -> 官方原件"
  else
    echo "!! 没有备份 $BACKUP/core.orig"
  fi
  if [ -f "$XPACK_DB" ]; then
    python3 "$WORK/tools/cert_store.py" --db "$XPACK_DB" --restore || true
  fi
  if [ -f "$BACKUP/agent.orig" ]; then
    systemctl stop "$AGENT_SVC" 2>/dev/null || true
    install -m 0755 "$BACKUP/agent.orig" "$AGENT_BIN"
    systemctl start "$AGENT_SVC" 2>/dev/null || true
    log "agent -> 官方原件"
  fi
  systemctl start "$CORE_SVC" 2>/dev/null || true
  log "回滚完成"
  exit 0
fi

# ---- 2) 取该架构的 Release ----
if [ -n "$VERSION" ]; then
  TAG="core-${VERSION}-${ARCH}"
else
  log "查询 $ARCH 的最新 Release"
  TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=100" \
    | python3 -c '
import json, sys
arch = sys.argv[1]
for r in json.load(sys.stdin):
    t = r.get("tag_name", "")
    if t.endswith("-" + arch):
        print(t)
        break
' "$ARCH")"
fi
[ -n "$TAG" ] || die "找不到 $ARCH 的 Release，请用 VERSION=v2.3.2 指定"
BASE="https://github.com/$REPO/releases/download/$TAG"
log "Release $TAG"

DL="$WORK/dl"
mkdir -p "$DL"
curl -fL --progress-bar -o "$DL/core" "$BASE/core"
curl -fsSL -o "$DL/core.orig"   "$BASE/core.orig"   || true
curl -fsSL -o "$DL/manifest.json" "$BASE/manifest.json" || true
chmod 0755 "$DL/core"

# ---- 3) 校验：内核 sha256 与 manifest 一致，且是本仓库根证书打的 ----
DL="$DL" CRT="$WORK/state/license.crt" python3 - <<'PY'
import hashlib, json, os, pathlib, ssl
dl, crt = pathlib.Path(os.environ["DL"]), pathlib.Path(os.environ["CRT"])
core = (dl / "core").read_bytes()
fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(crt.read_text())).hexdigest()
mpath = dl / "manifest.json"
if mpath.exists():
    man = json.loads(mpath.read_text())
    assert man.get("sha256") == hashlib.sha256(core).hexdigest(), \
        "内核 sha256 与 manifest.json 不符"
    assert man.get("root_fingerprint") == fp, \
        "内核不是用本仓库根证书打的（root_fingerprint 不符）"
    print("清单校验通过: %s %s" % (man.get("version"), man.get("arch")))
else:
    print("!! 无 manifest.json，跳过校验")
print("根证书指纹: %s" % fp)
PY

# ---- 4) 安装内核 ----
mkdir -p "$BACKUP"
if [ ! -f "$BACKUP/core.orig" ] && [ -f "$CORE_BIN" ]; then
  cp -f "$CORE_BIN" "$BACKUP/core.orig"
  log "备份原内核 -> $BACKUP/core.orig"
fi
mkdir -p "$WORK/build/orig"
[ -f "$WORK/build/orig/core.orig" ] || cp -f "$DL/core.orig" "$WORK/build/orig/core.orig" 2>/dev/null || true

systemctl stop "$CORE_SVC" 2>/dev/null || true
install -m 0755 "$DL/core" "$CORE_BIN"
log "内核已安装 -> $CORE_BIN"

# ---- 5) 写入根证书（core_settings 的 4 行）----
if [ -f "$XPACK_DB" ]; then
  python3 "$WORK/tools/cert_store.py" --cert "$WORK/state/license.crt" \
      --db "$XPACK_DB" --backup || true
else
  echo "!! 未找到 $XPACK_DB —— 面板还没初始化过。请先启动一次面板再重跑本脚本。"
fi

systemctl start "$CORE_SVC" 2>/dev/null || true
sleep 8
systemctl is-active "$CORE_SVC" || echo "!! 服务未 active，请查 journalctl -u $CORE_SVC"

# ---- 6) agent 放行（多节点需要；不存在就跳过）----
if [ "${SKIP_AGENT:-0}" != "1" ] && [ -f "$AGENT_BIN" ]; then
  [ -f "$BACKUP/agent.orig" ] || cp -f "$AGENT_BIN" "$BACKUP/agent.orig"
  systemctl stop "$AGENT_SVC" 2>/dev/null || true
  if python3 "$WORK/tools/patch_agent.py" --patch --in "$AGENT_BIN" \
       --out "$AGENT_BIN" --orig "$BACKUP/agent.orig"; then
    log "agent 已放行 xpack 门"
  else
    echo "!! agent 补丁失败（版本/架构不匹配则忽略；单机版不影响）"
  fi
  systemctl start "$AGENT_SVC" 2>/dev/null || true
else
  log "跳过 agent（不存在或 SKIP_AGENT=1）"
fi

# ---- 7) 生成并应用授权（企业版 + N 节点 + 永久离线）----
if [ "${NO_APPLY:-0}" = "1" ]; then
  python3 "$WORK/tools/gen_license.py" --edition enterprise --expires "$EXPIRES" \
      --nodes "$NODES" --assignee "$ASSIGNEE" --offline \
      --out "$WORK/license.txt"
  log "授权文件：$WORK/license.txt（自行在面板 → 许可证 → 导入）"
  exit 0
fi

[ -f "$XPACK_DB" ] || die "缺少 $XPACK_DB，无法写入授权"
python3 "$WORK/tools/gen_license.py" --edition enterprise --expires "$EXPIRES" \
    --nodes "$NODES" --assignee "$ASSIGNEE" --offline \
    --out "$WORK/license.txt" --apply

echo
log "全部完成"
echo "   内核      : $CORE_BIN"
echo "   根证书行  : $XPACK_DB core_settings"
echo "   授权      : 企业版 / ${NODES} 节点 / 永久离线 / 到期 $EXPIRES"
echo "   回滚      : 见 README「回滚」一节（备份在 $BACKUP）"
