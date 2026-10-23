#!/usr/bin/env bash
# 1Panel v2 内网本地破解内核一键安装 / 更新。
#
# 新流程（不再需要本站签名私钥，也不再校验任何签名）：
#   1) 检测宿主机 1Panel 版本与 Release 最新发版；
#      若 Release 版本较新，先把宿主机 1Panel 升级到与 Release 一致（官方包升级）；
#   2) 从 Release 下载破解内核（已移除全部授权检查），替换官方/第三方内核；
#   3) 本地生成企业版授权证书（999 节点、永久有效、离线），导入 licenses 表并
#      绑定主节点；机器中既有证书一律保留不删除，若主节点已绑定则先解绑
#      （交互终端会提示确认，非交互默认自动解绑）。
#
# 已有安装直接重跑同一条命令即可，无需手动卸载。
set -euo pipefail
umask 077
REPO="${REPO:-keweiya/xpack-toolkit}"

PANEL_ROOT="${PANEL_ROOT:-/opt/1panel}"
CORE_BIN="${CORE_BIN:-/usr/local/bin/1panel-core}"
AGENT_BIN="${AGENT_BIN:-/usr/local/bin/1panel-agent}"
CORE_SVC="${CORE_SVC:-1panel-core}"
AGENT_SVC="${AGENT_SVC:-1panel-agent}"
XPACK_DB="${XPACK_DB:-$PANEL_ROOT/db/xpack.db}"
SERIAL_PATH="${SERIAL_PATH:-$PANEL_ROOT/db/.serial}"
BACKUP="${BACKUP:-$PANEL_ROOT/crack/backup}"
PERSIST="${UNLOCK_WORK:-$PANEL_ROOT/unlock}"
OFFICIAL_BASE="https://resource.fit2cloud.com/1panel/package/v2/stable"
MODE=install

log() { printf '== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }
trap 'printf "!! Failed; artifacts/backups retained: %s / %s\n" "$PERSIST" "$BACKUP" >&2' ERR

PROGRESS="${PROGRESS:-auto}"
STALL_SECONDS="${STALL_SECONDS:-30}"
STALL_BYTES="${STALL_BYTES:-1024}"
DL_MAX_TIME="${DL_MAX_TIME:-1800}"

progress_bar_enabled() {
  case "$PROGRESS" in
    on) return 0 ;;
    off) return 1 ;;
    auto) [ -t 2 ] ;;
    *) die "Invalid PROGRESS; expected auto, on or off" ;;
  esac
}

usage() {
  printf '%s\n' 'Usage: unlock.sh [install|restore|verify] [options]' \
    '  --use-mirror, --mirror auto  Measure built-in mirrors and use the fastest valid one' \
    '  --mirror URL                Use only the specified HTTP(S) GitHub gateway' \
    '  --no-mirror, --direct        Use GitHub directly, without mirror fallback' \
    '  --http-proxy URL            Set a local HTTP(S) network proxy for curl' \
    '  --progress / --no-progress  Force download progress on/off (default: auto)' \
    '  --skip-agent                Do not rebuild/replace the amd64 agent' \
    '  --prompt-unbind             Prompt before releasing an existing master binding' \
    '  --help                      Show this help'
}

CLI_ROUTE=""
SKIP_AGENT=0
PROMPT_UNBIND=0
MODE_SET=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    install|deploy|restore|verify)
      [ "$MODE_SET" = 0 ] || die "Specify only one operation"
      MODE="$1"; MODE_SET=1 ;;
    --use-mirror) CLI_ROUTE=auto ;;
    --mirror)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "--mirror requires auto or an HTTP(S) URL"
      CLI_ROUTE="$2"; shift ;;
    --mirror=*) CLI_ROUTE="${1#*=}"; [ -n "$CLI_ROUTE" ] || die "--mirror requires auto or an HTTP(S) URL" ;;
    --no-mirror|--direct) CLI_ROUTE=direct ;;
    --http-proxy)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "--http-proxy requires a proxy URL"
      export XPACK_HTTP_PROXY="$2"; shift ;;
    --http-proxy=*) export XPACK_HTTP_PROXY="${1#*=}"; [ -n "$XPACK_HTTP_PROXY" ] || die "--http-proxy requires a proxy URL" ;;
    --progress) PROGRESS=on ;;
    --no-progress) PROGRESS=off ;;
    --skip-agent) SKIP_AGENT=1 ;;
    --prompt-unbind) PROMPT_UNBIND=1 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; die "Unknown installation argument" ;;
  esac
  shift
done

MIRROR_CHOICE="${CLI_ROUTE:-${GH_PROXY:-https://ghfast.top/}}"
[ "$(id -u)" -eq 0 ] || die "Run as root"
[ "$(uname -s)" = Linux ] || die "This release provides Linux cores"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  armv7l) ARCH=armv7 ;; ppc64le|s390x|riscv64) ARCH="$(uname -m)" ;;
  *) die "Unknown architecture: $(uname -m)" ;;
esac
PLATFORM="linux-$ARCH"
PANEL_CTL="${PANEL_CTL:-/usr/local/bin/1pctl}"

# ---------------------------------------------------------------------------
# 镜像 / 下载
# ---------------------------------------------------------------------------
MIRROR_CONFIG="$(python3 - "$MIRROR_CHOICE" "${GH_MIRRORS-https://ghfast.top/ https://gh-proxy.com/ https://ghproxy.net/}" <<'PY'
import re, sys, urllib.parse
preferred, configured = sys.argv[1:]
if preferred == "direct":
    raise SystemExit(0)
if preferred == "auto":
    preferred = ""
seen = set()
for value in ([preferred] if preferred else re.split(r"[\s,]+", configured.strip())):
    if not value:
        continue
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment or any(ord(c) < 33 for c in value)):
        raise SystemExit("Invalid GitHub mirror prefix; expected an HTTP(S) URL without credentials/query/fragment")
    try:
        parsed.port
    except ValueError:
        raise SystemExit("Invalid GitHub mirror port")
    value = value.rstrip("/") + "/"
    if value not in seen:
        print(value)
        seen.add(value)
PY
)" || die "Invalid GitHub mirror configuration"

MIRRORS=()
MIRROR_READY=0
rank_mirrors() {
  python3 - "$REPO" "$MIRROR_CONFIG" <<'PY'
import concurrent.futures, json, math, os, pathlib, subprocess, sys, tempfile
repo, configured = sys.argv[1:]
prefixes = configured.splitlines()
probe_url = "https://api.github.com/repos/" + repo + "/releases?per_page=100"
def probe(item):
    index, prefix = item
    with tempfile.TemporaryDirectory(prefix="xpack-mirror-probe-") as directory:
        target = pathlib.Path(directory) / "releases.json"
        command = ["curl", "--proto", "=http,https", "--proto-redir", "=http,https",
                   "--tlsv1.2", "-fsSL", "--connect-timeout", "3", "--max-time", "12",
                   "--max-filesize", "2097152", "--write-out", "\n%{http_code}\t%{time_starttransfer}\n"]
        if os.environ.get("XPACK_HTTP_PROXY"):
            command += ["--proxy", os.environ["XPACK_HTTP_PROXY"]]
        command += ["-o", str(target), prefix + probe_url]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            status, measured = result.stdout.strip().split("\t")
            elapsed = float(measured)
            if result.returncode or status != "200" or not math.isfinite(elapsed) or not 0 < elapsed <= 12:
                return None
            data = json.loads(target.read_text())
            if (not isinstance(data, list) or not data or any(not isinstance(r, dict) or
                    not isinstance(r.get("tag_name"), str) or not isinstance(r.get("assets", []), list) for r in data)):
                return None
            return elapsed, index, prefix
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    ranked = sorted(item for item in pool.map(probe, enumerate(prefixes)) if item is not None)
if not ranked:
    raise SystemExit("No valid GitHub mirror responded; select --no-mirror or specify --mirror URL")
for elapsed, index, prefix in ranked:
    print(prefix)
    print("== Mirror " + prefix + " response latency: " + format(elapsed * 1000, ".1f") + " ms", file=sys.stderr)
PY
}
configure_mirrors() {
  [ "$MIRROR_READY" = 0 ] || return 0
  local RANKED="" PREFIX
  [ -n "$MIRROR_CHOICE" ] || MIRROR_CHOICE=auto
  case "$MIRROR_CHOICE" in
    direct) MIRRORS=(); log "GitHub download mode: direct (mirrors disabled)" ;;
    auto)
      [ -n "$MIRROR_CONFIG" ] || die "No mirror candidates configured"
      log "Measuring GitHub mirror response latency"
      RANKED="$(rank_mirrors)" || die "All mirror probes failed; no installation changes were made"
      while IFS= read -r PREFIX; do MIRRORS+=("$PREFIX"); done <<< "$RANKED"
      log "Selected lowest-latency GitHub mirror: ${MIRRORS[0]}" ;;
    *) MIRRORS=("$MIRROR_CONFIG"); log "Using user-specified GitHub mirror: ${MIRRORS[0]}" ;;
  esac
  MIRROR_READY=1
}
run_download() {
  local PART="$1" CANDIDATE="$2" PID STATUS=0 ELAPSED=0 SIZE=0 START NOW
  shift 2
  local -a BASE=(--proto '=http,https' --proto-redir '=http,https' --tlsv1.2 -fSL
                 --connect-timeout 10 --max-time "$DL_MAX_TIME"
                 --speed-limit "$STALL_BYTES" --speed-time "$STALL_SECONDS"
                 --retry 1 --retry-max-time 20)
  START="$(date +%s)"
  # 进度条保持在单行刷新（curl --progress-bar 自带 \r 回写），不额外打印心跳。
  if progress_bar_enabled; then
    curl "${BASE[@]}" --progress-bar "$@" -o "$PART" "$CANDIDATE" &
  else
    curl "${BASE[@]}" -s "$@" -o "$PART" "$CANDIDATE" 2> "$PART.log" &
  fi
  PID=$!
  wait "$PID" || STATUS=$?
  NOW="$(date +%s)"; ELAPSED=$((NOW - START)); [ "$ELAPSED" -gt 0 ] || ELAPSED=1
  SIZE="$(wc -c < "$PART" 2>/dev/null)" || SIZE=0
  if [ "$STATUS" = 0 ]; then
    printf '   ... %s bytes in %ss (%s B/s)\n' "${SIZE// /}" "$ELAPSED" "$(( ${SIZE// /} / ELAPSED ))" >&2
  else
    printf '!! transfer failed (curl exit %s) after %ss, %s bytes received\n' \
      "$STATUS" "$ELAPSED" "${SIZE// /}" >&2
  fi
  return "$STATUS"
}
run_download_silent() {
  # 工具脚本等小文件：完全静默，不打印进度条与完成信息。
  local PART="$1" CANDIDATE="$2" STATUS=0
  shift 2
  curl --proto '=http,https' --proto-redir '=http,https' --tlsv1.2 -fSL \
    --connect-timeout 10 --max-time "$DL_MAX_TIME" \
    --speed-limit "$STALL_BYTES" --speed-time "$STALL_SECONDS" \
    --retry 1 --retry-max-time 20 -s "$@" -o "$PART" "$CANDIDATE" 2> "$PART.log"
  STATUS=$?
  [ "$STATUS" = 0 ] || printf '!! transfer failed (curl exit %s): %s\n' "$STATUS" "${CANDIDATE##*/}" >&2
  return "$STATUS"
}
fetch() {
  local URL="$1" DEST="$2" SILENT="${3:-}" PREFIX CANDIDATE PART ERROR HOST ATTEMPT=0
  local -a ROUTES=("$URL") CURL_PROXY=() ORDER=()
  case "$URL" in
    https://github.com/*|https://raw.githubusercontent.com/*|https://api.github.com/*)
      configure_mirrors
      if [ "${#MIRRORS[@]}" -gt 0 ]; then
        ROUTES=()
        for PREFIX in "${MIRRORS[@]}"; do ROUTES+=("$PREFIX$URL"); done
        ROUTES+=("$URL")   # 镜像全挂时回落到直连，避免卡死在加速器上
      fi ;;
  esac
  [ -z "${XPACK_HTTP_PROXY:-}" ] || CURL_PROXY=(--proxy "$XPACK_HTTP_PROXY")
  for CANDIDATE in "${ROUTES[@]}"; do
    ATTEMPT=$((ATTEMPT + 1))
    PART="$(mktemp "$DEST.part.XXXXXX")"
    HOST="${CANDIDATE#*://}"; HOST="${HOST%%/*}"
    [ -n "$SILENT" ] || log "Downloading ${DEST##*/} from $HOST (route $ATTEMPT/${#ROUTES[@]})"
    if [ -n "$SILENT" ]; then
      run_download_silent "$PART" "$CANDIDATE" "${CURL_PROXY[@]}"
    else
      run_download "$PART" "$CANDIDATE" "${CURL_PROXY[@]}"
    fi
    if [ $? -eq 0 ]; then
      mv -f -- "$PART" "$DEST"
      if [ "$CANDIDATE" != "$URL" ]; then
        PREFIX="${CANDIDATE%"$URL"}"
        ORDER=("$PREFIX")
        for HOST in "${MIRRORS[@]}"; do [ "$HOST" = "$PREFIX" ] || ORDER+=("$HOST"); done
        MIRRORS=("${ORDER[@]}")
      fi
      return 0
    fi
    [ -n "$SILENT" ] || printf '!! Download route %s failed; trying next route\n' "$HOST" >&2
    rm -f -- "$PART" "$PART.log"
  done
  die "All download routes failed: ${DEST##*/}"
}
fetch_direct() {
  # 官方包不经过 GitHub 镜像；仅沿用代理。
  local URL="$1" DEST="$2" PART
  local -a CURL_PROXY=()
  [ -z "${XPACK_HTTP_PROXY:-}" ] || CURL_PROXY=(--proxy "$XPACK_HTTP_PROXY")
  PART="$(mktemp "$DEST.part.XXXXXX")"
  log "Downloading ${DEST##*/} from fit2cloud (direct)"
  run_download "$PART" "$URL" "${CURL_PROXY[@]}" || { rm -f -- "$PART" "$PART.log"; die "Download failed: ${DEST##*/}"; }
  mv -f -- "$PART" "$DEST"
}

# ---------------------------------------------------------------------------
# 版本检测 / Release 预检
# ---------------------------------------------------------------------------
detect_installed_version() {
  python3 - "$PANEL_ROOT" "$CORE_BIN" "$PANEL_CTL" <<'PY'
import pathlib, re, sqlite3, subprocess, sys
root, core, ctl = sys.argv[1:]
pattern = r"v?\d+\.\d+\.\d+"
def normalize(value):
    value = value.strip()
    return "v" + value.lstrip("v") if re.fullmatch(pattern, value) else None
version = None
db = pathlib.Path(root) / "db/core.db"
if db.is_file():
    try:
        with sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True) as con:
            rows = con.execute("select value from settings where key='SystemVersion'").fetchall()
        if len(rows) == 1:
            version = normalize(rows[0][0])
    except sqlite3.Error:
        pass
if not version and pathlib.Path(core).is_file():
    try:
        result = subprocess.run([core, "version"], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            found = re.findall(r"(?<![\w.])(" + pattern + r")(?![\w.])", result.stdout)
            versions = {normalize(item) for item in found}
            if len(versions) == 1:
                version = versions.pop()
    except (OSError, subprocess.TimeoutExpired):
        pass
if not version and pathlib.Path(ctl).is_file():
    text = pathlib.Path(ctl).read_text(errors="replace")
    matches = re.findall(r"(?m)^\s*ORIGINAL_VERSION\s*=\s*['\"]?(" + pattern + r")[ '\"\t]*$", text)
    versions = {normalize(item) for item in matches}
    if len(versions) == 1:
        version = versions.pop()
if not version:
    raise SystemExit("Installed panel version was not detected; no panel changes were made")
print(version)
PY
}

select_release() {
  # 选出最高稳定 Release，写出下载 URL 与版本号。
  python3 - "$RUN" "$PLATFORM" <<'PY'
import json, pathlib, re, sys
run, platform = pathlib.Path(sys.argv[1]), sys.argv[2]
def version(value):
    return tuple(map(int, value.lstrip("v").split(".")))
releases = []
for release in json.loads((run / "releases.json").read_text()):
    tag = release.get("tag_name", "")
    if release.get("draft") or release.get("prerelease") or not re.fullmatch(r"core-v\d+\.\d+\.\d+", tag):
        continue
    releases.append((version(tag[5:]), release))
if not releases:
    raise SystemExit("No stable project release is published")
target, release = max(releases, key=lambda item: item[0])
tag = release["tag_name"]
assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
needed = ("manifest.json", "core-" + platform, "core-" + platform + ".orig")
if not all(name in assets for name in needed):
    raise SystemExit("Unsupported: latest Release " + tag + " has no verified assets for " + platform)
(run / "manifest.url").write_text(assets["manifest.json"])
(run / "core.url").write_text(assets["core-" + platform])
(run / "orig.url").write_text(assets["core-" + platform + ".orig"])
# 预构建的破解 Agent：有就直接下载替换；老 Release 没有时才回落到本机现打
if "agent-" + platform in assets:
    (run / "agent.url").write_text(assets["agent-" + platform])
if "agent-" + platform + ".orig" in assets:
    (run / "agent.orig.url").write_text(assets["agent-" + platform + ".orig"])
(run / "release.tag").write_text(tag)
(run / "selected.version").write_text(tag[5:])
print("Release " + tag[5:] + " selected for " + platform)
PY
}

# ---------------------------------------------------------------------------
# 运行时工具：内核资产（core/agent/manifest）走 Release，脚本工具走 main 分支。
# 这样只改证书显示或安装脚本时无需重新发版，push 到 main 即生效。
# ---------------------------------------------------------------------------
TOOL_FILES="tools/gen_license.py tools/aes128.py tools/patch_core.py tools/gosym.py tools/patch_agent.py state/license.crt"

fetch_tool_files() {
  # 从 main 分支静默拉取工具脚本（不打印进度）。
  mkdir -p "$WORK/tools" "$WORK/state"
  local REL
  for REL in $TOOL_FILES; do
    fetch "https://raw.githubusercontent.com/$REPO/main/$REL" "$WORK/$REL" silent
  done
  # 语法自检，确保工具下载完整可用
  python3 -m py_compile "$WORK/tools/gen_license.py" "$WORK/tools/aes128.py" \
    "$WORK/tools/patch_core.py" "$WORK/tools/gosym.py" "$WORK/tools/patch_agent.py" \
    || die "Runtime tools failed to compile"
}

fetch_tools() {
  # 先校验内核 manifest 结构，再静默拉取工具脚本。
  python3 - "$RUN" "$PLATFORM" <<'PY'
import json, pathlib, sys
run, platform = pathlib.Path(sys.argv[1]), sys.argv[2]
m = json.loads((run / "manifest.json").read_text())
if m.get("schema_version") != 2 or m.get("name") != "xpack-toolkit" or m.get("mode") != "offline":
    raise SystemExit("Expected an offline schema-2 release manifest")
if platform not in m.get("platforms", {}):
    raise SystemExit("Release has no verified core for " + platform)
if (run / "release.tag").exists() and (run / "release.tag").read_text() != "core-" + m.get("version", ""):
    raise SystemExit("Release tag/version mismatch")
p = m["platforms"][platform]
if p.get("os") != "linux" or p.get("arch") != platform[6:] or p.get("core_asset") != "core-" + platform:
    raise SystemExit("Invalid platform declaration")
PY
  fetch_tool_files
  log "Fetched runtime tools from main branch"
}

# ---------------------------------------------------------------------------
# 1pctl 配置值保真
# ---------------------------------------------------------------------------
# 官方发行包里的 /usr/local/bin/1pctl 是「占位符模板」：BASE_DIR=directory、
# ORIGINAL_PORT=port、ORIGINAL_ENTRANCE=entrance、ORIGINAL_USERNAME=username、
# ORIGINAL_PASSWORD=password。官方 installer 安装时会用 sed 把这些占位符替换成
# 用户真实配置。unlock.sh 升级时若直接覆盖 1pctl 而不回填，core 会去读
# directory/1panel/tmp/.secret，agent 会把端口解析成字符串 "port"，两者都以
# exit 2 崩溃。因此覆盖前先提取旧 1pctl 的配置值，覆盖后原样回填。
CTL_CONFIG_KEYS="BASE_DIR ORIGINAL_PORT ORIGINAL_USERNAME ORIGINAL_PASSWORD ORIGINAL_ENTRANCE LANGUAGE PANEL_EDITION"

extract_ctl_config() {
  local SRC="$1" OUT="$2" KEY VALUE
  [ -f "$SRC" ] || return 1
  : > "$OUT"
  while IFS='=' read -r KEY VALUE; do
    case " $CTL_CONFIG_KEYS " in
      *" $KEY "*) printf '%s=%s\n' "$KEY" "$VALUE" >> "$OUT" ;;
    esac
  done < "$SRC"
  [ -s "$OUT" ]
}

apply_ctl_config() {
  local SAVED="$1"
  [ -f "$SAVED" ] || return 0
  python3 - "$PANEL_CTL" "$SAVED" <<'PY'
import re, sys
ctl, saved = sys.argv[1], sys.argv[2]
kv = {}
for line in open(saved, encoding="utf-8", errors="replace"):
    line = line.rstrip("\n")
    if "=" in line:
        k, v = line.split("=", 1)
        kv[k] = v
text = open(ctl, encoding="utf-8", errors="replace").read()
def repl(m):
    k = m.group(1)
    return "%s=%s" % (k, kv[k]) if k in kv else m.group(0)
open(ctl, "w", encoding="utf-8").write(re.sub(r"(?m)^([A-Z_][A-Z0-9_]*)=.*$", repl, text))
PY
}

upgrade_1pctl() {
  local SRCDIR="$1" CTL_CONFIG
  [ -f "$SRCDIR/1pctl" ] || return 0
  CTL_CONFIG="$(mktemp "${TMPDIR:-/tmp}/xpack-ctl.XXXXXX")"
  if extract_ctl_config "$PANEL_CTL" "$CTL_CONFIG"; then
    backup_binary "$PANEL_CTL" ctl
    install -m 0755 "$SRCDIR/1pctl" "$PANEL_CTL"
    apply_ctl_config "$CTL_CONFIG"
  else
    log "Could not read config from existing 1pctl; keeping it unchanged"
  fi
  rm -f "$CTL_CONFIG"
}

# ---------------------------------------------------------------------------
# 3.1 官方 1Panel 升级（仅当 Release 版本较新时）
# ---------------------------------------------------------------------------
update_panel() {
  local VERSION="$1" TARBALL DEST SRCDIR
  TARBALL="$RUN/1panel-$VERSION-$PLATFORM.tar.gz"
  fetch_direct "$OFFICIAL_BASE/$VERSION/release/1panel-$VERSION-$PLATFORM.tar.gz" "$TARBALL"
  SRCDIR="$RUN/official-$VERSION"
  mkdir -p "$SRCDIR"
  tar xzf "$TARBALL" -C "$SRCDIR" --strip-components=1
  [ -f "$SRCDIR/1panel-core" ] && [ -f "$SRCDIR/1panel-agent" ] || die "Official package lacks binaries"

  log "Upgrading 1Panel $INSTALLED_VERSION -> $VERSION (official package)"
  systemctl stop "$CORE_SVC" 2>/dev/null || true
  systemctl stop "$AGENT_SVC" 2>/dev/null || true
  backup_binary "$CORE_BIN" core
  backup_binary "$AGENT_BIN" agent

  install -m 0755 "$SRCDIR/1panel-core" "$CORE_BIN"
  install -m 0755 "$SRCDIR/1panel-agent" "$AGENT_BIN"
  upgrade_1pctl "$SRCDIR"
  if [ -f "$SRCDIR/GeoIP.mmdb" ]; then
    mkdir -p "$PANEL_ROOT/geo"
    install -m 0644 "$SRCDIR/GeoIP.mmdb" "$PANEL_ROOT/geo/GeoIP.mmdb"
  fi
  if [ -d "$SRCDIR/lang" ]; then cp -r "$SRCDIR/lang" /usr/local/bin/; fi

  systemctl start "$CORE_SVC"
  systemctl is-active --quiet "$CORE_SVC"
  systemctl start "$AGENT_SVC" 2>/dev/null || true
  log "1Panel upgraded to $VERSION; database migrations completed"
}

backup_binary() {
  local SRC="$1" NAME="$2" SUM
  [ -f "$SRC" ] || return 0
  SUM="$(sha256sum "$SRC")"; SUM="${SUM%% *}"
  mkdir -p "$BACKUP"
  install -m 0755 "$SRC" "$BACKUP/1panel-$NAME.$SUM"
  install -m 0755 "$SRC" "$BACKUP/1panel-$NAME.previous"
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
PREFLIGHT="$(mktemp -d "${TMPDIR:-/tmp}/xpack-preflight.XXXXXX")"
trap 'rm -rf -- "$PREFLIGHT"' EXIT
mkdir -p "$PERSIST" "$BACKUP"

if [ "$MODE" = restore ]; then
  CORE_ORIG="$BACKUP/1panel-core.previous"
  AGENT_ORIG="$BACKUP/1panel-agent.previous"
  [ -f "$CORE_ORIG" ] || die "Missing core rollback image: $CORE_ORIG"
  systemctl stop "$CORE_SVC" 2>/dev/null || true
  [ -f "$AGENT_ORIG" ] && systemctl stop "$AGENT_SVC" 2>/dev/null || true
  install -m 0755 "$CORE_ORIG" "$CORE_BIN"
  [ -f "$AGENT_ORIG" ] && install -m 0755 "$AGENT_ORIG" "$AGENT_BIN"
  CTL_ORIG="$BACKUP/1panel-ctl.previous"
  [ -f "$CTL_ORIG" ] && install -m 0755 "$CTL_ORIG" "$PANEL_CTL"
  systemctl start "$CORE_SVC"
  [ -f "$AGENT_ORIG" ] && { systemctl start "$AGENT_SVC"; systemctl is-active --quiet "$AGENT_SVC"; }
  systemctl is-active --quiet "$CORE_SVC"
  log "Restored previous 1Panel binaries (licenses in the database are untouched)"
  exit 0
fi

if [ "$MODE" = verify ]; then
  # 安装完成后下载内容已清理，这里重新静默拉取工具脚本用于校验。
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/xpack-verify.XXXXXX")"
  fetch_tool_files
  python3 "$WORK/tools/patch_core.py" --verify --in "$CORE_BIN" || die "Cracked kernel not detected"
  if [ -f "$PERSIST/license.status" ] && [[ "$(<"$PERSIST/license.status")" != applied ]]; then
    log "Components verified; license is pending import"
  else
    python3 "$WORK/tools/gen_license.py" --verify-db --db "$XPACK_DB" --serial-path "$SERIAL_PATH"
  fi
  systemctl is-active --quiet "$CORE_SVC"
  rm -rf -- "$WORK"
  log "Cracked kernel verified on $CORE_BIN"
  exit 0
fi

# install / deploy
INSTALLED_VERSION="$(detect_installed_version)"
log "Installed panel $INSTALLED_VERSION / $PLATFORM"

fetch "https://api.github.com/repos/$REPO/releases?per_page=100" "$PREFLIGHT/releases.json"
RUN="$(mktemp -d "$PERSIST/run.XXXXXX")"
cp "$PREFLIGHT/releases.json" "$RUN/releases.json"
RELEASE_LINE="$(select_release)"
log "$RELEASE_LINE"
RELEASE_VERSION="$(<"$RUN/selected.version")"

# 下载 manifest（内核资产）与工具脚本（main 分支）
fetch "$(<"$RUN/manifest.url")" "$RUN/manifest.json"
WORK="$(mktemp -d "$PERSIST/runtime.XXXXXX")"
fetch_tools

PATCH_CORE="$WORK/tools/patch_core.py"
PATCH_AGENT="$WORK/tools/patch_agent.py"
GEN_LICENSE="$WORK/tools/gen_license.py"

# 3.1 版本比较：Release 较新则先官方升级到一致版本
VERSION_STATE="$(python3 - "$INSTALLED_VERSION" "$RELEASE_VERSION" <<'PY'
import sys
def v(x): return tuple(map(int, x.lstrip("v").split(".")))
installed, release = v(sys.argv[1]), v(sys.argv[2])
if release < installed:
    raise SystemExit("Unsupported: project release is older than installed panel")
print("newer" if release > installed else "equal")
PY
)"
if [ "$VERSION_STATE" = newer ]; then
  update_panel "$RELEASE_VERSION"
else
  log "Installed panel is already at Release version $RELEASE_VERSION; skip official upgrade"
fi

# 3.1 从 Release 下载破解内核并校验
fetch "$(<"$RUN/core.url")" "$RUN/core"
python3 - "$RUN" "$PLATFORM" <<'PY'
import hashlib, json, pathlib, struct, sys
run, platform = pathlib.Path(sys.argv[1]), sys.argv[2]
man = json.loads((run / "manifest.json").read_text())
arch = platform[6:]
p = man["platforms"][platform]
data = (run / "core").read_bytes()
if p.get("sha256") != hashlib.sha256(data).hexdigest():
    raise SystemExit("Cracked core SHA-256 mismatch")
if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != {"amd64": 62, "arm64": 183}[arch]:
    raise SystemExit("Cracked core ELF architecture mismatch")
print("Verified cracked core sha256 + arch: " + p.get("sha256")[:16])
PY

# 校验下载来的内核确实「已移除全部检查」
python3 "$PATCH_CORE" --verify --in "$RUN/core" || die "Downloaded core is not the remove-all-checks kernel"

# Agent：优先用 Release 里已经打好补丁的二进制，装机器只校验 + 替换；
# 老 Release 没有预构建 Agent 时才回落到「官方原件 + 本机现打」。
NEED_AGENT=0
if [ "$SKIP_AGENT" != 1 ] && [ -f "$AGENT_BIN" ]; then NEED_AGENT=1; fi
AGENT_SOURCE=""
if [ "$NEED_AGENT" = 1 ]; then
  if [ -f "$RUN/agent.url" ]; then
    fetch "$(<"$RUN/agent.url")" "$RUN/agent"
    python3 - "$RUN" "$PLATFORM" <<'PYEOF' || die "Downloaded patched agent failed verification"
import hashlib, json, pathlib, struct, sys
run, platform = pathlib.Path(sys.argv[1]), sys.argv[2]
arch = platform[6:]
info = json.loads((run / "manifest.json").read_text())["platforms"][platform]
data = (run / "agent").read_bytes()
if info.get("agent_sha256") != hashlib.sha256(data).hexdigest():
    raise SystemExit("Patched agent SHA-256 mismatch")
if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != {"amd64": 62, "arm64": 183}[arch]:
    raise SystemExit("Patched agent ELF architecture mismatch")
print("Verified patched agent sha256 + arch: " + info["agent_sha256"][:16])
PYEOF
    AGENT_SOURCE="$RUN/agent"
    log "Using prebuilt patched $ARCH agent from Release"
  elif [ -f "$RUN/agent.orig.url" ]; then
    fetch "$(<"$RUN/agent.orig.url")" "$RUN/agent.orig"
    python3 "$PATCH_AGENT" --patch --in "$RUN/agent.orig" --out "$RUN/agent" \
      --orig "$RUN/agent.orig" --manifest "$RUN/agent.manifest.json"
    python3 "$PATCH_AGENT" --verify --in "$RUN/agent" --orig "$RUN/agent.orig"
    AGENT_SOURCE="$RUN/agent"
    log "Rebuilt $ARCH agent from verified official source"
  else
    die "Release has no agent asset for $PLATFORM"
  fi
fi

# 备份并替换内核
backup_binary "$CORE_BIN" core
[ -z "$AGENT_SOURCE" ] || backup_binary "$AGENT_BIN" agent
systemctl stop "$CORE_SVC"
[ -z "$AGENT_SOURCE" ] || systemctl stop "$AGENT_SVC"
install -m 0755 "$RUN/core" "$CORE_BIN"
[ -z "$AGENT_SOURCE" ] || install -m 0755 "$AGENT_SOURCE" "$AGENT_BIN"

# 3.2 本地生成企业版授权（999 节点 / 永久 / 离线）并绑定主节点
PROMPT_FLAGS=()
[ "$PROMPT_UNBIND" = 1 ] && PROMPT_FLAGS=(--prompt-unbind)
LICENSE_OUT="$RUN/license.txt"
python3 "$GEN_LICENSE" --edition enterprise --expires "${EXPIRES:-9999-12-31}" \
  --nodes "${NODES:-999}" --assignee "${ASSIGNEE:-YG}" --offline \
  --out "$LICENSE_OUT" --db "$XPACK_DB" --serial-path "$SERIAL_PATH"
python3 "$GEN_LICENSE" --import-file "$LICENSE_OUT" --apply --no-restart \
  --db "$XPACK_DB" --serial-path "$SERIAL_PATH" "${PROMPT_FLAGS[@]}"
printf 'applied\n' > "$PERSIST/license.status"

# 重启并回读验证
if [ -n "$AGENT_SOURCE" ]; then
  systemctl start "$AGENT_SVC"
  systemctl is-active --quiet "$AGENT_SVC"
fi
systemctl start "$CORE_SVC"
systemctl is-active --quiet "$CORE_SVC"
python3 "$PATCH_CORE" --verify --in "$CORE_BIN"
python3 "$GEN_LICENSE" --verify-db --db "$XPACK_DB" --serial-path "$SERIAL_PATH"

# 静默清理下载的临时内容（release 资产与工具脚本），退出前不残留运行目录。
rm -rf -- "$RUN" "$WORK" "$PREFLIGHT" 2>/dev/null || true

log "Kernel replaced (all license checks removed); enterprise license applied with main-node binding"
log "Third-party certificates preserved; any prior master binding was released first"
log "Downloaded artifacts cleaned up"
log "Rollback: bash unlock.sh restore (previous images: $BACKUP)"
