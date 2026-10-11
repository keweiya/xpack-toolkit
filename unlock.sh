#!/usr/bin/env bash
# Verified offline reinstall. Only use local signing keys; never download keys.
# STATE/SIGN_KEY: local material. LICENSE_FILE/--license-file: pre-issued signed license.
# A project-signed license is required for activation: without one the run stops before
# any binary is replaced unless --no-license (ALLOW_PENDING=1) is given explicitly.
# ARTIFACT_DIR: local Release. NO_APPLY: persist license for manual import.
set -euo pipefail
umask 077
REPO="${REPO:-keweiya/xpack-toolkit}"

PANEL_ROOT="${PANEL_ROOT:-/opt/1panel}"
CORE_BIN="${CORE_BIN:-/usr/local/bin/1panel-core}"
AGENT_BIN="${AGENT_BIN:-/usr/local/bin/1panel-agent}"
CORE_SVC="${CORE_SVC:-1panel-core}"
AGENT_SVC="${AGENT_SVC:-1panel-agent}"
XPACK_DB="${XPACK_DB:-$PANEL_ROOT/db/xpack.db}"
BACKUP="${BACKUP:-$PANEL_ROOT/crack/backup}"
PERSIST="${UNLOCK_WORK:-$PANEL_ROOT/unlock}"
MODE=install
log() { printf '== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }
trap 'printf "!! Failed; artifacts/backups retained: %s / %s\n" "$PERSIST" "$BACKUP" >&2' ERR
# Download visibility: a stalled route is aborted and reported instead of hanging.
PROGRESS="${PROGRESS:-auto}"                 # auto (terminal bar / log heartbeat) | on | off
HEARTBEAT_SECONDS="${HEARTBEAT_SECONDS:-5}"  # log heartbeat interval
STALL_SECONDS="${STALL_SECONDS:-30}"         # curl aborts a route slower than STALL_BYTES for this long
STALL_BYTES="${STALL_BYTES:-1024}"           # average speed floor in bytes per second
DL_MAX_TIME="${DL_MAX_TIME:-1800}"           # per-route ceiling for the large core/agent files
progress_bar_enabled() {
  case "$PROGRESS" in
    on) return 0 ;;
    off) return 1 ;;
    auto) [ -t 2 ] ;;
    *) die "Invalid PROGRESS; expected auto, on or off" ;;
  esac
}
usage() {
  printf '%s\n' 'Usage: unlock.sh [install|restore|verify|cert] [options]' \
    '  --use-mirror, --mirror auto  Measure built-in mirrors and use the fastest valid one' \
    '  --mirror URL                Use only the specified HTTP(S) GitHub gateway' \
    '  --no-mirror, --direct        Use GitHub directly, without mirror fallback' \
    '  --http-proxy URL            Set a local HTTP(S) network proxy for curl' \
    '  --progress / --no-progress  Force download progress on/off (default: auto)' \
    '  --replace-foreign           Replace a third-party authorization with ours (archive first)' \
    '  --keep-foreign              Keep third-party certificates and license rows untouched' \
    '  --license-file PATH         Project-signed license to activate (same as LICENSE_FILE)' \
    '  --no-license                Install components only, leave the panel inactive (no activation)' \
    '  --help                      Show this help'
}
CLI_ROUTE=""
FOREIGN_CHOICE=""
FOREIGN_MODE=keep
FOREIGN_PRESENT=0
GEN_REPLACE_FLAGS=()
MODE_SET=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    install|deploy|restore|verify|cert)
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
    --replace-foreign) FOREIGN_CHOICE=replace ;;
    --keep-foreign) FOREIGN_CHOICE=keep ;;
    --progress) PROGRESS=on ;;
    --no-progress) PROGRESS=off ;;
    --license-file)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "--license-file requires a path"
      LICENSE_FILE="$2"; shift ;;
    --license-file=*) LICENSE_FILE="${1#*=}"; [ -n "$LICENSE_FILE" ] || die "--license-file requires a path" ;;
    --no-license) ALLOW_PENDING=1 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; die "Unknown installation argument" ;;
  esac
  shift
done
MIRROR_CHOICE="${CLI_ROUTE:-${GH_PROXY:-}}"
# Validate the authorization choice before any network call or persistent write.
FOREIGN_CHOICE="${FOREIGN_CHOICE:-${FOREIGN_LICENSE:-}}"
case "$FOREIGN_CHOICE" in
  ""|replace|keep) ;;
  *) die "Invalid FOREIGN_LICENSE; expected replace or keep" ;;
esac
FOREIGN_MODE="${FOREIGN_CHOICE:-keep}"
# Activation needs a project-signed license; --no-license/ALLOW_PENDING=1 opts out.
ALLOW_PENDING="${ALLOW_PENDING:-0}"
case "$ALLOW_PENDING" in 0|1) ;; *) die "Invalid ALLOW_PENDING; expected 0 or 1" ;; esac
# Where an already-issued .lic may be found when LICENSE_FILE is not given.
LICENSE_SEARCH_DIRS="${LICENSE_SEARCH_DIRS:-$PWD:$HOME:$PANEL_ROOT/crack:$PANEL_ROOT/unlock:/opt/1panel/crack:/root:/tmp}"
[ "$(id -u)" -eq 0 ] || die "Run as root"
[ "$(uname -s)" = Linux ] || die "This release provides Linux cores"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  armv7l) ARCH=armv7 ;; ppc64le|s390x|riscv64) ARCH="$(uname -m)" ;;
  *) die "Unknown architecture: $(uname -m)" ;;
esac
PLATFORM="linux-$ARCH"
PANEL_CTL="${PANEL_CTL:-/usr/local/bin/1pctl}"
# Public gateways receive public GitHub URLs only; never local signing material.
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
  local ANSWER="" RANKED="" PREFIX
  if [ -z "$MIRROR_CHOICE" ]; then
    MIRROR_CHOICE=direct
    # The controlling terminal is separate from stdin, including curl | bash.
    if { exec 3<>/dev/tty; } 2>/dev/null; then
      printf '是否使用内置 GitHub 镜像？[y/N]（启用后自动选择延迟最低的有效镜像）：' >&3
      if IFS= read -r ANSWER <&3; then
        case "$ANSWER" in y|Y|yes|YES|1) MIRROR_CHOICE=auto ;; esac
      fi
      exec 3>&-
    fi
  fi
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
validate_download() {
  python3 - "$1" "$2" "$PLATFORM" <<'PY'
import hashlib, json, os, pathlib, re, ssl, sys
candidate, destination, platform = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
name = destination.name
if not candidate.is_file() or candidate.stat().st_size == 0:
    raise SystemExit("Empty download")
if name in ("releases.json", "manifest.json"):
    with candidate.open() as stream:
        data = json.load(stream)
    if name == "releases.json":
        if not isinstance(data, list) or any(not isinstance(r, dict) or
                not isinstance(r.get("tag_name"), str) or
                not isinstance(r.get("assets", []), list) for r in data):
            raise SystemExit("Expected GitHub release-list JSON, not a gateway page")
    else:
        if (not isinstance(data, dict) or data.get("schema_version") != 2 or
                data.get("name") != "xpack-toolkit" or data.get("mode") != "offline" or
                data.get("remote_base") != "" or not isinstance(data.get("platforms"), dict) or
                platform not in data["platforms"] or not isinstance(data.get("runtime"), dict)):
            raise SystemExit("Expected an offline schema-2 unified release manifest")
        tag = destination.with_name("release.tag")
        if tag.is_file() and tag.read_text() != "core-" + str(data.get("version", "")):
            raise SystemExit("Release tag/version mismatch")
        declared = data.get("root_fingerprint")
        if not isinstance(declared, str) or not re.fullmatch(r"[0-9a-f]{64}", declared):
            raise SystemExit("Invalid manifest signing root")
        cert = os.environ.get("SIGN_CRT")
        expected_root = "cb8cc410354dbbda7b542c952a8c8ffb47a0f3d886c7e7273c89cb7a44156030" if not cert else None
        if cert and pathlib.Path(cert).is_file():
            expected_root = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pathlib.Path(cert).read_text())).hexdigest()
        if expected_root is not None and declared != expected_root:
            raise SystemExit("Manifest signing root mismatch")
        meta = data["platforms"][platform]
        if (not isinstance(meta, dict) or meta.get("os") != "linux" or
                meta.get("arch") != platform[6:] or meta.get("patches") != 3 or
                meta.get("core_asset") != "core-" + platform or
                meta.get("orig_asset") != "core-" + platform + ".orig"):
            raise SystemExit("Invalid platform declaration")
        for entry, hash_key, size_key in ((data["runtime"], "sha256", "size"),
                                         (meta, "sha256", "size"), (meta, "orig_sha256", "orig_size")):
            value = entry.get(hash_key)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise SystemExit("Invalid manifest download hash")
            size = entry.get(size_key)
            if size is not None and (type(size) is not int or size < 1):
                raise SystemExit("Invalid manifest download size")
        if data["runtime"].get("asset") != "runtime.tar.gz" or type(data["runtime"].get("size")) is not int:
            raise SystemExit("Invalid runtime declaration")
    raise SystemExit(0)
if name in ("runtime.tar.gz", "core", "core.orig", "agent.orig"):
    manifest = json.loads(destination.with_name("manifest.json").read_text())
    platform_meta = manifest["platforms"][platform]
    if name == "runtime.tar.gz":
        expected, size = manifest["runtime"]["sha256"], manifest["runtime"]["size"]
    elif name == "agent.orig":
        expected, size = platform_meta["agent_orig_sha256"], platform_meta["agent_orig_size"]
    else:
        expected = platform_meta["sha256" if name == "core" else "orig_sha256"]
        size = platform_meta.get("size" if name == "core" else "orig_size", platform_meta.get("size"))
    digest = hashlib.sha256()
    with candidate.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or digest.hexdigest() != expected:
        raise SystemExit("Download SHA-256 mismatch: " + name)
    if size is not None and candidate.stat().st_size != size:
        raise SystemExit("Download size mismatch: " + name)
PY
}
fetch() {
  local URL="$1" DEST="$2" PREFIX CANDIDATE PART ERROR HOST ATTEMPT=0
  local -a ROUTES=("$URL") CURL_PROXY=() ORDER=()
  case "$URL" in
    https://github.com/*|https://raw.githubusercontent.com/*|https://api.github.com/*)
      configure_mirrors
      if [ "${#MIRRORS[@]}" -gt 0 ]; then
        ROUTES=()
        for PREFIX in "${MIRRORS[@]}"; do ROUTES+=("$PREFIX$URL"); done
      fi ;;
  esac
  [ -z "${XPACK_HTTP_PROXY:-}" ] || CURL_PROXY=(--proxy "$XPACK_HTTP_PROXY")
  for CANDIDATE in "${ROUTES[@]}"; do
    ATTEMPT=$((ATTEMPT + 1))
    PART="$(mktemp "$DEST.part.XXXXXX")"
    ERROR="$PART.log"
    HOST="${CANDIDATE#*://}"; HOST="${HOST%%/*}"
    log "Downloading ${DEST##*/} from $HOST (route $ATTEMPT/${#ROUTES[@]})"
    if run_download "$PART" "$CANDIDATE" "${CURL_PROXY[@]}" \
      && validate_download "$PART" "$DEST" 2>> "$ERROR"; then
      mv -f -- "$PART" "$DEST"
      rm -f -- "$ERROR"
      if [ "$CANDIDATE" != "$URL" ]; then
        PREFIX="${CANDIDATE%"$URL"}"
        ORDER=("$PREFIX")
        for HOST in "${MIRRORS[@]}"; do [ "$HOST" = "$PREFIX" ] || ORDER+=("$HOST"); done
        MIRRORS=("${ORDER[@]}")
      fi
      return 0
    fi
    printf '!! Download route %s failed or returned invalid data; trying next route\n' "$HOST" >&2
    [ ! -s "$ERROR" ] || tail -n 3 "$ERROR" | sed 's/^/   /' >&2
    rm -f -- "$PART" "$ERROR"
  done
  die "All download routes failed: ${DEST##*/}"
}
run_download() {
  # Curl in the background with a heartbeat so a stalled transfer is visible.
  local PART="$1" CANDIDATE="$2" PID STATUS=0 ELAPSED=0 SIZE=0 START NOW RATE
  shift 2
  local -a BASE=(--proto '=http,https' --proto-redir '=http,https' --tlsv1.2 -fSL
                 --connect-timeout 10 --max-time "$DL_MAX_TIME"
                 --speed-limit "$STALL_BYTES" --speed-time "$STALL_SECONDS"
                 --retry 1 --retry-max-time 20)
  START="$(date +%s)"
  if progress_bar_enabled; then
    # A live progress bar needs curl's own stderr, so -s is dropped on a terminal.
    curl "${BASE[@]}" --progress-bar "$@" -o "$PART" "$CANDIDATE" &
  else
    curl "${BASE[@]}" -s "$@" -o "$PART" "$CANDIDATE" 2> "$PART.log" &
  fi
  PID=$!
  while kill -0 "$PID" 2>/dev/null; do
    # Quarter-second slices: a fast transfer never waits for the next heartbeat.
    for _ in $(seq 1 $((HEARTBEAT_SECONDS * 4))); do
      kill -0 "$PID" 2>/dev/null || break 2
      sleep 0.25 || true
    done
    ELAPSED=$((ELAPSED + HEARTBEAT_SECONDS))
    SIZE="$(wc -c < "$PART" 2>/dev/null)" || SIZE=0
    RATE=$(( ${SIZE// /} / ELAPSED ))
    printf '   ... still downloading: %ss elapsed, %s bytes received (%s B/s)\n' \
      "$ELAPSED" "${SIZE// /}" "$RATE" >&2
  done
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
WORK=""
if [[ "$MODE" = restore || "$MODE" = verify ]] && [ -f "$PERSIST/runtime.path" ]; then
  IFS= read -r WORK < "$PERSIST/runtime.path"
  [ -f "$WORK/tools/gen_license.py" ] || WORK=""
fi
if [ -z "$WORK" ]; then
  PREFLIGHT="$(mktemp -d "${TMPDIR:-/tmp}/xpack-preflight.XXXXXX")"
  trap 'rm -rf -- "$PREFLIGHT"' EXIT
  if [ -n "${ARTIFACT_DIR:-}" ]; then
    install -m 0600 "$ARTIFACT_DIR/manifest.json" "$PREFLIGHT/manifest.json"
  else
    fetch "https://api.github.com/repos/$REPO/releases?per_page=100" "$PREFLIGHT/releases.json"
  fi
fi
if [[ "$MODE" = install || "$MODE" = deploy || "$MODE" = cert ]]; then
  INSTALLED_VERSION="$(python3 - "${VERSION:-}" "$PANEL_ROOT" "$CORE_BIN" "$PANEL_CTL" <<'PY'
import pathlib, re, sqlite3, subprocess, sys
requested, root, core, ctl = sys.argv[1:]
pattern = r"v?\d+\.\d+\.\d+"
def normalize(value):
    value = value.strip()
    return "v" + value.lstrip("v") if re.fullmatch(pattern, value) else None
if requested and not normalize(requested):
    raise SystemExit("Invalid VERSION; expected vMAJOR.MINOR.PATCH")
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
)"
  log "Installed panel $INSTALLED_VERSION / $PLATFORM"
fi
NEED_AGENT=0
if [ "$ARCH" = amd64 ] && [ "${SKIP_AGENT:-0}" != 1 ] && [ -f "$AGENT_BIN" ]; then NEED_AGENT=1; fi
if [ -z "$WORK" ]; then
  RUN="$PREFLIGHT"
  if [ -n "${ARTIFACT_DIR:-}" ]; then
    python3 - "$RUN/manifest.json" "${INSTALLED_VERSION:-}" "$PLATFORM" <<'PY'
import json, pathlib, re, sys
m = json.loads(pathlib.Path(sys.argv[1]).read_text())
def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"v?\d+\.\d+\.\d+", value):
        raise SystemExit("Invalid stable release version")
    return tuple(map(int, value.lstrip("v").split(".")))
target = version(m.get("version"))
if sys.argv[2] and target < version(sys.argv[2]):
    raise SystemExit("Unsupported: project release is older than installed " + sys.argv[2])
if sys.argv[3] not in m.get("platforms", {}):
    raise SystemExit("Unsupported: project release has no verified platform assets")
pathlib.Path(sys.argv[1]).with_name("selected.version").write_text(m["version"])
print("Version preflight passed: project " + m["version"] + " / installed " + sys.argv[2])
PY
  else
    python3 - "$RUN" "${INSTALLED_VERSION:-}" "$PLATFORM" "$NEED_AGENT" <<'PY'
import json, pathlib, re, sys
run, requested, platform, agent = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4] == "1"
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
if requested and target < version(requested):
    raise SystemExit("Unsupported: repository latest " + tag[5:] + " is older than installed " + requested)
assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
needed = ("manifest.json", "runtime.tar.gz", "core-" + platform, "core-" + platform + ".orig")
if agent:
    needed += ("agent-" + platform + ".orig",)
if not all(name in assets for name in needed):
    raise SystemExit("Unsupported: latest Release " + tag + " has no verified assets for " + platform)
(run / "manifest.url").write_text(assets["manifest.json"])
(run / "runtime.url").write_text(assets["runtime.tar.gz"])
(run / "core.url").write_text(assets["core-" + platform])
(run / "orig.url").write_text(assets["core-" + platform + ".orig"])
if agent:
    (run / "agent.url").write_text(assets["agent-" + platform + ".orig"])
(run / "release.tag").write_text(tag)
(run / "selected.version").write_text(tag[5:])
print("Version preflight passed: repository latest " + tag[5:] + " / installed " + requested)
PY
  fi
  RELEASE_VERSION="$(<"$PREFLIGHT/selected.version")"
  mkdir -p "$PERSIST" "$BACKUP"
  RUN="$(mktemp -d "$PERSIST/run.XXXXXX")"
  if [ -n "${ARTIFACT_DIR:-}" ]; then
    install -m 0600 "$ARTIFACT_DIR/manifest.json" "$RUN/manifest.json"
    install -m 0600 "$ARTIFACT_DIR/runtime.tar.gz" "$RUN/runtime.tar.gz"
  else
    for NAME in manifest runtime core orig; do
      install -m 0600 "$PREFLIGHT/$NAME.url" "$RUN/$NAME.url"
    done
    [ "$NEED_AGENT" != 1 ] || install -m 0600 "$PREFLIGHT/agent.url" "$RUN/agent.url"
    install -m 0600 "$PREFLIGHT/release.tag" "$RUN/release.tag"
    log "Release $RELEASE_VERSION / $PLATFORM"
    fetch "$(<"$RUN/manifest.url")" "$RUN/manifest.json"
    fetch "$(<"$RUN/runtime.url")" "$RUN/runtime.tar.gz"
  fi
  WORK="$(mktemp -d "$PERSIST/runtime.XXXXXX")"
  python3 - "$RUN" "$WORK" "$PLATFORM" "$NEED_AGENT" "$RELEASE_VERSION" <<'PY'
import hashlib, json, pathlib, ssl, tarfile, sys
run, work, platform = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
m = json.loads((run / "manifest.json").read_text())
if m.get("schema_version") != 2 or m.get("name") != "xpack-toolkit" or m.get("mode") != "offline" or m.get("remote_base") != "":
    raise SystemExit("Expected an offline schema-2 unified release manifest")
if platform not in m.get("platforms", {}):
    raise SystemExit("Release has no verified core for " + platform)
if (run / "release.tag").exists() and (run / "release.tag").read_text() != "core-" + m.get("version", ""):
    raise SystemExit("Release tag/version mismatch")
if sys.argv[5] and m.get("version") != sys.argv[5]:
    raise SystemExit("Manifest does not match the selected latest project release")
p = m["platforms"][platform]
if p.get("os") != "linux" or p.get("arch") != platform[6:] or p.get("patches") != 3:
    raise SystemExit("Invalid platform declaration")
if p.get("core_asset") != "core-" + platform or p.get("orig_asset") != "core-" + platform + ".orig":
    raise SystemExit("Unexpected platform asset names")
if sys.argv[4] == "1" and (p.get("agent_orig_asset") != "agent-" + platform + ".orig"
                           or not p.get("agent_orig_sha256") or not p.get("agent_orig_size")):
    raise SystemExit("Release has no verified original agent for " + platform)
meta = m["runtime"]
archive = run / "runtime.tar.gz"
data = archive.read_bytes()
if meta.get("asset") != archive.name or meta.get("size") != len(data) or meta.get("sha256") != hashlib.sha256(data).hexdigest():
    raise SystemExit("Runtime archive checksum mismatch")
allowed = {"tools/" + f for f in ("gen_license.py", "patch_core.py", "patch_agent.py", "cert_store.py", "aes128.py", "gosym.py", "official_rootcert.json")} | {"state/license.crt"}
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if len(members) != len(allowed) or {a.name for a in members} != allowed or any(not a.isfile() for a in members):
        raise SystemExit("Runtime archive must contain only the public file whitelist")
    for item in members:
        target = work / item.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(tf.extractfile(item).read())
        target.chmod(0o600)
fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert((work / "state/license.crt").read_text())).hexdigest()
if m.get("root_fingerprint") != fp:
    raise SystemExit("Bundled signing root differs from release manifest")
print("Verified bundled runtime / " + m["version"] + " / " + platform)
PY
  printf '%s\n' "$WORK" > "$PERSIST/runtime.path"
fi
PATCH_CORE="$WORK/tools/patch_core.py"
PATCH_AGENT="$WORK/tools/patch_agent.py"
CERT_STORE="$WORK/tools/cert_store.py"
GEN_LICENSE="$WORK/tools/gen_license.py"
# Older cached runtimes used long local filenames; no network probes are needed.
[ -f "$PATCH_CORE" ] || PATCH_CORE="$WORK/tools/patch_1panel_core.py"
[ -f "$PATCH_AGENT" ] || PATCH_AGENT="$WORK/tools/patch_1panel_agent.py"
[ -f "$CERT_STORE" ] || CERT_STORE="$WORK/tools/rootcert_store.py"
if [ -z "${STATE:-}" ]; then
  if [ -f "$WORK/state/license.crt" ]; then STATE="$WORK/state"
  else STATE="$WORK/web/state"; fi
fi
export STATE
export SIGN_CRT="${SIGN_CRT:-$STATE/license.crt}"
export SIGN_KEY="${SIGN_KEY:-$STATE/license.key}"
if [ ! -s "$SIGN_CRT" ] && [ -s "$WORK/state/license.crt" ]; then
  export SIGN_CRT="$WORK/state/license.crt"
fi
export REMOTE_BASE=""
check_root() {
  python3 - "$CERT_STORE" "$XPACK_DB" "$SIGN_CRT" <<'PY'
import importlib.util, pathlib, sqlite3, ssl, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location("root_check", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
pem = pathlib.Path(sys.argv[3]).read_text()
fp = m.fingerprint(pem)
with sqlite3.connect("file:" + sys.argv[2] + "?mode=ro", uri=True) as con:
    for key in ("LicenseRootCertHK", "LicenseRootCertCN", "LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint"):
        rows = con.execute("select value from core_settings where key=?", (key,)).fetchall()
        if len(rows) != 1:
            raise SystemExit("Missing/duplicate root certificate row: " + key)
        value = m.decrypt(rows[0][0])
        if key.endswith("Fingerprint"):
            valid = value == fp
        else:
            valid = ssl.PEM_cert_to_DER_cert(value) == ssl.PEM_cert_to_DER_cert(pem)
        if not valid:
            raise SystemExit("Root certificate readback mismatch: " + key)
print("Root certificate readback: all four rows match " + fp)
PY
}
official() {
  python3 - "$1" "$2" "$PATCH_CORE" "$PATCH_AGENT" <<'PY'
import contextlib, importlib.util, pathlib, sys
path, kind, core_tool, agent_tool = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(core_tool).parent))
spec = importlib.util.spec_from_file_location("patch_check", core_tool if kind == "core" else agent_tool)
m = importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(sys.stderr):
    spec.loader.exec_module(m)
data = pathlib.Path(path).read_bytes()
if kind == "core":
    # Restoration must work without the current site's certificate/private key.
    m.root_fingerprint = lambda *args, **kwargs: m.ROOT_FP_HK_ORIG
    sites = [s for s in m.build_table(data, remote_base="", verbose=False) if s[0].startswith(("P1.", "P2.", "C7."))]
    if len(sites) != 3 or any(orig is None or data[off:off + len(orig)] != orig
                              for _, off, orig, _, _ in sites):
        raise SystemExit("Not an official original core: " + path)
    for host in ("hk", "cn"):
        if data.count(("https://license.lxware.%s/api/v1/" % host).encode()) != 1:
            raise SystemExit("Original core contains modified license addresses: " + path)
else:
    sites = m.locate(data)
    if not sites or any(s[2] != "original" for s in sites):
        raise SystemExit("Not an official original agent: " + path)
PY
}
backup_orig() {
  local SRC="$1" NAME="$2" SUM DEST INVALID
  official "$SRC" "$NAME"
  SUM="$(sha256sum "$SRC")"; SUM="${SUM%% *}"
  DEST="$BACKUP/1panel-$NAME.orig"
  # Quarantine mislabeled historical backups; never reuse a modified rollback image.
  if [ -f "$DEST" ]; then
    if ! official "$DEST" "$NAME" >/dev/null 2>&1 \
       || { [ -f "$DEST.sha256" ] && ! sha256sum -c "$DEST.sha256" >/dev/null 2>&1; } \
       || { [ ! -f "$DEST.sha256" ] && ! cmp -s "$SRC" "$DEST"; }; then
      INVALID="$(sha256sum "$DEST")"; INVALID="${INVALID%% *}"
      INVALID="$BACKUP/1panel-$NAME.invalid.$INVALID.orig"
      install -m 0600 "$DEST" "$INVALID"
      [ ! -f "$DEST.sha256" ] || install -m 0600 "$DEST.sha256" "$INVALID.sha256"
      install -m 0755 "$SRC" "$DEST"
      log "Archived stale $NAME backup; saved verified official replacement"
    fi
  else
    install -m 0755 "$SRC" "$DEST"
  fi
  sha256sum "$DEST" > "$DEST.sha256"
  install -m 0755 "$SRC" "$BACKUP/1panel-$NAME.$SUM.orig"
}
restore_source() {
  local NAME="$1" FILE SUM
  for FILE in "$BACKUP/1panel-$NAME.orig" "$BACKUP/$NAME.orig" \
              "$PANEL_ROOT/backup/1panel-$NAME.orig" "$PANEL_ROOT/backup/$NAME.orig" \
              "$BACKUP/1panel-$NAME."*.orig; do
    if [ -f "$FILE" ]; then
      case "$FILE" in *.invalid.*) continue ;; esac
      if ! official "$FILE" "$NAME" >/dev/null 2>&1; then continue; fi
      if [ -f "$FILE.sha256" ] && ! sha256sum -c "$FILE.sha256" >/dev/null 2>&1; then continue; fi
      if [ ! -f "$FILE.sha256" ]; then
        SUM="$(sha256sum "$FILE")"; SUM="${SUM%% *}"
        case "$FILE" in *".$SUM.orig") ;; *) continue ;; esac
      fi
      printf '%s\n' "$FILE"
      return
    fi
  done
  die "Missing official $NAME rollback image"
}
if [ "$MODE" = restore ]; then
  RESTORE_CRT="$SIGN_CRT"
  [ -s "$RESTORE_CRT" ] || RESTORE_CRT="$WORK/state/license.crt"
  python3 "$CERT_STORE" --preserve-foreign --check-owned --cert "$RESTORE_CRT" --db "$XPACK_DB"
  CORE_ORIG="$(restore_source core)"
  AGENT_ORIG=""
  if [ -f "$BACKUP/1panel-agent.orig" ] || [ -f "$BACKUP/agent.orig" ] \
     || [ -f "$PANEL_ROOT/backup/1panel-agent.orig" ] || [ -f "$PANEL_ROOT/backup/agent.orig" ]; then
    AGENT_ORIG="$(restore_source agent)"
  fi
  [ -f "$XPACK_DB" ] || die "Missing initialized database: $XPACK_DB"
  systemctl stop "$CORE_SVC"
  [ -z "$AGENT_ORIG" ] || systemctl stop "$AGENT_SVC"
  install -m 0755 "$CORE_ORIG" "$CORE_BIN"
  python3 "$CERT_STORE" --preserve-foreign --cert "$RESTORE_CRT" --db "$XPACK_DB" --bak "$BACKUP/core_settings_license_rootcert.json" --restore
  if [ -n "$AGENT_ORIG" ]; then
    install -m 0755 "$AGENT_ORIG" "$AGENT_BIN"
    systemctl start "$AGENT_SVC"
    systemctl is-active --quiet "$AGENT_SVC"
  fi
  systemctl start "$CORE_SVC"
  systemctl is-active --quiet "$CORE_SVC"
  log "Restored official binaries and root certificate rows"
  exit 0
fi
[ -s "$SIGN_CRT" ] || die "Missing public root certificate: $SIGN_CRT"
if [ "$MODE" = verify ]; then
  python3 "$PATCH_CORE" --verify --in "$CORE_BIN"
  python3 "$CERT_STORE" --db "$XPACK_DB" --show
  check_root
  if [ -f "$PERSIST/license.status" ] && [[ "$(<"$PERSIST/license.status")" != applied ]]; then
    log "Components verified; a project-signed license is pending import"
  else
    python3 "$GEN_LICENSE" --verify-db --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
  fi
  systemctl is-active --quiet "$CORE_SVC"
  exit 0
fi
if [[ "$MODE" = install || "$MODE" = deploy || "$MODE" = cert ]]; then
  ROOT_STATE="$(python3 "$CERT_STORE" --preserve-foreign --check-owned --cert "$SIGN_CRT" --db "$XPACK_DB")"
  printf '%s\n' "$ROOT_STATE"
  LICENSE_STATE="$(python3 "$GEN_LICENSE" --preserve-foreign --preflight-db --db "$XPACK_DB" \
    --serial-path "$PANEL_ROOT/db/.serial")"
  printf '%s\n' "$LICENSE_STATE"
  FOREIGN_SUMMARY="$(python3 - "$ROOT_STATE" "$LICENSE_STATE" <<'PY'
import json, sys
def parsed(text):
    try:
        value = json.loads(text)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}
roots = parsed(sys.argv[1]).get("roots", {})
state = parsed(sys.argv[2])
print(json.dumps({"roots": sorted(name for name, value in roots.items() if value == "foreign"),
                  "licenses": int(state.get("foreignLicenseCount", 0))}))
PY
)"
  FOREIGN_PRESENT=0
  [ "$FOREIGN_SUMMARY" = '{"roots": [], "licenses": 0}' ] || FOREIGN_PRESENT=1
  if [ -z "$FOREIGN_CHOICE" ]; then
    FOREIGN_MODE=keep
    if [ "$FOREIGN_PRESENT" = 1 ] && { exec 4<>/dev/tty; } 2>/dev/null; then
      printf '检测到第三方授权（证书/许可证）：是否直接替换为本站内核授权？[Y/n]（原件先留档备份）：' >&4
      if IFS= read -r FOREIGN_ANSWER <&4; then
        case "$FOREIGN_ANSWER" in n|N|no|NO|0) FOREIGN_MODE=keep ;; *) FOREIGN_MODE=replace ;; esac
      fi
      exec 4>&-
    fi
  else
    FOREIGN_MODE="$FOREIGN_CHOICE"
  fi
  GEN_REPLACE_FLAGS=()
  if [ "$FOREIGN_MODE" = replace ]; then
    GEN_HELP="$(python3 "$GEN_LICENSE" --help)"
    for FLAG in --replace-foreign --drop-foreign-licenses; do
      [[ "$GEN_HELP" == *"$FLAG"* ]] || die "Update gen_license.py: missing $FLAG"
    done
    if [ "$FOREIGN_PRESENT" = 1 ]; then
      GEN_REPLACE_FLAGS=(--replace-foreign)
      log "Third-party authorization detected: $FOREIGN_SUMMARY -> replacing with our kernel (originals archived first)"
    else
      log "No third-party authorization detected; nothing to replace"
    fi
  elif [ "$FOREIGN_PRESENT" = 1 ]; then
    log "Third-party authorization detected: $FOREIGN_SUMMARY -> keeping third-party certificates and licenses"
  fi
fi
# A discovered .lic only counts when it is ours: valid signature chain against the
# toolkit root, offline, unexpired, sane node allowance and this machine's serial.
license_candidate_ok() {
  local FILE="$1"
  [ -s "$FILE" ] || return 1
  python3 - "$GEN_LICENSE" "$FILE" "$PANEL_ROOT/db/.serial" <<'PY' > /dev/null 2>&1
import datetime as dt, importlib.util, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location("license_check", sys.argv[1])
module = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(module)
    content = module.verify_license(pathlib.Path(sys.argv[2]).read_text())
except Exception:
    raise SystemExit(1)
if content.get("offline") is not True:
    raise SystemExit(1)
products = content.get("products") or []
if not products or not content.get("deviceID") or int(products[0].get("maxNodeCount", 0)) < 1:
    raise SystemExit(1)
now = dt.datetime.now(dt.timezone.utc)
for product in products:
    try:
        expiry = dt.datetime.fromisoformat(str(product["expiresAt"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        raise SystemExit(1)
    if expiry.tzinfo is None or expiry <= now:
        raise SystemExit(1)
serial = pathlib.Path(sys.argv[3])
if serial.is_file() and serial.read_text().strip() != content["deviceID"]:
    raise SystemExit(1)
PY
}
LICENSE_OUT="$RUN/license.txt"
LICENSE_READY=1
LICENSE_SOURCE=""
if [ -n "${LICENSE_FILE:-}" ]; then
  [ -s "$LICENSE_FILE" ] || die "License file missing or empty: $LICENSE_FILE"
  install -m 0600 "$LICENSE_FILE" "$LICENSE_OUT"
  LICENSE_SOURCE="$LICENSE_FILE"
elif [ -s "$SIGN_KEY" ]; then
  python3 "$GEN_LICENSE" --edition enterprise --expires "${EXPIRES:-2099-12-31}" \
    --nodes "${NODES:-999}" --assignee "${ASSIGNEE:-YG}" --offline --out "$LICENSE_OUT" \
    --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
  LICENSE_SOURCE="local signing material"
else
  # No signing material: an already-issued project license still activates the panel.
  while IFS= read -r DIRECTORY; do
    [ -n "$DIRECTORY" ] || continue
    for CANDIDATE in "$DIRECTORY"/*.lic; do
      [ -s "$CANDIDATE" ] || continue
      license_candidate_ok "$CANDIDATE" || continue
      install -m 0600 "$CANDIDATE" "$LICENSE_OUT"
      LICENSE_SOURCE="$CANDIDATE"
      break
    done
    [ -z "$LICENSE_SOURCE" ] || break
  done <<< "$(printf '%s' "$LICENSE_SEARCH_DIRS" | tr ':' '\n')"
  if [ -z "$LICENSE_SOURCE" ] && python3 "$GEN_LICENSE" --export-existing "$LICENSE_OUT" --db "$XPACK_DB" 2> "$RUN/license-export.log"; then
    LICENSE_SOURCE="project license already stored in the panel database"
  fi
  if [ -z "$LICENSE_SOURCE" ] && [ "$ALLOW_PENDING" != 1 ]; then
    if { exec 5<>/dev/tty; } 2>/dev/null; then
      for ATTEMPT in 1 2 3; do
        printf '本站授权文件是激活必需的，请给出 .lic 路径（留空中止）：' >&5
        IFS= read -r LICENSE_ANSWER <&5 || break
        [ -n "$LICENSE_ANSWER" ] || break
        if license_candidate_ok "$LICENSE_ANSWER"; then
          install -m 0600 "$LICENSE_ANSWER" "$LICENSE_OUT"
          LICENSE_SOURCE="$LICENSE_ANSWER"
          break
        fi
        printf '!! %s 不是本站签发、已过期或与本机 serial 不匹配\n' "$LICENSE_ANSWER" >&5
      done
      exec 5>&-
    fi
  fi
  if [ -n "$LICENSE_SOURCE" ]; then
    log "Project-signed license: $LICENSE_SOURCE"
  elif [ "$ALLOW_PENDING" = 1 ]; then
    LICENSE_READY=0
    log "No project-signed license and --no-license given; installing components only, the panel stays inactive"
  else
    die "本站授权文件是激活必需的：请用 LICENSE_FILE=/path/1Panel-Enterprise-XXXX.lic（或 --license-file PATH），也可把签好的 .lic 放进 $PANEL_ROOT/crack/、\$HOME 或当前目录后重跑；只装组件不激活请显式加 --no-license"
  fi
fi
# Shared generator owns encrypted three-segment decoding/signature verification.
if [ "$LICENSE_READY" = 1 ]; then
python3 - "$GEN_LICENSE" "$LICENSE_OUT" "$PANEL_ROOT/db/.serial" <<'PY'
import datetime as dt, importlib.util, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location("license_check", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
content = m.verify_license(pathlib.Path(sys.argv[2]).read_text())
if content.get("offline") is not True:
    raise SystemExit("An offline signed license is required")
products = content.get("products") or []
if not products or not content.get("deviceID") or int(products[0].get("maxNodeCount", 0)) < 1:
    raise SystemExit("Missing device ID or invalid node allowance")
for product in products:
    expiry = dt.datetime.fromisoformat(product["expiresAt"].replace("Z", "+00:00"))
    if expiry.tzinfo is None:
        raise SystemExit("License expiry must include its timezone")
    if expiry <= dt.datetime.now(dt.timezone.utc):
        raise SystemExit("The signed license has expired")
serial = pathlib.Path(sys.argv[3])
if serial.is_file() and serial.read_text().strip() != content["deviceID"]:
    raise SystemExit("License device ID differs from panel serial")
print("License: %s / expiry %s / nodes %s" % (
    content.get("licenseName"), content["products"][0]["expiresAt"], content["products"][0]["maxNodeCount"]))
PY
fi
if [ "$MODE" = cert ]; then
  [ "$LICENSE_READY" = 1 ] || die "No project-signed license to export; provide LICENSE_FILE or local signing material"
  log "Signed offline license retained: $LICENSE_OUT"
  exit 0
fi
[ -f "$XPACK_DB" ] || die "Missing initialized database: $XPACK_DB"
if [ "${NO_APPLY:-0}" != 1 ] && [ "$LICENSE_READY" = 1 ]; then
  HELP="$(python3 "$GEN_LICENSE" --help)"
  for FLAG in --db --serial-path --no-restart --preflight-db --verify-db --preserve-foreign --foreign-backup-dir; do
    [[ "$HELP" == *"$FLAG"* ]] || die "Update gen_license.py: missing $FLAG (legacy expiry patching is not used)"
  done
fi
if [ -n "${ARTIFACT_DIR:-}" ]; then
  install -m 0755 "$ARTIFACT_DIR/core-$PLATFORM" "$RUN/core"
  install -m 0755 "$ARTIFACT_DIR/core-$PLATFORM.orig" "$RUN/core.orig"
else
  fetch "$(<"$RUN/core.url")" "$RUN/core"
  fetch "$(<"$RUN/orig.url")" "$RUN/core.orig"
fi
python3 - "$RUN" "$SIGN_CRT" "$ARCH" <<'PY'
import hashlib, json, pathlib, ssl, struct, sys
dl, cert, arch = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
man = json.loads((dl / "manifest.json").read_text())
fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
if man.get("root_fingerprint") != fp:
    raise SystemExit("Manifest signing root mismatch")
man = man["platforms"]["linux-" + arch]
if man.get("arch") != arch or man.get("os") != "linux" or man.get("patches") != 3:
    raise SystemExit("Manifest arch/root_fingerprint mismatch")
if man.get("core_asset") != "core-linux-" + arch or man.get("orig_asset") != "core-linux-" + arch + ".orig":
    raise SystemExit("Manifest core asset names mismatch")
for name, key, alias in (("core", "sha256", "output_sha256"), ("core.orig", "orig_sha256", "source_sha256")):
    data = (dl / name).read_bytes()
    want = man.get(key) or man.get(alias)
    if not want or hashlib.sha256(data).hexdigest() != want:
        raise SystemExit("Missing/mismatched " + key)
    if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != {"amd64": 62, "arm64": 183}[arch]:
        raise SystemExit("ELF architecture mismatch: " + name)
    if name == "core" and data.count(fp.encode()) < 2:
        raise SystemExit("Artifact does not contain declared root fingerprint")
print("Verified Release sha256 + orig sha256 + arch + rootFP: " + fp)
PY
official "$RUN/core.orig" core
# Rebuild every run (including old online Releases) from the verified original.
python3 "$PATCH_CORE" --patch --in "$RUN/core.orig" --out "$RUN/core.offline" \
  --orig "$RUN/core.orig" --manifest "$RUN/offline.manifest.json" --remote-base ''
python3 "$PATCH_CORE" --verify --in "$RUN/core.offline"
python3 - "$RUN/core.orig" "$RUN/core.offline" <<'PY'
import pathlib, sys
orig, out = (pathlib.Path(p).read_bytes() for p in sys.argv[1:])
for host in ("hk", "cn"):
    url = ("https://license.lxware.%s/api/v1/" % host).encode()
    pos = orig.find(url)
    if pos < 0 or orig.find(url, pos + 1) >= 0 or out[pos:pos + len(url)] != url:
        raise SystemExit("P3/P4 not cleared; update local patch_core tool")
PY
AGENT_SOURCE=""
if [ "$ARCH" != amd64 ] && [ "${SKIP_AGENT:-0}" != 1 ]; then
  log "Agent byte patches are validated for amd64 only; preserving the installed $ARCH agent"
  SKIP_AGENT=1
fi
if [ "$NEED_AGENT" = 1 ]; then
  if [ -n "${ARTIFACT_DIR:-}" ]; then
    install -m 0755 "$ARTIFACT_DIR/agent-$PLATFORM.orig" "$RUN/agent.orig"
  else
    fetch "$(<"$RUN/agent.url")" "$RUN/agent.orig"
  fi
  python3 - "$RUN" "$ARCH" <<'PY'
import hashlib, json, pathlib, struct, sys
run, arch = pathlib.Path(sys.argv[1]), sys.argv[2]
m = json.loads((run / "manifest.json").read_text())["platforms"]["linux-" + arch]
data = (run / "agent.orig").read_bytes()
if m.get("agent_orig_asset") != "agent-linux-" + arch + ".orig" or m.get("agent_orig_size") != len(data):
    raise SystemExit("Original agent manifest size/name mismatch")
if hashlib.sha256(data).hexdigest() != m.get("agent_orig_sha256"):
    raise SystemExit("Original agent SHA-256 mismatch")
if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != {"amd64": 62, "arm64": 183}[arch]:
    raise SystemExit("Original agent ELF architecture mismatch")
print("Verified matching official agent source: " + arch)
PY
  official "$RUN/agent.orig" agent
  AGENT_SOURCE="$RUN/agent.orig"
  log "Replacing existing agent using a freshly verified official source"
  python3 "$PATCH_AGENT" --patch --in "$RUN/agent.orig" --out "$RUN/agent" \
    --orig "$RUN/agent.orig" --manifest "$RUN/agent.manifest.json"
  python3 "$PATCH_AGENT" --verify --in "$RUN/agent"
fi
python3 "$CERT_STORE" --preserve-foreign --archive-current --cert "$SIGN_CRT" --db "$XPACK_DB" \
  --bak "$BACKUP/core_settings_license_rootcert.json"
if [ "${NO_APPLY:-0}" != 1 ] && [ "$LICENSE_READY" = 1 ]; then
  python3 "$GEN_LICENSE" --preserve-foreign --archive-foreign --foreign-backup-dir "$BACKUP" \
    --import-file "$LICENSE_OUT" --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
fi
backup_orig "$RUN/core.orig" core
[ -z "$AGENT_SOURCE" ] || backup_orig "$RUN/agent.orig" agent
# Preserve replaced binaries separately from verified official rollback images.
for KIND in core agent; do
  if [ "$KIND" = core ]; then PREVIOUS="$CORE_BIN"
  elif [ -n "$AGENT_SOURCE" ]; then PREVIOUS="$AGENT_BIN"
  else continue; fi
  if [ -f "$PREVIOUS" ]; then
    SUM="$(sha256sum "$PREVIOUS")"; SUM="${SUM%% *}"
    SAVED="$BACKUP/1panel-$KIND.previous.$SUM"
    if [ -e "$SAVED" ]; then
      [ ! -L "$SAVED" ] && cmp -s "$PREVIOUS" "$SAVED" || die "Previous binary backup mismatch: $SAVED"
    else
      install -m 0600 "$PREVIOUS" "$SAVED"
    fi
  fi
done
systemctl stop "$CORE_SVC"
[ -z "$AGENT_SOURCE" ] || systemctl stop "$AGENT_SVC"
install -m 0755 "$RUN/core.offline" "$CORE_BIN"
[ -z "$AGENT_SOURCE" ] || install -m 0755 "$RUN/agent" "$AGENT_BIN"
# Only the current verified project CA is an ownership anchor, not arbitrary DB roots.
python3 - "$SIGN_CRT" > "$RUN/project-root-fingerprint" <<'PY'
import hashlib, pathlib, ssl, sys
print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(pathlib.Path(sys.argv[1]).read_text())).hexdigest())
PY
install -m 0600 "$RUN/project-root-fingerprint" "$BACKUP/script_root_fingerprints"
python3 "$CERT_STORE" --preserve-foreign --cert "$SIGN_CRT" --db "$XPACK_DB" --bak "$BACKUP/core_settings_license_rootcert.json"
if [ "${NO_APPLY:-0}" != 1 ] && [ "$LICENSE_READY" = 1 ]; then
  python3 "$GEN_LICENSE" --preserve-foreign --foreign-backup-dir "$BACKUP" --import-file "$LICENSE_OUT" --apply --db "$XPACK_DB" \
    --serial-path "$PANEL_ROOT/db/.serial" --no-restart "${GEN_REPLACE_FLAGS[@]}"
  printf 'applied\n' > "$PERSIST/license.status"
elif [ "${NO_APPLY:-0}" = 1 ]; then
  printf 'not-applied\n' > "$PERSIST/license.status"
else
  if [ "$FOREIGN_MODE" = replace ] && [ "$FOREIGN_PRESENT" = 1 ]; then
    log "No project-signed license supplied: third-party license rows were kept (not dropped) so the panel is not left without any authorization"
  fi
  printf 'pending\n' > "$PERSIST/license.status"
fi
cmp -s "$RUN/core.offline" "$CORE_BIN" || die "Installed core changed during license apply"
if [ -n "$AGENT_SOURCE" ]; then
  systemctl start "$AGENT_SVC"
  systemctl is-active --quiet "$AGENT_SVC"
fi
systemctl start "$CORE_SVC"
systemctl is-active --quiet "$CORE_SVC"
python3 "$PATCH_CORE" --verify --in "$CORE_BIN"
python3 "$CERT_STORE" --db "$XPACK_DB" --show
check_root
if [ "${NO_APPLY:-0}" != 1 ] && [ "$LICENSE_READY" = 1 ]; then
  python3 "$GEN_LICENSE" --verify-db --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
fi
if [ "${NO_APPLY:-0}" = 1 ]; then
  log "Core/certificate replaced; license NOT applied (NO_APPLY=1)"
  [ "$FOREIGN_PRESENT" != 1 ] || [ "$FOREIGN_MODE" != replace ] \
    || log "Third-party authorization archived under $BACKUP; import the project license to replace it"
elif [ "$LICENSE_READY" != 1 ]; then
  log "Components installed WITHOUT a project-signed license (--no-license): the panel stays inactive"
  log "Activate later with: sudo env LICENSE_FILE=/path/1Panel-Enterprise-XXXX.lic bash unlock.sh install"
else
  log "Core/certificate replaced; offline license applied with automatic main-node binding"
  [ "$FOREIGN_PRESENT" != 1 ] || [ "$FOREIGN_MODE" != replace ] \
    || log "Third-party authorization replaced and archived under $BACKUP"
fi
log "License and verified artifacts retained: $RUN"
log "Rollback: bash unlock.sh restore (official images: $BACKUP)"
