#!/usr/bin/env bash
# Verified offline reinstall. Only use local signing keys; never download keys.
# STATE/SIGN_KEY: local material. LICENSE_FILE: pre-issued signed license.
# ARTIFACT_DIR: local Release. NO_APPLY: persist license for manual import.
set -euo pipefail
umask 077
REPO="${REPO:-keweiya/xpack-toolkit}"
BRANCH="${BRANCH:-main}"
PANEL_ROOT="${PANEL_ROOT:-/opt/1panel}"
CORE_BIN="${CORE_BIN:-/usr/local/bin/1panel-core}"
AGENT_BIN="${AGENT_BIN:-/usr/local/bin/1panel-agent}"
CORE_SVC="${CORE_SVC:-1panel-core}"
AGENT_SVC="${AGENT_SVC:-1panel-agent}"
XPACK_DB="${XPACK_DB:-$PANEL_ROOT/db/xpack.db}"
BACKUP="${BACKUP:-$PANEL_ROOT/crack/backup}"
PERSIST="${UNLOCK_WORK:-$PANEL_ROOT/unlock}"
MODE="${1:-install}"
log() { printf '== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }
trap 'printf "!! Failed; artifacts/backups retained: %s / %s\n" "$PERSIST" "$BACKUP" >&2' ERR
case "$MODE" in install|deploy|restore|verify|cert) ;; *) die "usage: $0 {install|restore|verify|cert}" ;; esac
[ "$(id -u)" -eq 0 ] || die "Run as root"
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die "Unknown architecture" ;; esac
mkdir -p "$PERSIST" "$BACKUP"
fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 2 -o "$2" "$1"; }
SELF="${BASH_SOURCE[0]:-}"
WORK=""
if [ -n "$SELF" ] && [ -f "$SELF" ]; then
  CANDIDATE="$(cd "$(dirname "$SELF")" && pwd)"
  [ ! -f "$CANDIDATE/tools/gen_license.py" ] || WORK="$CANDIDATE"
fi
if [ -z "$WORK" ] && [ "$MODE" = restore ] && [ -f "$PERSIST/runtime.path" ]; then
  IFS= read -r WORK < "$PERSIST/runtime.path"
  [ -f "$WORK/tools/gen_license.py" ] || WORK=""
fi
if [ -z "$WORK" ]; then
  WORK="$(mktemp -d "$PERSIST/runtime.XXXXXX")"
  mkdir -p "$WORK/tools" "$WORK/web/state"
  RAW="https://raw.githubusercontent.com/$REPO/$BRANCH"
  # Whitelist public code/certificates: no repository archive/private state.
  for PAIR in 'patch_1panel_core.py patch_core.py' 'patch_1panel_agent.py patch_agent.py' \
              'rootcert_store.py cert_store.py' 'gen_license.py gen_license.py' \
              'aes128.py aes128.py' 'gosym.py gosym.py'; do
    read -r LONG SHORT <<< "$PAIR"
    if ! fetch "$RAW/tools/$LONG" "$WORK/tools/$LONG"; then
      fetch "$RAW/tools/$SHORT" "$WORK/tools/$LONG" || die "Missing public tool: $LONG / $SHORT"
    fi
  done
  if [ "$MODE" != restore ]; then
    fetch "$RAW/web/state/license.crt" "$WORK/web/state/license.crt" \
      || fetch "$RAW/state/license.crt" "$WORK/web/state/license.crt"
  fi
  fetch "$RAW/tools/official_rootcert.json" "$WORK/tools/official_rootcert.json" || true
  printf '%s\n' "$WORK" > "$PERSIST/runtime.path"
fi
tool() {
  if [ -f "$WORK/tools/$1" ]; then printf '%s\n' "$WORK/tools/$1"
  elif [ -f "$WORK/tools/$2" ]; then printf '%s\n' "$WORK/tools/$2"
  else die "Missing tool: $1 / $2"; fi
}
PATCH_CORE="$(tool patch_1panel_core.py patch_core.py)"
PATCH_AGENT="$(tool patch_1panel_agent.py patch_agent.py)"
CERT_STORE="$(tool rootcert_store.py cert_store.py)"
GEN_LICENSE="$(tool gen_license.py gen_license.py)"
export STATE="${STATE:-}"
if [ -z "$STATE" ]; then
  if [ -f "$WORK/web/state/license.crt" ]; then STATE="$WORK/web/state"
  else STATE="$WORK/state"; fi
fi
export SIGN_CRT="${SIGN_CRT:-$STATE/license.crt}"
export SIGN_KEY="${SIGN_KEY:-$STATE/license.key}"
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
  local SRC="$1" NAME="$2" SUM DEST
  official "$SRC" "$NAME"
  SUM="$(sha256sum "$SRC")"; SUM="${SUM%% *}"
  DEST="$BACKUP/1panel-$NAME.orig"
  # Retain first official rollback image and each newer verified original.
  if [ -f "$DEST" ]; then
    official "$DEST" "$NAME"
    if [ -f "$DEST.sha256" ]; then sha256sum -c "$DEST.sha256"; fi
  else install -m 0755 "$SRC" "$DEST"; fi
  sha256sum "$DEST" > "$DEST.sha256"
  install -m 0755 "$SRC" "$BACKUP/1panel-$NAME.$SUM.orig"
}
restore_source() {
  local NAME="$1" FILE
  for FILE in "$BACKUP/1panel-$NAME.orig" "$BACKUP/$NAME.orig"; do
    if [ -f "$FILE" ]; then
      official "$FILE" "$NAME" || return 1
      if [ -f "$FILE.sha256" ]; then sha256sum -c "$FILE.sha256" >&2 || return 1; fi
      printf '%s\n' "$FILE"
      return
    fi
  done
  die "Missing official $NAME rollback image"
}
if [ "$MODE" = restore ]; then
  CORE_ORIG="$(restore_source core)"
  AGENT_ORIG=""
  if [ -f "$BACKUP/1panel-agent.orig" ] || [ -f "$BACKUP/agent.orig" ]; then AGENT_ORIG="$(restore_source agent)"; fi
  [ -f "$XPACK_DB" ] || die "Missing initialized database: $XPACK_DB"
  systemctl stop "$CORE_SVC"
  [ -z "$AGENT_ORIG" ] || systemctl stop "$AGENT_SVC"
  install -m 0755 "$CORE_ORIG" "$CORE_BIN"
  python3 "$CERT_STORE" --db "$XPACK_DB" --bak "$BACKUP/core_settings_license_rootcert.json" --restore
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
  python3 "$GEN_LICENSE" --verify-db --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
  systemctl is-active --quiet "$CORE_SVC"
  exit 0
fi
RUN="$(mktemp -d "$PERSIST/run.XXXXXX")"
LICENSE_OUT="$RUN/license.txt"
if [ -n "${LICENSE_FILE:-}" ]; then
  install -m 0600 "$LICENSE_FILE" "$LICENSE_OUT"
elif [ -s "$SIGN_KEY" ]; then
  python3 "$GEN_LICENSE" --edition enterprise --expires "${EXPIRES:-2099-12-31}" \
    --nodes "${NODES:-999}" --assignee "${ASSIGNEE:-YG}" --offline --out "$LICENSE_OUT" \
    --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
else
  python3 "$GEN_LICENSE" --export-existing "$LICENSE_OUT" --db "$XPACK_DB"
  log "Reusing verified existing certificate; expiry and node allowance remain signed values"
fi
# Shared generator owns encrypted three-segment decoding/signature verification.
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
if [ "$MODE" = cert ]; then log "Signed offline license retained: $LICENSE_OUT"; exit 0; fi
[ -f "$XPACK_DB" ] || die "Missing initialized database: $XPACK_DB"
if [ "${NO_APPLY:-0}" != 1 ]; then
  HELP="$(python3 "$GEN_LICENSE" --help)"
  for FLAG in --db --serial-path --no-restart --replace-root-fingerprint --verify-db; do
    [[ "$HELP" == *"$FLAG"* ]] || die "Update gen_license.py: missing $FLAG (legacy expiry patching is not used)"
  done
fi
if [ -n "${ARTIFACT_DIR:-}" ]; then
  install -m 0600 "$ARTIFACT_DIR/manifest.json" "$RUN/manifest.json"
  for NAME in 1panel-core core; do
    if [ -f "$ARTIFACT_DIR/$NAME" ]; then install -m 0755 "$ARTIFACT_DIR/$NAME" "$RUN/core"; break; fi
  done
  for NAME in 1panel-core.orig core.orig orig/1panel-core.orig orig/core.orig; do
    if [ -f "$ARTIFACT_DIR/$NAME" ]; then install -m 0755 "$ARTIFACT_DIR/$NAME" "$RUN/core.orig"; break; fi
  done
else
  if [ -n "${ARTIFACT_URL:-}" ]; then BASE="${ARTIFACT_URL%/}"
  else
    if [ -n "${VERSION:-}" ]; then TAG="core-v${VERSION#v}-${ARCH}"
    else
      fetch "https://api.github.com/repos/$REPO/releases?per_page=100" "$RUN/releases.json"
      TAG="$(python3 - "$RUN/releases.json" "$ARCH" <<'PY'
import json, re, sys
for release in json.load(open(sys.argv[1])):
    tag = release.get("tag_name", "")
    if not release.get("draft") and not release.get("prerelease") and re.fullmatch(r"core-v?\d[^/]*-" + sys.argv[2], tag):
        print(tag)
        break
PY
)"
    fi
    [ -n "$TAG" ] || die "No Release for $ARCH"
    BASE="https://github.com/$REPO/releases/download/$TAG"
  fi
  fetch "$BASE/manifest.json" "$RUN/manifest.json"
  fetch "$BASE/1panel-core" "$RUN/core" || fetch "$BASE/core" "$RUN/core"
  fetch "$BASE/1panel-core.orig" "$RUN/core.orig" || fetch "$BASE/core.orig" "$RUN/core.orig"
fi
python3 - "$RUN" "$SIGN_CRT" "$ARCH" <<'PY'
import hashlib, json, pathlib, ssl, struct, sys
dl, cert, arch = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
man = json.loads((dl / "manifest.json").read_text())
fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
if man.get("name", "core") not in ("core", "1panel-core"):
    raise SystemExit("Wrong artifact name")
if man.get("arch") != arch or man.get("root_fingerprint") != fp:
    raise SystemExit("Manifest arch/root_fingerprint mismatch")
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
if [ "${SKIP_AGENT:-0}" != 1 ] && [ -f "$AGENT_BIN" ]; then
  if official "$AGENT_BIN" agent; then AGENT_SOURCE="$AGENT_BIN"
  else AGENT_SOURCE="$(restore_source agent)"; fi
  install -m 0755 "$AGENT_SOURCE" "$RUN/agent.orig"
  python3 "$PATCH_AGENT" --patch --in "$RUN/agent.orig" --out "$RUN/agent" \
    --orig "$RUN/agent.orig" --manifest "$RUN/agent.manifest.json"
  python3 "$PATCH_AGENT" --verify --in "$RUN/agent"
fi
backup_orig "$RUN/core.orig" core
[ -z "$AGENT_SOURCE" ] || backup_orig "$RUN/agent.orig" agent
systemctl stop "$CORE_SVC"
[ -z "$AGENT_SOURCE" ] || systemctl stop "$AGENT_SVC"
install -m 0755 "$RUN/core.offline" "$CORE_BIN"
[ -z "$AGENT_SOURCE" ] || install -m 0755 "$RUN/agent" "$AGENT_BIN"
# Read old site fingerprints before root rotation, excluding official roots.
python3 - "$CERT_STORE" "$XPACK_DB" "$BACKUP/script_root_fingerprints" > "$RUN/old-root-fingerprints" <<'PY'
import importlib.util, pathlib, re, sqlite3, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location("old_store", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
history = pathlib.Path(sys.argv[3])
fps = set(history.read_text().splitlines()) if history.is_file() else set()
with sqlite3.connect("file:" + sys.argv[2] + "?mode=ro", uri=True) as con:
    for key in ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint"):
        row = con.execute("select value from core_settings where key=?", (key,)).fetchone()
        if row:
            try:
                fp = m.decrypt(row[0])
            except Exception:
                continue
            if re.fullmatch(r"[0-9a-f]{64}", fp) and fp not in m.OFFICIAL_FP.values():
                fps.add(fp)
for fp in sorted(fps):
    if re.fullmatch(r"[0-9a-f]{64}", fp) and fp not in m.OFFICIAL_FP.values():
        print(fp)
PY
# Retain previous roots across NO_APPLY or an interrupted certificate rotation.
install -m 0600 "$RUN/old-root-fingerprints" "$BACKUP/script_root_fingerprints"
python3 "$CERT_STORE" --cert "$SIGN_CRT" --db "$XPACK_DB" --bak "$BACKUP/core_settings_license_rootcert.json"
if [ "${NO_APPLY:-0}" != 1 ]; then
  REPLACE_ARGS=()
  while IFS= read -r FP; do REPLACE_ARGS+=(--replace-root-fingerprint "$FP"); done < "$RUN/old-root-fingerprints"
  python3 "$GEN_LICENSE" --import-file "$LICENSE_OUT" --apply --db "$XPACK_DB" \
    --serial-path "$PANEL_ROOT/db/.serial" --no-restart "${REPLACE_ARGS[@]}"
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
if [ "${NO_APPLY:-0}" != 1 ]; then
  python3 "$GEN_LICENSE" --verify-db --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
fi
if [ "${NO_APPLY:-0}" = 1 ]; then log "Core/certificate replaced; license NOT applied (NO_APPLY=1)"
else log "Core/certificate replaced; offline license applied with automatic main-node binding"; fi
log "License and verified artifacts retained: $RUN"
log "Rollback: bash unlock.sh restore (official images: $BACKUP)"
