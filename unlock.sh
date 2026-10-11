#!/usr/bin/env bash
# Verified offline reinstall. Only use local signing keys; never download keys.
# STATE/SIGN_KEY: local material. LICENSE_FILE: pre-issued signed license.
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
MODE="${1:-install}"
log() { printf '== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }
trap 'printf "!! Failed; artifacts/backups retained: %s / %s\n" "$PERSIST" "$BACKUP" >&2' ERR
case "$MODE" in install|deploy|restore|verify|cert) ;; *) die "usage: $0 {install|restore|verify|cert}" ;; esac
[ "$(id -u)" -eq 0 ] || die "Run as root"
[ "$(uname -s)" = Linux ] || die "This release provides Linux cores"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  armv7l) ARCH=armv7 ;; ppc64le|s390x|riscv64) ARCH="$(uname -m)" ;;
  *) die "Unknown architecture: $(uname -m)" ;;
esac
PLATFORM="linux-$ARCH"
PANEL_CTL="${PANEL_CTL:-/usr/local/bin/1pctl}"
fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 2 -o "$2" "$1"; }
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
  python3 "$CERT_STORE" --check-owned --cert "$RESTORE_CRT" --db "$XPACK_DB"
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
  python3 "$CERT_STORE" --cert "$RESTORE_CRT" --db "$XPACK_DB" --bak "$BACKUP/core_settings_license_rootcert.json" --restore
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
if [[ "$MODE" = install || "$MODE" = deploy || "$MODE" = cert ]]; then
  python3 "$CERT_STORE" --check-owned --cert "$SIGN_CRT" --db "$XPACK_DB"
  python3 "$GEN_LICENSE" --preflight-db --db "$XPACK_DB" --serial-path "$PANEL_ROOT/db/.serial"
fi
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
  for FLAG in --db --serial-path --no-restart --preflight-db --verify-db; do
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
backup_orig "$RUN/core.orig" core
[ -z "$AGENT_SOURCE" ] || backup_orig "$RUN/agent.orig" agent
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
python3 "$CERT_STORE" --cert "$SIGN_CRT" --db "$XPACK_DB" --bak "$BACKUP/core_settings_license_rootcert.json"
if [ "${NO_APPLY:-0}" != 1 ]; then
  python3 "$GEN_LICENSE" --import-file "$LICENSE_OUT" --apply --db "$XPACK_DB" \
    --serial-path "$PANEL_ROOT/db/.serial" --no-restart
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
