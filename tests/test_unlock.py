"""Release-only installer tests. Every command and write uses temporary fixtures.

Run: python3 -m unittest discover -s tests -p test_unlock.py -v
Actual-tool smoke tests use only public tools and read-only build core originals.
No service, binary, database or signing key from a live installation is touched.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
URL_HK = b"https://license.lxware.hk/api/v1/"
URL_CN = b"https://license.lxware.cn/api/v1/"
PUBLIC_TOOLS = ("gen_license.py", "patch_core.py", "patch_agent.py", "cert_store.py",
                "aes128.py", "gosym.py", "official_rootcert.json")
PUBLIC_FILES = {"tools/" + name for name in PUBLIC_TOOLS} | {"state/license.crt"}
API_URL = "https://api.github.com/repos/fixture/xpack/releases?per_page=100"
INITIAL_CORE = b"fixture installed core, not a live binary"

PATCH_CORE = r'''
import argparse, hashlib, json, os, pathlib, ssl
with open(os.environ["EVENT_LOG"], "a") as f: f.write("code patch_core\n")
ROOT_FP_HK_ORIG = b"a" * 64
def build_table(data, remote_base=None, **kwargs):
    return [("P1.fp", 32, b"a"*64, None, ""),
            ("P2.fp", 96, b"b"*64, None, ""),
            ("C7.keep", 160, b"ORIG", b"KEEP", "")]
def main():
    p = argparse.ArgumentParser()
    for x in ("in", "out", "orig", "manifest", "remote-base"): p.add_argument("--"+x)
    p.add_argument("--patch", action="store_true")
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    data = bytearray(pathlib.Path(getattr(a, "in")).read_bytes())
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pathlib.Path(os.environ["SIGN_CRT"]).read_text())).hexdigest().encode()
    if a.patch:
        data[32:96] = fp; data[96:160] = fp; data[160:164] = b"KEEP"
        if os.environ.get("LEGACY_PATCHER"):
            data[164:164+len(b"https://license.lxware.hk/api/v1/")] = b"https://thirdparty.test/api/v1//"
        pathlib.Path(a.out).write_bytes(data)
        pathlib.Path(a.manifest).write_text("{}")
    elif data[32:96] != fp or data[96:160] != fp or data[160:164] != b"KEEP":
        raise SystemExit(2)
if __name__ == "__main__": main()
'''

PATCH_AGENT = r'''
import argparse, os, pathlib
with open(os.environ["EVENT_LOG"], "a") as f: f.write("code patch_agent\n")
def locate(data):
    return [("A1", 20, "original" if data[20:24] == b"ORIG" else
             "patched" if data[20:24] == b"KEEP" else "unknown", b"")]
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for x in ("in", "out", "orig", "manifest"): p.add_argument("--"+x)
    p.add_argument("--patch", action="store_true"); p.add_argument("--verify", action="store_true")
    a = p.parse_args(); data = bytearray(pathlib.Path(getattr(a, "in")).read_bytes())
    if a.patch:
        if locate(data)[0][2] != "original": raise SystemExit(2)
        data[20:24] = b"KEEP"; pathlib.Path(a.out).write_bytes(data)
        pathlib.Path(a.manifest).write_text("{}")
    elif locate(data)[0][2] != "patched": raise SystemExit(2)
'''

GEN_LICENSE = r'''
import argparse, json, os, pathlib, sqlite3
with open(os.environ["EVENT_LOG"], "a") as f: f.write("code gen_license\n")
def verify_license(text):
    d = json.loads(text)
    if d.get("signed") is not True: raise ValueError("Unsigned fixture license")
    return d
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for x in ("edition", "expires", "nodes", "assignee", "out", "import-file", "db", "serial-path", "export-existing"):
        p.add_argument("--"+x)
    p.add_argument("--replace-root-fingerprint", action="append", default=[])
    for x in ("offline", "apply", "no-restart", "verify-db"): p.add_argument("--"+x, action="store_true")
    a = p.parse_args()
    if a.export_existing:
        with sqlite3.connect(a.db) as c: row = c.execute("select license from licenses").fetchone()
        if not row: raise SystemExit(10)
        verify_license(row[0])
        pathlib.Path(a.export_existing).write_text(row[0])
        with open(os.environ["EVENT_LOG"], "a") as f: f.write("export-existing\n")
        raise SystemExit(0)
    if a.verify_db:
        if os.environ.get("FAIL_VERIFY_DB"): raise SystemExit(9)
        with sqlite3.connect(a.db) as c: row = c.execute("select bind_node_id,license from licenses").fetchone()
        assert row and row[0] == 17
        verify_license(row[1]); raise SystemExit(0)
    if a.out:
        assert a.db == os.environ["XPACK_DB"]
        assert a.serial_path == os.environ["PANEL_ROOT"] + "/db/.serial"
        assert pathlib.Path(os.environ["SIGN_KEY"]).is_file()
        d = {"signed": True, "offline": a.offline, "licenseName": "Enterprise",
             "assigneeName": a.assignee, "deviceID": "fixture-device",
             "products": [{"expiresAt": a.expires+"T00:00:00Z", "maxNodeCount": int(a.nodes)}]}
        pathlib.Path(a.out).write_text(json.dumps(d))
    if a.apply:
        if os.environ.get("FAIL_APPLY"): raise SystemExit(8)
        assert a.no_restart
        text = pathlib.Path(a.import_file).read_text(); verify_license(text)
        with sqlite3.connect(a.db) as c:
            node = c.execute("select id from nodes where local=1").fetchone()[0]
            c.execute("delete from licenses")
            c.execute("insert into licenses values (?,?)", (node, text))
        with open(os.environ["EVENT_LOG"], "a") as f:
            f.write("apply "+str(node)+" "+",".join(a.replace_root_fingerprint)+"\n")
'''

CERT_STORE = r'''
import argparse, hashlib, json, os, pathlib, sqlite3, ssl
with open(os.environ["EVENT_LOG"], "a") as f: f.write("code cert_store\n")
OFFICIAL_FP = {"hk": "a"*64, "cn": "b"*64}
def decrypt(v): return v
def fingerprint(pem): return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for x in ("cert", "db", "bak"): p.add_argument("--"+x)
    p.add_argument("--restore", action="store_true"); p.add_argument("--show", action="store_true")
    a = p.parse_args()
    if a.show: raise SystemExit(0)
    if os.environ.get("FAIL_CERT"): raise SystemExit(7)
    with sqlite3.connect(a.db) as c:
        if a.restore:
            c.execute("delete from core_settings")
            for key, value in json.loads(pathlib.Path(a.bak).read_text()).items():
                c.execute("insert into core_settings values (?,?)", (key, value))
        else:
            backup = pathlib.Path(a.bak)
            if not backup.exists():
                backup.write_text(json.dumps(dict(c.execute("select key,value from core_settings").fetchall())))
            pem = pathlib.Path(a.cert).read_text(); fp = fingerprint(pem)
            for key in ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint", "LicenseRootCertHK", "LicenseRootCertCN"):
                c.execute("delete from core_settings where key=?", (key,))
                value = fp if key.endswith("Fingerprint") else pem
                if os.environ.get("BAD_CERT_WRITE"): value = "invalid"
                c.execute("insert into core_settings values (?,?)", (key, value))
    with open(os.environ["EVENT_LOG"], "a") as f: f.write("cert "+("restore" if a.restore else "write")+"\n")
'''

MOCK_COMMAND = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, sys
name = pathlib.Path(sys.argv[0]).name; args = sys.argv[1:]
base = pathlib.Path(os.environ["FIXTURE_ROOT"]).resolve()
def confined(value):
    assert pathlib.Path(value).resolve().is_relative_to(base), "write escaped temporary fixture: " + value
with open(os.environ["EVENT_LOG"], "a") as f: f.write(name+" "+" ".join(args)+"\n")
if name == "id":
    assert args == ["-u"]; print("0")
elif name == "uname":
    assert args in (["-s"], ["-m"])
    print(os.environ.get("TEST_OS", "Linux") if args == ["-s"] else os.environ.get("TEST_ARCH", "x86_64"))
elif name == "systemctl":
    op = args[0]; service = args[-1]
    assert service in (os.environ["CORE_SVC"], os.environ["AGENT_SVC"])
    state = pathlib.Path(os.environ["MOCK_STATE"])/(service+".stopped")
    if os.environ.get("FAIL_SYSTEMCTL") == op: raise SystemExit(5)
    if op == "stop": state.touch()
    elif op == "start": state.unlink(missing_ok=True)
    elif op == "is-active":
        assert args[1] == "--quiet"
        if state.exists(): raise SystemExit(3)
    else: raise AssertionError("Unexpected service operation")
elif name == "install":
    src, dst = args[-2:]; confined(dst)
    if dst in (os.environ["CORE_BIN"], os.environ["AGENT_BIN"]):
        service = os.environ["CORE_SVC"] if dst == os.environ["CORE_BIN"] else os.environ["AGENT_SVC"]
        assert (pathlib.Path(os.environ["MOCK_STATE"])/(service+".stopped")).exists(), "replace before stop"
    if os.environ.get("FAIL_INSTALL") and dst == os.environ["CORE_BIN"]: raise SystemExit(6)
    raise SystemExit(subprocess.call([os.environ["REAL_INSTALL"]]+args))
elif name == "curl":
    url = args[-1]; dst = args[args.index("-o")+1]; confined(dst)
    if os.environ.get("FAIL_CURL"): raise SystemExit(22)
    urls = json.loads(pathlib.Path(os.environ["CURL_MAP"]).read_text())
    if url not in urls or not pathlib.Path(urls[url]).is_file():
        with open(os.environ["EVENT_LOG"], "a") as f: f.write("CURL_MISTAKE "+url+"\n")
        raise SystemExit(22)
    shutil.copyfile(urls[url], dst)
else: raise AssertionError("Unexpected mock command")
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Fixture:
    def __init__(self, base):
        self.base = Path(base)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.script = self.repo / "unlock.sh"
        shutil.copy2(ROOT / "unlock.sh", self.script)
        self.state = self.base / "local-state"
        self.state.mkdir()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(self.state / "license.key"), "-out", str(self.state / "license.crt"),
                        "-days", "1", "-subj", "/CN=temporary-unlock-test"],
                       capture_output=True, check=True, timeout=30)
        self.fp = sha(ssl.PEM_cert_to_DER_cert((self.state / "license.crt").read_text()))
        self.downloads = self.base / "downloads"
        self.assets = self.downloads / "assets"
        self.assets.mkdir(parents=True)
        self.public = {"tools/patch_core.py": PATCH_CORE.encode(), "tools/patch_agent.py": PATCH_AGENT.encode(),
                       "tools/gen_license.py": GEN_LICENSE.encode(), "tools/cert_store.py": CERT_STORE.encode(),
                       "tools/aes128.py": b"", "tools/gosym.py": b"", "tools/official_rootcert.json": b"{}",
                       "state/license.crt": (self.state / "license.crt").read_bytes()}
        self.man = {"schema_version": 2, "name": "xpack-toolkit", "version": "v2.3.2",
                    "mode": "offline", "remote_base": "", "root_fingerprint": self.fp, "platforms": {}}
        self.originals = {}
        self.outputs = {}
        for arch, machine in (("amd64", 62), ("arm64", 183)):
            head = bytearray(32); head[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", head, 18, machine)
            original = bytes(head) + b"a"*64 + b"b"*64 + b"ORIG" + URL_HK + URL_CN
            patched = bytes(head) + self.fp.encode()*2 + b"KEEP" + URL_HK + URL_CN
            self.set_core(arch, original, patched)
        self.pack_runtime()
        self.write_api()
        self.panel = self.base / "panel"
        (self.panel / "db").mkdir(parents=True)
        self.db = self.panel / "db/xpack.db"
        with sqlite3.connect(self.db) as c:
            c.executescript("create table core_settings(key text,value text);"
                            "create table licenses(bind_node_id int,license text);"
                            "create table nodes(id int,local int); insert into nodes values(17,1);")
        (self.panel / "db/.serial").write_text("fixture-device")
        self.core = self.base / "core"
        self.core.write_bytes(INITIAL_CORE)
        self.agent = self.base / "agent"
        self.work = self.base / "unlock-work"
        self.backup = self.base / "backup"
        self.events = self.base / "events"
        self.bin = self.base / "mock-bin"
        self.bin.mkdir()
        for name in ("systemctl", "curl", "install", "id", "uname"):
            path = self.bin / name; path.write_text(MOCK_COMMAND); path.chmod(0o755)
        self.env = {"PATH": str(self.bin)+os.pathsep+os.defpath, "HOME": str(self.base),
                    "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                    "PANEL_ROOT": str(self.panel), "CORE_BIN": str(self.core), "AGENT_BIN": str(self.agent),
                    "CORE_SVC": "fixture-core", "AGENT_SVC": "fixture-agent", "XPACK_DB": str(self.db),
                    "BACKUP": str(self.backup), "UNLOCK_WORK": str(self.work),
                    "STATE": str(self.state), "SIGN_CRT": str(self.state / "license.crt"),
                    "SIGN_KEY": str(self.state / "license.key"), "REPO": "fixture/xpack", "VERSION": "v2.3.2",
                    "EVENT_LOG": str(self.events), "MOCK_STATE": str(self.base), "FIXTURE_ROOT": str(self.base),
                    "CURL_MAP": str(self.downloads / "urls.json"), "REAL_INSTALL": shutil.which("install")}

    def set_core(self, arch, original, patched):
        self.originals[arch] = original; self.outputs[arch] = patched
        core = "core-linux-"+arch
        (self.assets / core).write_bytes(patched)
        (self.assets / (core+".orig")).write_bytes(original)
        self.man["platforms"]["linux-"+arch] = {
            "os": "linux", "arch": arch, "patches": 3, "core_asset": core, "orig_asset": core+".orig",
            "size": len(patched), "orig_size": len(original), "sha256": sha(patched), "orig_sha256": sha(original)}

    def pack_runtime(self, files=None, symlink=None, duplicate=None):
        files = self.public if files is None else files
        path = self.assets / "runtime.tar.gz"
        with tarfile.open(path, "w:gz") as tf:
            for name, data in files.items():
                item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o600
                if name == symlink:
                    item.type = tarfile.SYMTYPE; item.linkname = "../../escape"; item.size = 0
                    tf.addfile(item)
                else: tf.addfile(item, io.BytesIO(data))
            if duplicate:
                item = tarfile.TarInfo(duplicate); item.size = len(files[duplicate])
                tf.addfile(item, io.BytesIO(files[duplicate]))
        data = path.read_bytes()
        self.man["runtime"] = {"asset": "runtime.tar.gz", "size": len(data), "sha256": sha(data)}
        self.write_manifest()

    def write_manifest(self):
        (self.assets / "manifest.json").write_text(json.dumps(self.man))

    def write_api(self, releases=None):
        names = ("manifest.json", "runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig",
                 "core-linux-arm64", "core-linux-arm64.orig")
        assets = [{"name": name, "browser_download_url": self.asset_url(name)} for name in names]
        if releases is None:
            releases = [{"tag_name": "core-v9.9.9", "draft": True, "assets": assets},
                        {"tag_name": "core-v9.9.8", "prerelease": True, "assets": assets},
                        {"tag_name": "core-v2.3.2-amd64", "assets": assets},
                        {"tag_name": "core-v2.3.2", "draft": False, "prerelease": False, "assets": assets}]
        (self.downloads / "releases.json").write_text(json.dumps(releases))
        urls = {API_URL: str(self.downloads / "releases.json")}
        urls.update({self.asset_url(name): str(self.assets / name) for name in names})
        (self.downloads / "urls.json").write_text(json.dumps(urls))
        return releases

    @staticmethod
    def asset_url(name):
        return "https://github.com/fixture/xpack/releases/download/core-v2.3.2/"+name

    def run(self, mode="install", piped=False, **env):
        args = ["bash", "-s", "--", mode] if piped else ["bash", str(self.script), mode]
        return subprocess.run(args, input=self.script.read_text() if piped else None,
                              cwd=self.base, env={**self.env, **env}, capture_output=True, text=True, timeout=120)

    def log(self):
        return self.events.read_text() if self.events.exists() else ""

    def urls(self):
        return [line.split()[-1] for line in self.log().splitlines() if line.startswith("curl ")]

    def last_license(self):
        return max(self.work.glob("run.*/license.txt"), key=lambda p: p.stat().st_mtime_ns)


class UnlockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="public-unlock-test-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def before_stop(self, result, before_code=False):
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn("systemctl stop", self.f.log())
        self.assertEqual(self.f.core.read_bytes(), INITIAL_CORE)
        self.assertNotIn("CURL_MISTAKE", self.f.log())
        if before_code: self.assertNotIn("code ", self.f.log())

    def assert_downloads(self, arch, repetitions=1):
        expected = [API_URL] + [self.f.asset_url(name) for name in
                               ("manifest.json", "runtime.tar.gz", "core-linux-"+arch, "core-linux-"+arch+".orig")]
        self.assertEqual(self.f.urls(), expected*repetitions)
        self.assertNotIn("CURL_MISTAKE", self.f.log())
        self.assertNotIn("license.key", "\n".join(self.f.urls()))
        self.assertNotIn("raw.githubusercontent", self.f.log())

    def test_shell_syntax_single_entry(self):
        self.ok(subprocess.run(["bash", "-n", str(ROOT / "unlock.sh")], capture_output=True, text=True))

    def test_fresh_key_install_repeat_local_node_and_release_only(self):
        self.ok(self.f.run(NODES="42", EXPIRES="2035-01-01"))
        self.f.core.write_bytes(b"stale fixture core")
        self.ok(self.f.run(NODES="43", EXPIRES="2036-01-01"))
        self.assertEqual(self.f.core.read_bytes(), self.f.outputs["amd64"])
        with sqlite3.connect(self.f.db) as c: rows = c.execute("select bind_node_id,license from licenses").fetchall()
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0][0], 17)
        self.assertEqual(json.loads(rows[0][1])["products"][0]["maxNodeCount"], 43)
        self.assertEqual((self.f.backup / "1panel-core.orig").read_bytes(), self.f.originals["amd64"])
        self.assertIn("apply 17 "+self.f.fp, self.f.log())
        self.assert_downloads("amd64", 2)

    def test_cached_verify_restore_no_network_or_private_material(self):
        self.ok(self.f.run())
        before = self.f.urls()
        (self.f.state / "license.key").unlink()
        self.ok(self.f.run("verify", FAIL_CURL="1"))
        (self.f.state / "license.crt").unlink()
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        self.assertEqual(self.f.urls(), before)
        self.assertEqual(self.f.core.read_bytes(), self.f.originals["amd64"])

    def test_no_key_existing_signed_certificate_reused_without_resigning(self):
        self.ok(self.f.run(NODES="37", EXPIRES="2037-01-01"))
        issued = self.f.last_license().read_text()
        (self.f.state / "license.key").unlink()
        self.ok(self.f.run(NODES="999", EXPIRES="2099-12-31"))
        self.assertEqual(self.f.last_license().read_text(), issued)
        self.assertIn("export-existing", self.f.log())
        self.assert_downloads("amd64", 2)

    def test_no_key_no_existing_license_fails_before_stop(self):
        (self.f.state / "license.key").unlink()
        self.before_stop(self.f.run())

    def test_preissued_license_and_piped_entry_without_key(self):
        self.ok(self.f.run("cert"))
        issued = self.f.last_license()
        (self.f.state / "license.key").unlink()
        self.ok(self.f.run(piped=True, LICENSE_FILE=str(issued)))
        self.assertEqual(self.f.core.read_bytes(), self.f.outputs["amd64"])
        self.assertNotIn("license.key", "\n".join(self.f.urls()))

    def test_arm64_version_asset_selection_preserves_agent(self):
        self.f.agent.write_bytes(b"arm64 agent untouched")
        result = self.f.run(TEST_ARCH="aarch64", VERSION="2.3.2")
        self.ok(result)
        self.assertEqual(self.f.core.read_bytes(), self.f.outputs["arm64"])
        self.assertEqual(self.f.agent.read_bytes(), b"arm64 agent untouched")
        self.assertIn("preserving the installed arm64 agent", result.stdout)
        self.ok(self.f.run("verify", TEST_ARCH="aarch64", FAIL_CURL="1"))
        self.assert_downloads("arm64")

    def test_linux_and_unsupported_arch_rejected_before_stop(self):
        for override in ({"TEST_OS": "Darwin"}, {"TEST_ARCH": "mips64"}, {"TEST_ARCH": "armv7l"},
                         {"TEST_ARCH": "ppc64le"}, {"TEST_ARCH": "s390x"}, {"TEST_ARCH": "riscv64"}):
            with self.subTest(**override): self.before_stop(self.f.run(**override), before_code=True)

    def test_unadapted_official_four_version_fails_early(self):
        self.before_stop(self.f.run(VERSION="v2.3.4"), before_code=True)
        self.assertEqual(self.f.urls(), [API_URL])

    def test_missing_release_assets_do_not_guess_url(self):
        releases = self.f.write_api()
        release = releases[-1]
        for name in ("manifest.json", "runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig"):
            with self.subTest(name=name):
                bad = json.loads(json.dumps(release)); bad["assets"] = [a for a in bad["assets"] if a["name"] != name]
                self.f.write_api([bad]); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(), before_code=True)
                self.assertEqual(self.f.urls(), [API_URL])

    def test_api_failure_does_not_try_fallback(self):
        self.before_stop(self.f.run(FAIL_CURL="1"), before_code=True)
        self.assertEqual(self.f.urls(), [API_URL])

    def test_invalid_manifest_rejected_before_runtime_code(self):
        original = json.loads(json.dumps(self.f.man))
        for key, value in (("schema_version", 1), ("name", "core"), ("mode", "online"),
                           ("remote_base", "https://example.test/"), ("version", "v2.3.1"),
                           ("root_fingerprint", "0"*64)):
            with self.subTest(key=key):
                self.f.man = json.loads(json.dumps(original)); self.f.man[key] = value
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(), before_code=True)

    def test_platform_manifest_names_and_arch_rejected_before_code(self):
        original = json.loads(json.dumps(self.f.man))
        for key, value in (("arch", "arm64"), ("os", "darwin"), ("patches", 4),
                           ("core_asset", "core"), ("orig_asset", "core.orig")):
            with self.subTest(key=key):
                self.f.man = json.loads(json.dumps(original))
                self.f.man["platforms"]["linux-amd64"][key] = value
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(), before_code=True)

    def test_runtime_corruption_hash_size_and_asset_before_code(self):
        original = dict(self.f.man["runtime"])
        for key, value in (("sha256", "0"*64), ("size", 0), ("asset", "runtime.zip")):
            with self.subTest(key=key):
                self.f.man["runtime"] = dict(original, **{key: value})
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(), before_code=True)

    def test_runtime_whitelist_traversal_private_pem_symlink_duplicate(self):
        variants = ("traversal", "private-key", "pem-key", "extra", "missing", "symlink", "duplicate")
        for variant in variants:
            with self.subTest(variant=variant):
                files = dict(self.f.public)
                if variant == "traversal": files["../escape"] = files.pop("tools/gosym.py")
                if variant == "private-key": files["state/license.key"] = (self.f.state / "license.key").read_bytes()
                if variant == "pem-key": files["state/secret.pem"] = (self.f.state / "license.key").read_bytes()
                if variant == "extra": files["tools/extra.py"] = b"raise RuntimeError('must never run')"
                if variant == "missing": files.pop("tools/official_rootcert.json")
                self.f.pack_runtime(files, symlink="tools/gosym.py" if variant == "symlink" else None,
                                    duplicate="tools/gosym.py" if variant == "duplicate" else None)
                self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(), before_code=True)
                for runtime in self.f.work.glob("runtime.*"):
                    self.assertEqual(list(runtime.iterdir()), [])
                self.assertFalse((self.f.work / "escape").exists())

    def test_bundled_and_local_root_mismatch_before_stop(self):
        self.f.public["state/license.crt"] = b"invalid PEM"
        self.f.pack_runtime()
        self.before_stop(self.f.run(), before_code=True)
        self.f.public["state/license.crt"] = (self.f.state / "license.crt").read_bytes()
        self.f.pack_runtime(); self.f.events.unlink(missing_ok=True)
        self.f.man["root_fingerprint"] = "0"*64; self.f.write_manifest()
        self.before_stop(self.f.run(), before_code=True)

    def test_binary_sha_original_and_elf_rejected_before_stop(self):
        original = dict(self.f.man["platforms"]["linux-amd64"])
        for key, value in (("sha256", "0"*64), ("orig_sha256", None)):
            with self.subTest(key=key):
                self.f.man["platforms"]["linux-amd64"] = dict(original, **{key: value})
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run())
        for binary in ("core", "orig"):
            with self.subTest(binary=binary):
                self.f.man["platforms"]["linux-amd64"] = dict(original)
                raw = bytearray(self.f.outputs["amd64"] if binary == "core" else self.f.originals["amd64"])
                struct.pack_into("<H", raw, 18, 183)
                asset = "core-linux-amd64"+(".orig" if binary == "orig" else "")
                (self.f.assets / asset).write_bytes(raw)
                self.f.man["platforms"]["linux-amd64"]["orig_sha256" if binary == "orig" else "sha256"] = sha(raw)
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run())
                (self.f.assets / asset).write_bytes(self.f.originals["amd64"] if binary == "orig" else self.f.outputs["amd64"])

    def test_patched_original_and_modified_addresses_not_backed_up(self):
        for raw in (self.f.outputs["amd64"], self.f.originals["amd64"].replace(URL_HK, b"https://thirdparty.test/api/v1//")):
            with self.subTest(sha=sha(raw)):
                (self.f.assets / "core-linux-amd64.orig").write_bytes(raw)
                self.f.man["platforms"]["linux-amd64"]["orig_sha256"] = sha(raw)
                self.f.man["platforms"]["linux-amd64"]["orig_size"] = len(raw)
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run())
                self.assertFalse((self.f.backup / "1panel-core.orig").exists())

    def test_same_version_install_refreshes_runtime_instead_of_cache(self):
        self.ok(self.f.run())
        cached = Path((self.f.work / "runtime.path").read_text().strip())
        (cached / "tools/patch_core.py").write_text("raise RuntimeError('stale cache')")
        self.f.public["tools/gosym.py"] = b"# refreshed public runtime\n"
        self.f.pack_runtime()
        self.ok(self.f.run())
        refreshed = Path((self.f.work / "runtime.path").read_text().strip())
        self.assertNotEqual(cached, refreshed)
        self.assertEqual((refreshed / "tools/gosym.py").read_bytes(), self.f.public["tools/gosym.py"])
        self.assert_downloads("amd64", 2)

    def test_no_apply_retains_artifacts_and_never_imports_license(self):
        result = self.f.run(NO_APPLY="1"); self.ok(result)
        self.assertIn("license NOT applied", result.stdout)
        self.assertNotIn("apply 17", self.f.log())
        run = self.f.last_license().parent
        for name in ("license.txt", "manifest.json", "runtime.tar.gz", "core", "core.orig", "core.offline"):
            self.assertTrue((run / name).is_file(), name)
        runtime = Path((self.f.work / "runtime.path").read_text().strip())
        self.assertEqual({p.relative_to(runtime).as_posix() for p in runtime.rglob("*") if p.is_file()}, PUBLIC_FILES)
        self.ok(self.f.run("restore", FAIL_CURL="1"))

    def test_service_failure_has_no_success_message(self):
        for op in ("stop", "start", "is-active"):
            with self.subTest(op=op):
                result = self.f.run(FAIL_SYSTEMCTL=op)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("offline license applied with", result.stdout)
                self.assertNotIn("Rollback:", result.stdout)

    def test_install_cert_apply_readback_failure_propagates(self):
        for variable in ("FAIL_INSTALL", "FAIL_CERT", "FAIL_APPLY", "BAD_CERT_WRITE", "FAIL_VERIFY_DB"):
            with self.subTest(variable=variable):
                result = self.f.run(**{variable: "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("offline license applied with", result.stdout)

    def test_license_validation_fails_before_stop(self):
        self.ok(self.f.run("cert")); issued = self.f.last_license()
        original = json.loads(issued.read_text())
        for variant in ("unsigned", "online", "expired", "timezone", "device", "nodes", "serial"):
            with self.subTest(variant=variant):
                data = json.loads(json.dumps(original))
                if variant == "unsigned": data["signed"] = False
                if variant == "online": data["offline"] = False
                if variant == "expired": data["products"][0]["expiresAt"] = "2000-01-01T00:00:00Z"
                if variant == "timezone": data["products"][0]["expiresAt"] = "2099-12-31"
                if variant == "device": data["deviceID"] = ""
                if variant == "nodes": data["products"][0]["maxNodeCount"] = 0
                if variant == "serial": (self.f.panel / "db/.serial").write_text("another-device")
                issued.write_text(json.dumps(data)); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(LICENSE_FILE=str(issued)))

    def test_amd64_agent_repeat_and_restore(self):
        self.f.agent.write_bytes(b"\x00"*20+b"ORIG")
        self.ok(self.f.run()); self.ok(self.f.run())
        self.assertEqual(self.f.agent.read_bytes()[20:24], b"KEEP")
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        self.assertEqual(self.f.agent.read_bytes()[20:24], b"ORIG")

    def test_legacy_url_patcher_and_corrupt_restore_fail(self):
        self.before_stop(self.f.run(LEGACY_PATCHER="1"))
        self.ok(self.f.run())
        (self.f.backup / "1panel-core.orig").write_bytes(self.f.originals["amd64"]+b"tampered")
        before = self.f.log().count("systemctl stop")
        result = self.f.run("restore", FAIL_CURL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.log().count("systemctl stop"), before)

    def test_real_tools_encrypted_metadata_signature_binding_and_restore(self):
        available = [arch for arch in ("amd64", "arm64") if (ROOT / "build/releases" / arch / "core.orig").is_file()]
        if not available: self.skipTest("read-only official build/releases core.orig fixtures are absent")
        for arch in available:
            with self.subTest(arch=arch), tempfile.TemporaryDirectory(prefix="public-unlock-real-") as base:
                f = Fixture(base)
                tools = f.repo / "tools"; tools.mkdir()
                for name in PUBLIC_TOOLS:
                    shutil.copy2(ROOT / "tools" / name, tools / name)
                    f.public["tools/"+name] = (tools / name).read_bytes()
                original = (ROOT / "build/releases" / arch / "core.orig").read_bytes()
                (f.assets / ("core-linux-"+arch+".orig")).write_bytes(original)
                patched_path = f.assets / ("core-linux-"+arch)
                patch = subprocess.run([sys.executable, str(tools / "patch_core.py"), "--patch",
                                        "--in", str(f.assets / ("core-linux-"+arch+".orig")), "--out", str(patched_path),
                                        "--orig", str(f.assets / ("core-linux-"+arch+".orig")),
                                        "--manifest", str(f.base / "local-patch.json"), "--remote-base", ""],
                                       env=f.env, capture_output=True, text=True, timeout=120)
                self.ok(patch)
                f.set_core(arch, original, patched_path.read_bytes()); f.pack_runtime()
                f.env["TEST_ARCH"] = "x86_64" if arch == "amd64" else "aarch64"
                with sqlite3.connect(f.db) as c:
                    c.executescript("drop table core_settings; drop table nodes; drop table licenses;"
                                    "create table core_settings(id integer primary key,created_at text,updated_at text,"
                                    "key text,value text,description text);"
                                    "create table nodes(id integer primary key,name text);insert into nodes values(17,'local');")
                    fields = ("license_name usage_name assignee_name version_constraint device_id license offline trial issuer "
                              "product_pro last_sync_at sms_total sms_used bind_node_id free_count free_nodes status message")
                    c.execute("create table licenses(id integer primary key,created_at text,updated_at text,"+
                              ",".join('"%s" text' % name for name in fields.split())+")")
                (f.panel / "db/.serial").write_text("fixture-device-not-live")
                self.ok(f.run(NODES="43", EXPIRES="2036-01-01"))
                self.ok(f.run(NODES="44", EXPIRES="2037-01-01"))
                with sqlite3.connect(f.db) as c: license_id = c.execute("select id from licenses").fetchone()[0]
                issued = f.last_license()
                (f.state / "license.key").unlink()
                self.ok(f.run(LICENSE_FILE=str(issued)))
                self.ok(f.run(NODES="999", EXPIRES="2099-12-31"))
                self.ok(f.run("verify", FAIL_CURL="1"))
                self.assertEqual(sha(f.core.read_bytes()), f.man["platforms"]["linux-"+arch]["sha256"])
                code = r'''
import json, pathlib, sqlite3, sys
sys.path.insert(0, sys.argv[1]); import gen_license as g; import cert_store as cs
with sqlite3.connect(sys.argv[2]) as c:
    c.row_factory = sqlite3.Row
    rows = c.execute("select * from licenses").fetchall(); assert len(rows) == 1
    raw = dict(rows[0]); d = g.decrypt_row(raw); signed = g.verify_license(d["license"])
    assert raw["id"] == int(sys.argv[4])
    assert d["bind_node_id"] == "17" and d["free_count"] == "44"
    assert d["device_id"] == "fixture-device-not-live" and d["status"] == "Bound"
    assert raw["status"] != d["status"] and raw["license"] != d["license"]
    assert signed["offline"] is True and signed["products"][0]["maxNodeCount"] == 44
    assert signed["products"][0]["expiresAt"].startswith("2037-01-01")
    pem = pathlib.Path(sys.argv[3]).read_text(); fp = cs.fingerprint(pem)
    roots = c.execute("select key,value from core_settings").fetchall(); assert len(roots) == 4
    for row in roots:
        plain = cs.decrypt(row["value"]); assert plain != row["value"]
        assert plain == (fp if row["key"].endswith("Fingerprint") else pem)
parts = d["license"].split("-"); assert len(parts) == 3
parts[1] = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
try: g.verify_license("-".join(parts))
except ValueError: pass
else: raise AssertionError("Modified RSA signature accepted")
'''
                result = subprocess.run([sys.executable, "-c", code, str(tools), str(f.db),
                                         str(f.state / "license.crt"), str(license_id)],
                                        env=f.env, capture_output=True, text=True, timeout=30)
                self.ok(result)
                self.assertNotIn("CURL_MISTAKE", f.log())
                self.assertNotIn("license.key", "\n".join(f.urls()))
                other = "arm64" if arch == "amd64" else "amd64"
                self.assertFalse(any("core-linux-"+other in url for url in f.urls()))
                before = f.urls(); (f.state / "license.crt").unlink()
                self.ok(f.run("restore", FAIL_CURL="1"))
                self.assertEqual(f.urls(), before)
                self.assertEqual(sha(f.core.read_bytes()), sha(original))


if __name__ == "__main__":
    unittest.main()
