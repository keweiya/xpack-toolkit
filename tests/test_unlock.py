"""Release-only installer tests. Every command and write uses temporary fixtures.

Run: python3 -m unittest discover -s tests -p test_unlock.py -v
Actual-tool smoke tests use only public tools and read-only official build originals.
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
import argparse, hashlib, json, os, pathlib, sqlite3, sys
with open(os.environ["EVENT_LOG"], "a") as f: f.write("code gen_license "+" ".join(sys.argv[1:])+"\n")
def verify_license(text):
    d = json.loads(text)
    if d.get("signed") is not True: raise ValueError("Unsigned fixture license")
    if d.get("foreign"): raise ValueError("Wrong project signing key")
    return d
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for x in ("edition", "expires", "nodes", "assignee", "out", "import-file", "db", "serial-path", "export-existing", "foreign-backup-dir"):
        p.add_argument("--"+x)
    p.add_argument("--replace-root-fingerprint", action="append", default=[])
    for x in ("offline", "apply", "no-restart", "verify-db", "preflight-db", "preserve-foreign", "archive-foreign"): p.add_argument("--"+x, action="store_true")
    a = p.parse_args()
    if a.preflight_db:
        with sqlite3.connect("file:" + pathlib.Path(a.db).resolve().as_posix() + "?mode=ro", uri=True) as c:
            local = c.execute("select id from nodes where local=1").fetchone()
            rows = c.execute("select bind_node_id from licenses").fetchall()
        if not local or (not a.preserve_foreign and any(str(row[0]) != str(local[0]) for row in rows)):
            raise SystemExit("Foreign-bound fixture license")
        with open(os.environ["EVENT_LOG"], "a") as f: f.write("preflight-db\n")
        raise SystemExit(0)
    if a.export_existing:
        with sqlite3.connect(a.db) as c: rows = c.execute("select license from licenses").fetchall()
        matches = []
        for (text,) in rows:
            try: verify_license(text)
            except (ValueError, TypeError): continue
            matches.append(text)
        if len(matches) != 1: raise SystemExit(10)
        pathlib.Path(a.export_existing).write_text(matches[0])
        with open(os.environ["EVENT_LOG"], "a") as f: f.write("export-existing\n")
        raise SystemExit(0)
    if a.verify_db:
        if os.environ.get("FAIL_VERIFY_DB"): raise SystemExit(9)
        with sqlite3.connect(a.db) as c: rows = c.execute("select bind_node_id,license from licenses").fetchall()
        matches = [row for row in rows if row[0] == 17 and not json.loads(row[1]).get("foreign")]
        assert len(matches) == 1
        verify_license(matches[0][1]); raise SystemExit(0)
    if a.out:
        assert a.db == os.environ["XPACK_DB"]
        assert a.serial_path == os.environ["PANEL_ROOT"] + "/db/.serial"
        assert pathlib.Path(os.environ["SIGN_KEY"]).is_file()
        d = {"signed": True, "offline": a.offline, "licenseName": "Enterprise",
             "assigneeName": a.assignee, "deviceID": "fixture-device",
             "products": [{"expiresAt": a.expires+"T00:00:00Z", "maxNodeCount": int(a.nodes)}]}
        pathlib.Path(a.out).write_text(json.dumps(d))
    if a.archive_foreign:
        assert a.preserve_foreign and a.foreign_backup_dir
        verify_license(pathlib.Path(a.import_file).read_text())
        with sqlite3.connect(a.db) as c: rows = c.execute("select rowid,bind_node_id,license from licenses").fetchall()
        foreign = [row for row in rows if json.loads(row[2]).get("foreign")]
        if foreign:
            raw = json.dumps({"rows": [{"rowid": row[0], "bind_node_id": row[1], "license": row[2]} for row in foreign]}, sort_keys=True).encode()
            digest = hashlib.sha256(raw).hexdigest()
            backup = pathlib.Path(a.foreign_backup_dir)/("foreign-licenses."+digest+".json")
            backup.parent.mkdir(parents=True, exist_ok=True)
            if backup.exists(): assert backup.read_bytes() == raw
            else: backup.write_bytes(raw)
            pathlib.Path(str(backup)+".sha256").write_text(digest+"  "+str(backup)+"\n")
        raise SystemExit(0)
    if a.apply:
        if os.environ.get("FAIL_APPLY"): raise SystemExit(8)
        assert a.no_restart
        text = pathlib.Path(a.import_file).read_text(); verify_license(text)
        with sqlite3.connect(a.db) as c:
            node = c.execute("select id from nodes where local=1").fetchone()[0]
            rows = c.execute("select rowid,bind_node_id,license from licenses").fetchall()
            foreign = [row for row in rows if json.loads(row[2]).get("foreign")]
            if foreign and a.preserve_foreign:
                assert a.foreign_backup_dir
                raw = json.dumps({"rows": [{"rowid": row[0], "bind_node_id": row[1], "license": row[2]} for row in foreign]}, sort_keys=True).encode()
                digest = hashlib.sha256(raw).hexdigest()
                backup = pathlib.Path(a.foreign_backup_dir)/("foreign-licenses."+digest+".json")
                backup.parent.mkdir(parents=True, exist_ok=True)
                if backup.exists(): assert backup.read_bytes() == raw
                else: backup.write_bytes(raw)
                pathlib.Path(str(backup)+".sha256").write_text(digest+"  "+str(backup)+"\n")
                for row in foreign:
                    if str(row[1]) == str(node): c.execute("update licenses set bind_node_id=0 where rowid=?", (row[0],))
            elif any(str(row[1]) == str(node) for row in foreign): raise SystemExit("Foreign-bound fixture license")
            for row in rows:
                if row not in foreign: c.execute("delete from licenses where rowid=?", (row[0],))
            c.execute("insert into licenses values (?,?)", (node, text))
        with open(os.environ["EVENT_LOG"], "a") as f:
            f.write("apply "+str(node)+" "+",".join(a.replace_root_fingerprint)+"\n")
'''

CERT_STORE = r'''
import argparse, hashlib, json, os, pathlib, sqlite3, ssl, sys
with open(os.environ["EVENT_LOG"], "a") as f: f.write("code cert_store "+" ".join(sys.argv[1:])+"\n")
OFFICIAL_FP = {"hk": "a"*64, "cn": "b"*64}
def decrypt(v): return v
def fingerprint(pem): return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for x in ("cert", "db", "bak"): p.add_argument("--"+x)
    p.add_argument("--restore", action="store_true"); p.add_argument("--show", action="store_true")
    p.add_argument("--check-owned", action="store_true")
    p.add_argument("--preserve-foreign", action="store_true")
    p.add_argument("--archive-current", action="store_true")
    a = p.parse_args()
    if a.show: raise SystemExit(0)
    if a.check_owned:
        pem = pathlib.Path(a.cert).read_text(); fp = fingerprint(pem)
        with sqlite3.connect("file:" + pathlib.Path(a.db).resolve().as_posix() + "?mode=ro", uri=True) as c:
            roots = c.execute("select key,value from core_settings where key in (?, ?, ?, ?)",
                ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint", "LicenseRootCertHK", "LicenseRootCertCN")).fetchall()
        for key, value in roots:
            allowed = {fp, OFFICIAL_FP["hk"], OFFICIAL_FP["cn"]} if key.endswith("Fingerprint") else {pem}
            if value not in allowed and not a.preserve_foreign: raise SystemExit("Unknown fixture root")
        with open(os.environ["EVENT_LOG"], "a") as f: f.write("check-owned\n")
        raise SystemExit(0)
    if a.archive_current:
        assert a.preserve_foreign
        with sqlite3.connect(a.db) as c:
            rows = dict(c.execute("select key,value from core_settings where key in (?, ?, ?, ?)",
                ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint", "LicenseRootCertHK", "LicenseRootCertCN")).fetchall())
        pem = pathlib.Path(a.cert).read_text(); fp = fingerprint(pem)
        if rows and any(value != (fp if key.endswith("Fingerprint") else pem) for key, value in rows.items()):
            backup = pathlib.Path(a.bak)
            if not backup.exists(): backup.write_text(json.dumps(rows))
            preserved = pathlib.Path(str(backup)+".preserved.json")
            raw = json.dumps(rows, sort_keys=True).encode()
            if not preserved.exists(): preserved.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            archived = backup.parent/("core_settings_license_rootcert.preserved."+digest+".json")
            if not archived.exists(): archived.write_bytes(raw)
            pathlib.Path(str(preserved)+".sha256").write_text(hashlib.sha256(preserved.read_bytes()).hexdigest()+"  "+str(preserved)+"\n")
        raise SystemExit(0)
    if os.environ.get("FAIL_CERT"): raise SystemExit(7)
    with sqlite3.connect(a.db) as c:
        if a.restore:
            c.execute("delete from core_settings where key in (?, ?, ?, ?)",
                ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint", "LicenseRootCertHK", "LicenseRootCertCN"))
            for key, value in json.loads(pathlib.Path(a.bak).read_text()).items():
                if key in ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint", "LicenseRootCertHK", "LicenseRootCertCN"):
                    c.execute("insert into core_settings values (?,?)", (key, value))
        else:
            backup = pathlib.Path(a.bak)
            rows = dict(c.execute("select key,value from core_settings where key in (?, ?, ?, ?)",
                ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint", "LicenseRootCertHK", "LicenseRootCertCN")).fetchall())
            if not backup.exists(): backup.write_text(json.dumps(rows))
            if a.preserve_foreign:
                preserved = pathlib.Path(str(backup)+".preserved.json")
                raw = json.dumps(rows, sort_keys=True).encode()
                if not preserved.exists(): preserved.write_bytes(raw)
                pathlib.Path(str(preserved)+".sha256").write_text(hashlib.sha256(preserved.read_bytes()).hexdigest()+"  "+str(preserved)+"\n")
            pem = pathlib.Path(a.cert).read_text(); fp = fingerprint(pem)
            for key in ("LicenseRootCertHKFingerprint", "LicenseRootCertCNFingerprint", "LicenseRootCertHK", "LicenseRootCertCN"):
                c.execute("delete from core_settings where key=?", (key,))
                value = fp if key.endswith("Fingerprint") else pem
                if os.environ.get("BAD_CERT_WRITE"): value = "invalid"
                c.execute("insert into core_settings values (?,?)", (key, value))
    with open(os.environ["EVENT_LOG"], "a") as f: f.write("cert "+("restore" if a.restore else "write")+"\n")
'''

MOCK_COMMAND = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, subprocess, sys
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
elif name in ("core", "1pctl"):
    assert args == ["version"], "version detection attempted a non-version command"
    assert sys.stdin.read() == "", "version command must receive DEVNULL stdin"
    if os.environ.get("TEST_VERSIONFAIL"): raise SystemExit(4)
    print("1Panel version: " + os.environ.get("TEST_VERSION", "v2.3.2"))
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
    trace = os.environ.get("CURL_TRACE")
    if trace:
        with open(trace, "a") as f:
            f.write(json.dumps({"args": args, "proxy_env": {key: os.environ[key] for key in
                ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")
                if key in os.environ}})+"\n")
    api = os.environ.get("API_URL_CHECK", "")
    original_url = url[url.find(api):] if api and api in url else url
    if api and original_url == api:
        assert pathlib.Path(dst).resolve().is_relative_to(pathlib.Path(os.environ["TMPDIR"]).resolve())
        assert not pathlib.Path(os.environ["UNLOCK_WORK"]).exists(), "persistent runtime before first API"
        assert not pathlib.Path(os.environ["BACKUP"]).exists(), "backup before first API"
        watched = json.loads(pathlib.Path(os.environ["API_SNAPSHOT"]).read_text())
        for filename, expected in watched.items():
            path = pathlib.Path(filename)
            actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
            assert actual == expected, "machine data changed before first API: " + filename
        assert not list(pathlib.Path(os.environ["MOCK_STATE"]).glob("*.stopped"))
        with open(os.environ["EVENT_LOG"], "a") as f: f.write("first-api-readonly\n")
    if os.environ.get("FAIL_CURL"): raise SystemExit(22)
    failures = os.environ.get("MOCKFAIL_URLS")
    failures = json.loads(pathlib.Path(failures).read_text()) if failures else {}
    if url in failures:
        pathlib.Path(dst).write_bytes(b"incomplete HTTP response")
        raise SystemExit(int(failures[url]))
    bad_map = os.environ.get("CURL_BAD_MAP")
    bad_map = json.loads(pathlib.Path(bad_map).read_text()) if bad_map else {}
    if url in bad_map:
        shutil.copyfile(bad_map[url], dst)
        raise SystemExit(0)
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
        self.extra_urls = {}
        self.public = {"tools/patch_core.py": PATCH_CORE.encode(), "tools/patch_agent.py": PATCH_AGENT.encode(),
                       "tools/gen_license.py": GEN_LICENSE.encode(), "tools/cert_store.py": CERT_STORE.encode(),
                       "tools/aes128.py": b"", "tools/gosym.py": b"", "tools/official_rootcert.json": b"{}",
                       "state/license.crt": (self.state / "license.crt").read_bytes()}
        self.man = {"schema_version": 2, "name": "xpack-toolkit", "version": "v2.3.2",
                    "mode": "offline", "remote_base": "", "root_fingerprint": self.fp, "platforms": {}}
        self.originals = {}
        self.outputs = {}
        self.agent_originals = {}
        for arch, machine in (("amd64", 62), ("arm64", 183)):
            head = bytearray(32); head[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", head, 18, machine)
            original = bytes(head) + b"a"*64 + b"b"*64 + b"ORIG" + URL_HK + URL_CN
            patched = bytes(head) + self.fp.encode()*2 + b"KEEP" + URL_HK + URL_CN
            self.set_core(arch, original, patched)
            head[20:24] = b"ORIG"
            self.set_agent(arch, bytes(head) + b"trusted official agent fixture")
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
        self.ctl = self.base / "1pctl"
        self.ctl.write_text("#!/bin/sh\nORIGINAL_VERSION='v2.3.2'\n")
        self.work = self.base / "unlock-work"
        self.backup = self.base / "backup"
        self.events = self.base / "events"
        self.bin = self.base / "mock-bin"
        self.bin.mkdir()
        self.temporary = self.base / "tmp"
        self.temporary.mkdir()
        for name in ("systemctl", "curl", "install", "id", "uname", "1pctl"):
            path = self.bin / name; path.write_text(MOCK_COMMAND); path.chmod(0o755)
        self.env = {"PATH": str(self.bin)+os.pathsep+os.defpath, "HOME": str(self.base),
                    "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(self.temporary),
                    "PANEL_ROOT": str(self.panel), "CORE_BIN": str(self.core), "AGENT_BIN": str(self.agent),
                    "CORE_SVC": "fixture-core", "AGENT_SVC": "fixture-agent", "XPACK_DB": str(self.db),
                    "BACKUP": str(self.backup), "UNLOCK_WORK": str(self.work),
                    "STATE": str(self.state), "SIGN_CRT": str(self.state / "license.crt"),
                    "SIGN_KEY": str(self.state / "license.key"), "REPO": "fixture/xpack", "VERSION": "v2.3.2",
                    "EVENT_LOG": str(self.events), "MOCK_STATE": str(self.base), "FIXTURE_ROOT": str(self.base),
                    "CURL_MAP": str(self.downloads / "urls.json"), "REAL_INSTALL": shutil.which("install"),
                    "GH_MIRRORS": "", "CURL_TRACE": str(self.downloads / "curl-trace.jsonl")}

        self.env["PANEL_CTL"] = str(self.ctl)

    def set_core(self, arch, original, patched):
        self.originals[arch] = original; self.outputs[arch] = patched
        core = "core-linux-"+arch
        (self.assets / core).write_bytes(patched)
        (self.assets / (core+".orig")).write_bytes(original)
        self.man["platforms"].setdefault("linux-"+arch, {}).update({
            "os": "linux", "arch": arch, "patches": 3, "core_asset": core, "orig_asset": core+".orig",
            "size": len(patched), "orig_size": len(original), "sha256": sha(patched), "orig_sha256": sha(original)})

    def set_agent(self, arch, original):
        self.agent_originals[arch] = original
        asset = "agent-linux-"+arch+".orig"
        (self.assets / asset).write_bytes(original)
        self.man["platforms"]["linux-"+arch].update({
            "agent_orig_asset": asset, "agent_orig_sha256": sha(original), "agent_orig_size": len(original)})

    def installed_version(self, version):
        with sqlite3.connect(self.panel / "db/core.db") as c:
            c.execute("create table if not exists settings(key text,value text)")
            c.execute("delete from settings where key='SystemVersion'")
            c.execute("insert into settings values('SystemVersion',?)", (version,))

    def executable_core(self):
        self.core.write_text(MOCK_COMMAND)
        self.core.chmod(0o755)

    @staticmethod
    def backup_file(path, data, checksum=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        Path(str(path)+".sha256").write_text((checksum or sha(data))+"  "+str(path)+"\n")

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
                 "core-linux-arm64", "core-linux-arm64.orig", "agent-linux-amd64.orig", "agent-linux-arm64.orig")
        assets = [{"name": name, "browser_download_url": self.asset_url(name)} for name in names]
        if releases is None:
            releases = [{"tag_name": "core-v9.9.9", "draft": True, "assets": assets},
                        {"tag_name": "core-v9.9.8", "prerelease": True, "assets": assets},
                        {"tag_name": "core-v2.3.2-amd64", "assets": assets},
                        {"tag_name": "core-" + self.man["version"], "draft": False, "prerelease": False, "assets": assets}]
        (self.downloads / "releases.json").write_text(json.dumps(releases))
        urls = {API_URL: str(self.downloads / "releases.json")}
        urls.update({self.asset_url(name): str(self.assets / name) for name in names})
        urls.update(self.extra_urls)
        (self.downloads / "urls.json").write_text(json.dumps(urls))
        return releases

    def asset_url(self, name, version=None):
        version = self.man["version"] if version is None else version
        return "https://github.com/fixture/xpack/releases/download/core-"+version+"/"+name

    def mirror_urls(self, prefixes):
        path = Path(self.env["CURL_MAP"])
        urls = json.loads(path.read_text())
        originals = {url: filename for url, filename in urls.items()
                     if url.startswith(("https://github.com/", "https://api.github.com/",
                                        "https://raw.githubusercontent.com/"))}
        for prefix in prefixes:
            urls.update({prefix.rstrip("/")+"/"+url: filename for url, filename in originals.items()})
        path.write_text(json.dumps(urls))

    def curl_failures(self, urls):
        path = self.downloads / "curl-failures.json"
        path.write_text(json.dumps({url: 22 for url in urls} if not isinstance(urls, dict) else urls))
        self.env["MOCKFAIL_URLS"] = str(path)

    def curl_responses(self, responses):
        mapping = {}
        for index, (url, data) in enumerate(responses.items()):
            path = self.downloads / ("curl-response-%d" % index)
            path.write_bytes(data.encode() if isinstance(data, str) else data)
            mapping[url] = str(path)
        path = self.downloads / "curl-bad-map.json"
        path.write_text(json.dumps(mapping))
        self.env["CURL_BAD_MAP"] = str(path)

    def curl_trace(self):
        path = Path(self.env["CURL_TRACE"])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def set_target_version(self, version):
        self.man["version"] = version
        self.write_manifest()
        self.write_api()

    def release_for(self, version, missing=(), **metadata):
        directory = self.downloads / "versions" / version
        directory.mkdir(parents=True, exist_ok=True)
        assets = []
        for source in self.assets.iterdir():
            if not source.is_file(): continue
            target = directory / source.name
            if source.name == "manifest.json":
                manifest = json.loads(source.read_text()); manifest["version"] = version
                target.write_text(json.dumps(manifest))
            else:
                shutil.copyfile(source, target)
            url = self.asset_url(source.name, version)
            self.extra_urls[url] = str(target)
            if source.name not in missing:
                assets.append({"name": source.name, "browser_download_url": url})
        return {"tag_name": "core-" + version, "draft": False, "prerelease": False,
                "assets": assets, **metadata}

    def machine_snapshot(self):
        paths = [self.core, self.agent, self.ctl]
        for directory in (self.panel, self.state, self.backup):
            if directory.is_dir(): paths.extend(directory.rglob("*"))
        return {str(path): sha(path.read_bytes()) for path in paths if path.is_file()}

    def guard_first_api(self):
        snapshot = self.base / "api-snapshot.json"
        watched = self.machine_snapshot()
        watched[str(self.agent)] = sha(self.agent.read_bytes()) if self.agent.is_file() else None
        snapshot.write_text(json.dumps(watched))
        self.env.update({"API_URL_CHECK": API_URL, "API_SNAPSHOT": str(snapshot)})

    def run(self, mode="install", piped=False, **env):
        args = ["bash", "-s", "--"] if piped else ["bash", str(self.script)]
        if mode is not None: args.append(mode)
        return subprocess.run(args, input=self.script.read_text() if piped else None,
                              cwd=self.base, env={**self.env, **env}, capture_output=True, text=True, timeout=120)

    def log(self):
        return self.events.read_text() if self.events.exists() else ""

    def urls(self):
        return [line.split()[-1] for line in self.log().splitlines() if line.startswith("curl ")]

    def last_license(self):
        return max(self.work.glob("run.*/license.txt"), key=lambda p: p.stat().st_mtime_ns)

    def real_license_tools(self):
        tools = self.repo / "tools"
        tools.mkdir(exist_ok=True)
        for name in PUBLIC_TOOLS:
            shutil.copy2(ROOT / "tools" / name, tools / name)
            if name not in ("patch_core.py", "patch_agent.py", "gosym.py"):
                self.public["tools/"+name] = (tools / name).read_bytes()
        with sqlite3.connect(self.db) as c:
            c.executescript("drop table core_settings; drop table nodes; drop table licenses;"
                            "create table core_settings(id integer primary key,created_at text,updated_at text,"
                            "key text,value text,description text);"
                            "create table nodes(id integer primary key,name text);insert into nodes values(17,'local');")
            fields = ("license_name usage_name assignee_name version_constraint device_id license offline trial issuer "
                      "product_pro last_sync_at sms_total sms_used bind_node_id free_count free_nodes status message")
            c.execute("create table licenses(id integer primary key,created_at text,updated_at text,"+
                      ",".join('"%s" text' % name for name in fields.split())+")")
            c.execute("insert into core_settings(key,value,description) values('UnrelatedSetting','keep','application metadata')")
        self.pack_runtime()
        return tools

    def real_foreign_fixture(self):
        tools = self.real_license_tools()
        foreign = self.base / "foreign-state"; foreign.mkdir()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(foreign / "license.key"), "-out", str(foreign / "license.crt"),
                        "-days", "1", "-subj", "/CN=temporary-foreign-unlock-test"],
                       capture_output=True, check=True, timeout=30)
        code = r'''
import json, pathlib, sqlite3, sys
sys.path.insert(0, sys.argv[1]); import gen_license as g; import cert_store as cs
pem = pathlib.Path(g.SIGN_CRT).read_text()
cs.write(sys.argv[2], pem, cs.fingerprint(pem))
content, row = g.build("enterprise", "2037-01-01", 23, "foreign-assignee", "fixture-device", "foreign-issuer", 7, False, True, "2.x")
row.update(license=g.encode_license(content), bind_node_id="17", free_nodes='["foreign-child"]',
           message="foreign message", created_at="foreign-created", updated_at="foreign-updated", id=41)
encrypted = g.encrypt_row(row)
with sqlite3.connect(sys.argv[2]) as c:
    c.execute("insert into licenses (%s) values (%s)" % (",".join(encrypted), ",".join("?" * len(encrypted))), list(encrypted.values()))
'''
        result = subprocess.run([sys.executable, "-c", code, str(tools), str(self.db)],
                                env={**self.env, "SIGN_KEY": str(foreign / "license.key"),
                                     "SIGN_CRT": str(foreign / "license.crt")},
                                capture_output=True, text=True, timeout=30)
        if result.returncode: raise AssertionError(result.stdout+result.stderr)
        return tools, foreign

    def rows(self, table):
        with sqlite3.connect(self.db) as c:
            c.row_factory = sqlite3.Row
            return [dict(row) for row in c.execute("select * from "+table+" order by id")]

    def root_values(self):
        with sqlite3.connect(self.db) as c:
            return dict(c.execute("select key,value from core_settings where key like 'LicenseRootCert%'"))

    def real_project_license(self, tools):
        issued = self.base / "project-license.txt"
        result = subprocess.run([sys.executable, str(tools / "gen_license.py"), "--offline",
                                 "--expires", "2038-01-01", "--nodes", "42", "--db", str(self.db),
                                 "--serial-path", str(self.panel / "db/.serial"), "--out", str(issued)],
                                env=self.env, capture_output=True, text=True, timeout=30)
        if result.returncode: raise AssertionError(result.stdout+result.stderr)
        return issued


class UnlockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="public-unlock-test-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def before_stop(self, result, before_code=False, original=INITIAL_CORE):
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn("systemctl stop", self.f.log())
        self.assertEqual(self.f.core.read_bytes(), original)
        self.assertNotIn("CURL_MISTAKE", self.f.log())
        if before_code: self.assertNotIn("code ", self.f.log())

    def assert_downloads(self, arch, repetitions=1, agent=False):
        expected = [API_URL] + [self.f.asset_url(name) for name in
                               ("manifest.json", "runtime.tar.gz", "core-linux-"+arch, "core-linux-"+arch+".orig")]
        if agent: expected.append(self.f.asset_url("agent-linux-"+arch+".orig"))
        self.assertEqual(self.f.urls(), expected*repetitions)
        self.assertNotIn("CURL_MISTAKE", self.f.log())
        self.assertNotIn("license.key", "\n".join(self.f.urls()))
        self.assertNotIn("raw.githubusercontent", self.f.log())

    def assert_version_preflight_exit(self, result, snapshot=None, network=True, original=INITIAL_CORE):
        self.before_stop(result, before_code=True, original=original)
        self.assertEqual(self.f.urls(), [API_URL] if network else [])
        self.assertFalse(self.f.work.exists())
        self.assertFalse(self.f.backup.exists())
        self.assertEqual(list(self.f.temporary.iterdir()), [])
        if snapshot is not None:
            self.assertEqual(self.f.machine_snapshot(), snapshot)

    def test_highest_semver_numeric_equal_newer_and_older_matrix(self):
        cases = (("v2.3.2", "v2.3.2", True), ("v3.0.0", "v2.99.99", True),
                 ("v2.10.0", "v2.9.99", True), ("v2.3.10", "v2.3.9", True),
                 ("v2.9.99", "v2.10.0", False), ("v2.3.9", "v2.3.10", False),
                 ("v2.99.99", "v3.0.0", False), ("v0.0.1", "v0.0.0", True))
        for target, installed, allowed in cases:
            with self.subTest(target=target, installed=installed), tempfile.TemporaryDirectory(prefix="public-version-") as base:
                self.f = Fixture(base)
                self.f.set_target_version(target); self.f.installed_version(installed)
                before = self.f.machine_snapshot(); self.f.guard_first_api()
                result = self.f.run(VERSION="v1.0.0")
                if allowed:
                    self.ok(result); self.assert_downloads("amd64")
                    self.assertEqual(self.f.core.read_bytes(), self.f.outputs["amd64"])
                else:
                    self.assert_version_preflight_exit(result, before)
                self.assertIn("first-api-readonly", self.f.log())

    def test_highest_release_uses_numeric_tag_not_api_order_or_created_latest(self):
        latest_created = self.f.release_for("v2.9.9", created_at="2099-01-01T00:00:00Z",
                                             published_at="2099-01-01T00:00:00Z")
        highest = self.f.release_for("v2.10.0", created_at="2020-01-01T00:00:00Z",
                                    published_at="2020-01-01T00:00:00Z")
        older = self.f.release_for("v2.3.2")
        self.f.write_api([latest_created, older, highest])
        self.f.installed_version("v2.9.9")
        self.ok(self.f.run())
        self.assertEqual(self.f.urls(), [API_URL] + [self.f.asset_url(name, "v2.10.0") for name in
                         ("manifest.json", "runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig")])
        self.assertEqual(json.loads((self.f.last_license().parent / "manifest.json").read_text())["version"], "v2.10.0")

    def test_malformed_draft_prerelease_and_rc_tags_are_ignored(self):
        stable = self.f.release_for("v2.3.2")
        ignored = []
        for tag in ("core-v99.0.0-rc.1", "core-v99.0.0-amd64", "core-v99.0",
                    "core-99.0.0", "v99.0.0", "core-v99.0.0+build", "core-v99.0.0\n"):
            release = dict(stable, tag_name=tag, draft=False, prerelease=False)
            ignored.append(release)
        ignored.extend((dict(stable, tag_name="core-v99.0.0", draft=True),
                        dict(stable, tag_name="core-v98.0.0", prerelease=True)))
        self.f.write_api(ignored + [stable])
        self.ok(self.f.run())
        self.assert_downloads("amd64")

    def test_highest_missing_architecture_never_falls_back_to_older_supported_tag(self):
        for arch, machine in (("amd64", "x86_64"), ("arm64", "aarch64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory(prefix="public-version-arch-") as base:
                self.f = Fixture(base)
                older = self.f.release_for("v2.3.2")
                highest = self.f.release_for("v2.4.0", missing=("core-linux-"+arch, "core-linux-"+arch+".orig"))
                self.f.write_api([older, highest]); before = self.f.machine_snapshot()
                self.assert_version_preflight_exit(self.f.run(TEST_ARCH=machine), before)

    def test_highest_missing_official_agent_never_falls_back_to_older_tag(self):
        self.f.agent.write_bytes(b"installed agent sentinel")
        highest = self.f.release_for("v2.4.0", missing=("agent-linux-amd64.orig",))
        older = self.f.release_for("v2.3.2")
        self.f.write_api([older, highest]); before = self.f.machine_snapshot()
        self.assert_version_preflight_exit(self.f.run(), before)

    def test_valid_version_env_cannot_bypass_newer_installed_database(self):
        self.f.installed_version("v2.10.0")
        self.f.executable_core()
        original = self.f.core.read_bytes()
        before = self.f.machine_snapshot()
        result = self.f.run(VERSION="v2.3.2", TEST_VERSION="v2.3.2")
        self.assert_version_preflight_exit(result, before, original=original)
        self.assertNotIn("core version", self.f.log())

    def test_first_network_api_precedes_detection_and_all_persistent_mutations(self):
        self.f.executable_core(); self.f.ctl.unlink()
        app = self.f.panel / "apps/example/data"; app.mkdir(parents=True)
        (app / "keep.txt").write_bytes(b"application sentinel")
        with sqlite3.connect(self.f.db) as c:
            c.execute("insert into core_settings values('UnrelatedSetting','keep')")
        self.f.guard_first_api()
        self.ok(self.f.run(VERSION="", TEST_VERSION="v2.3.2"))
        self.assertLess(self.f.log().index("first-api-readonly"), self.f.log().index("core version"))
        self.assert_downloads("amd64")
        self.assertEqual((app / "keep.txt").read_bytes(), b"application sentinel")
        self.assertEqual(list(self.f.temporary.iterdir()), [])

    def test_local_manifest_higher_version_is_selected_without_network(self):
        self.f.installed_version("v2.3.2")
        self.f.set_target_version("v2.10.0")
        self.ok(self.f.run(ARTIFACT_DIR=str(self.f.assets), VERSION="v2.3.2", FAIL_CURL="1"))
        self.assertEqual(self.f.urls(), [])
        self.assertEqual(json.loads((self.f.last_license().parent / "manifest.json").read_text())["version"], "v2.10.0")

    def test_local_manifest_lower_version_exits_before_persistent_or_machine_edits(self):
        self.f.installed_version("v2.10.0")
        self.f.set_target_version("v2.9.99")
        before = self.f.machine_snapshot()
        self.assert_version_preflight_exit(self.f.run(ARTIFACT_DIR=str(self.f.assets), VERSION="v2.9.99"),
                                           before, network=False)

    def test_unknown_actual_version_never_uses_valid_version_env_fallback(self):
        self.f.ctl.write_text("#!/bin/sh\nORIGINAL_VERSION='unknown'\n")
        before = self.f.machine_snapshot(); self.f.guard_first_api()
        self.assert_version_preflight_exit(self.f.run(VERSION="v2.3.2"), before)

    def test_foreign_bound_license_db_is_archived_then_project_bound(self):
        text = json.dumps({"signed": True, "foreign": True, "metadata": "untouched"})
        with sqlite3.connect(self.f.db) as c:
            c.execute("insert into licenses values(17,?)", (text,))
        self.ok(self.f.run())
        with sqlite3.connect(self.f.db) as c: rows = c.execute("select bind_node_id,license from licenses order by rowid").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], (0, text)); self.assertEqual(rows[1][0], 17)
        archives = list(self.f.backup.glob("foreign-licenses.*.json")); self.assertEqual(len(archives), 1)
        self.assertEqual(json.loads(archives[0].read_text())["rows"][0]["license"], text)
        self.assertIn("--preserve-foreign --foreign-backup-dir", self.f.log())

    def test_unknown_root_and_history_migrate_without_touching_other_keys(self):
        foreign = "c"*64
        with sqlite3.connect(self.f.db) as c:
            c.execute("insert into core_settings values('LicenseRootCertHKFingerprint',?)", (foreign,))
            c.execute("insert into core_settings values('UnrelatedSetting','keep')")
        self.f.backup.mkdir()
        (self.f.backup / "script_root_fingerprints").write_text(foreign+"\n")
        self.ok(self.f.run())
        preserved = self.f.backup / "core_settings_license_rootcert.json.preserved.json"
        self.assertEqual(json.loads(preserved.read_text())["LicenseRootCertHKFingerprint"], foreign)
        self.assertEqual((self.f.backup / "script_root_fingerprints").read_text(), self.f.fp+"\n")
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        with sqlite3.connect(self.f.db) as c: settings = dict(c.execute("select key,value from core_settings"))
        self.assertEqual(settings, {"LicenseRootCertHKFingerprint": foreign, "UnrelatedSetting": "keep"})

    def test_known_official_project_roots_preserve_unrelated_settings_and_restore(self):
        with sqlite3.connect(self.f.db) as c:
            c.executemany("insert into core_settings values(?,?)", (
                ("LicenseRootCertHKFingerprint", "a"*64), ("LicenseRootCertCNFingerprint", "b"*64),
                ("UnrelatedSetting", "application sentinel")))
        self.ok(self.f.run())
        self.ok(self.f.run())
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        with sqlite3.connect(self.f.db) as c:
            settings = dict(c.execute("select key,value from core_settings"))
        self.assertEqual(settings, {"LicenseRootCertHKFingerprint": "a"*64,
                                    "LicenseRootCertCNFingerprint": "b"*64,
                                    "UnrelatedSetting": "application sentinel"})

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
        self.assertIn("apply 17 \n", self.f.log())
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

    def test_no_key_no_existing_license_installs_pending(self):
        (self.f.state / "license.key").unlink()
        self.f.agent.write_bytes(b"foreign agent without signing material")
        self.ok(self.f.run())
        self.assertEqual(self.f.core.read_bytes(), self.f.outputs["amd64"])
        self.assertEqual(self.f.agent.read_bytes(), self.f.agent_originals["amd64"].replace(b"ORIG", b"KEEP"))
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "pending")
        self.assertNotIn("apply 17", self.f.log()); self.assertNotIn("--verify-db", self.f.log())

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

    def test_auto_version_no_argument_piped_install_matches_database_version(self):
        self.f.installed_version("v2.3.2")
        self.f.executable_core()
        before_db = (self.f.panel / "db/core.db").read_bytes()
        self.ok(self.f.run(mode=None, piped=True, VERSION="", TEST_VERSIONFAIL="1"))
        self.assertNotIn("core version", self.f.log())
        self.assertEqual((self.f.panel / "db/core.db").read_bytes(), before_db)
        self.assert_downloads("amd64")

    def test_auto_version_core_command_official_output_and_closed_stdin(self):
        self.f.executable_core()
        self.f.ctl.unlink()
        self.ok(self.f.run(mode=None, piped=True, VERSION="", TEST_VERSION="v2.3.2"))
        self.assertEqual(self.f.log().count("core version"), 1)
        self.assertNotIn("1pctl version", self.f.log())
        self.assert_downloads("amd64")

    def test_auto_version_literal_control_file_fallback_without_execution(self):
        marker = self.f.base / "control-executed"
        self.f.ctl.write_text("#!/bin/sh\nORIGINAL_VERSION='v2.3.2'\ntouch " + str(marker) + "\n")
        self.f.ctl.chmod(0o755)
        self.ok(self.f.run(VERSION=""))
        self.assertFalse(marker.exists())
        self.assertNotIn("1pctl version", self.f.log())
        self.assert_downloads("amd64")

    def test_auto_version_failed_core_command_falls_back_to_literal(self):
        self.f.executable_core()
        self.ok(self.f.run(VERSION="", TEST_VERSIONFAIL="1"))
        self.assertEqual(self.f.log().count("core version"), 1)
        self.assert_downloads("amd64")

    def test_auto_version_absent_release_never_guesses_latest(self):
        self.f.installed_version("v2.3.4")
        self.before_stop(self.f.run(mode=None, piped=True, VERSION=""), before_code=True)
        self.assertEqual(self.f.urls(), [API_URL])

    def test_unknown_version_fails_after_api_before_persistent_state_and_service(self):
        self.f.ctl.write_text("#!/bin/sh\nORIGINAL_VERSION='unknown'\n")
        self.before_stop(self.f.run(VERSION=""), before_code=True)
        self.assertEqual(self.f.urls(), [API_URL])
        self.assertFalse(self.f.work.exists())
        self.assertFalse(self.f.backup.exists())

    def test_version_control_file_injection_is_never_executed_or_sourced(self):
        marker = self.f.base / "injected"
        self.f.ctl.write_text("#!/bin/sh\nORIGINAL_VERSION=$(touch " + str(marker) + "; echo v2.3.2)\n")
        self.f.ctl.chmod(0o755)
        self.before_stop(self.f.run(VERSION=""), before_code=True)
        self.assertFalse(marker.exists())
        self.assertEqual(self.f.urls(), [API_URL])
        self.assertNotIn("1pctl version", self.f.log())

    def test_explicit_version_strict_validation_follows_first_api(self):
        for version in ("latest", "v2.3", "vv2.3.2", "v2.3.2;echo injected", "2.3.2/../other"):
            with self.subTest(version=version):
                self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(VERSION=version), before_code=True)
                self.assertEqual(self.f.urls(), [API_URL])

    def test_install_retains_apps_database_and_unrelated_backup(self):
        app = self.f.panel / "apps/example/data"
        app.mkdir(parents=True)
        sentinel = app / "keep.txt"; sentinel.write_bytes(b"application data")
        self.f.installed_version("v2.3.2")
        db_bytes = (self.f.panel / "db/core.db").read_bytes()
        other = self.f.base / "legacy-tool.bak"; other.write_bytes(b"unrelated backup")
        self.ok(self.f.run(VERSION=""))
        self.assertEqual(sentinel.read_bytes(), b"application data")
        self.assertEqual((self.f.panel / "db/core.db").read_bytes(), db_bytes)
        self.assertEqual(other.read_bytes(), b"unrelated backup")

    def test_linux_and_unsupported_arch_rejected_before_stop(self):
        for override in ({"TEST_OS": "Darwin"}, {"TEST_ARCH": "mips64"}, {"TEST_ARCH": "armv7l"},
                         {"TEST_ARCH": "ppc64le"}, {"TEST_ARCH": "s390x"}, {"TEST_ARCH": "riscv64"}):
            with self.subTest(**override): self.before_stop(self.f.run(**override), before_code=True)

    def test_unadapted_official_four_version_fails_early(self):
        self.f.installed_version("v2.3.4")
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
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "not-applied")
        self.assertNotIn("apply 17", self.f.log())
        self.assertNotIn("--verify-db", self.f.log())
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
        self.f.agent.write_bytes(b"dirty installed agent with no backup")
        self.ok(self.f.run()); self.ok(self.f.run())
        self.assertEqual(self.f.agent.read_bytes(), self.f.agent_originals["amd64"].replace(b"ORIG", b"KEEP"))
        self.assertEqual((self.f.backup / "1panel-agent.orig").read_bytes(), self.f.agent_originals["amd64"])
        self.assert_downloads("amd64", 2, agent=True)
        before = self.f.urls()
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        self.assertEqual(self.f.agent.read_bytes(), self.f.agent_originals["amd64"])
        self.assertEqual(self.f.urls(), before)

    def test_dirty_installed_core_agent_and_backups_replaced_with_quarantine(self):
        dirty_core = self.f.outputs["amd64"]
        dirty_agent = self.f.agent_originals["amd64"].replace(b"ORIG", b"KEEP")
        self.f.core.write_bytes(dirty_core); self.f.agent.write_bytes(dirty_agent)
        old_sums = {}
        for name, dirty in (("core", dirty_core), ("agent", dirty_agent)):
            canonical = self.f.backup / ("1panel-"+name+".orig")
            self.f.backup_file(canonical, dirty)
            old_sums[name] = Path(str(canonical)+".sha256").read_bytes()
        self.ok(self.f.run())
        for name, original, dirty in (("core", self.f.originals["amd64"], dirty_core),
                                      ("agent", self.f.agent_originals["amd64"], dirty_agent)):
            canonical = self.f.backup / ("1panel-"+name+".orig")
            quarantine = self.f.backup / ("1panel-"+name+".invalid."+sha(dirty)+".orig")
            self.assertEqual(canonical.read_bytes(), original)
            self.assertEqual(quarantine.read_bytes(), dirty)
            self.assertEqual(Path(str(quarantine)+".sha256").read_bytes(), old_sums[name])
            self.assertEqual((self.f.backup / ("1panel-"+name+"."+sha(original)+".orig")).read_bytes(), original)
        self.assertEqual(self.f.core.read_bytes(), self.f.outputs["amd64"])
        self.assertEqual(self.f.agent.read_bytes(), dirty_agent)
        self.assert_downloads("amd64", agent=True)

    def test_wrong_checksum_official_canonical_repaired_for_core_and_agent(self):
        self.f.agent.write_bytes(b"dirty agent")
        for name, original in (("core", self.f.originals["amd64"]),
                                ("agent", self.f.agent_originals["amd64"])):
            self.f.backup_file(self.f.backup / ("1panel-"+name+".orig"), original, checksum="0"*64)
        self.ok(self.f.run())
        for name, original in (("core", self.f.originals["amd64"]),
                                ("agent", self.f.agent_originals["amd64"])):
            canonical = self.f.backup / ("1panel-"+name+".orig")
            self.assertTrue((self.f.backup / ("1panel-"+name+".invalid."+sha(original)+".orig")).is_file())
            self.assertTrue(Path(str(canonical)+".sha256").read_text().startswith(sha(original)+" "))

    def test_valid_first_canonical_retained_and_current_checksum_variant_saved(self):
        self.f.agent.write_bytes(b"dirty agent")
        historical = {"core": self.f.originals["amd64"]+b"historical original core",
                      "agent": self.f.agent_originals["amd64"]+b"historical original agent"}
        for name, original in historical.items():
            self.f.backup_file(self.f.backup / ("1panel-"+name+".orig"), original)
        self.ok(self.f.run())
        for name, current in (("core", self.f.originals["amd64"]),
                               ("agent", self.f.agent_originals["amd64"])):
            self.assertEqual((self.f.backup / ("1panel-"+name+".orig")).read_bytes(), historical[name])
            self.assertEqual((self.f.backup / ("1panel-"+name+"."+sha(current)+".orig")).read_bytes(), current)
            self.assertEqual(list(self.f.backup.glob("1panel-"+name+".invalid.*.orig")), [])

    def test_agent_trusted_sha_size_and_elf_fail_before_service_stop(self):
        self.f.agent.write_bytes(b"dirty installed agent")
        original = self.f.agent_originals["amd64"]
        platform = dict(self.f.man["platforms"]["linux-amd64"])
        for variant in ("sha", "size", "elf", "already-patched"):
            with self.subTest(variant=variant):
                self.f.man["platforms"]["linux-amd64"] = dict(platform)
                raw = original
                if variant == "sha": raw = original+b"corrupt"
                if variant == "size": self.f.man["platforms"]["linux-amd64"]["agent_orig_size"] = len(original)+1
                if variant == "elf":
                    raw = bytearray(original); struct.pack_into("<H", raw, 18, 183); raw = bytes(raw)
                    self.f.set_agent("amd64", raw)
                if variant == "already-patched":
                    raw = original.replace(b"ORIG", b"KEEP"); self.f.set_agent("amd64", raw)
                (self.f.assets / "agent-linux-amd64.orig").write_bytes(raw)
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run())
                self.assertEqual(self.f.agent.read_bytes(), b"dirty installed agent")
                self.assertNotIn("systemctl stop fixture-agent", self.f.log())

    def test_missing_agent_release_asset_is_not_guessed(self):
        self.f.agent.write_bytes(b"dirty agent")
        releases = self.f.write_api()
        release = releases[-1]
        release["assets"] = [a for a in release["assets"] if a["name"] != "agent-linux-amd64.orig"]
        self.f.write_api([release])
        self.before_stop(self.f.run(), before_code=True)
        self.assertEqual(self.f.urls(), [API_URL])

    def test_agent_manifest_names_and_missing_metadata_rejected_before_code(self):
        self.f.agent.write_bytes(b"dirty agent")
        platform = dict(self.f.man["platforms"]["linux-amd64"])
        for key in ("agent_orig_asset", "agent_orig_sha256", "agent_orig_size"):
            with self.subTest(key=key):
                self.f.man["platforms"]["linux-amd64"] = dict(platform)
                self.f.man["platforms"]["linux-amd64"].pop(key)
                self.f.write_manifest(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(), before_code=True)

    def test_skip_agent_retains_actual_file_without_extra_download(self):
        self.f.agent.write_bytes(b"skip this installed agent")
        self.ok(self.f.run(SKIP_AGENT="1"))
        self.assertEqual(self.f.agent.read_bytes(), b"skip this installed agent")
        self.assertNotIn("systemctl stop fixture-agent", self.f.log())
        self.assertFalse((self.f.backup / "1panel-agent.orig").exists())
        self.assert_downloads("amd64")

    def test_agent_path_directory_does_not_trigger_download(self):
        self.f.agent.mkdir()
        self.ok(self.f.run())
        self.assertTrue(self.f.agent.is_dir())
        self.assert_downloads("amd64")

    def test_local_artifact_install_agent_uses_verified_fresh_original_no_network(self):
        self.f.agent.write_bytes(b"dirty installed agent")
        self.ok(self.f.run(ARTIFACT_DIR=str(self.f.assets), FAIL_CURL="1"))
        self.assertEqual(self.f.agent.read_bytes(), self.f.agent_originals["amd64"].replace(b"ORIG", b"KEEP"))
        self.assertEqual(self.f.urls(), [])

    def test_local_artifact_auto_version_mismatch_fails_before_code_and_stop(self):
        self.f.installed_version("v2.3.4")
        self.before_stop(self.f.run(VERSION="", ARTIFACT_DIR=str(self.f.assets)), before_code=True)
        self.assertEqual(self.f.urls(), [])

    def test_restore_skips_bad_first_backup_and_accepts_valid_hash_variant(self):
        self.f.agent.write_bytes(b"dirty agent")
        self.ok(self.f.run())
        before = self.f.urls()
        for name in ("core", "agent"):
            (self.f.backup / ("1panel-"+name+".orig")).write_bytes(b"bad first backup")
        self.ok(self.f.run("restore", VERSION="", FAIL_CURL="1"))
        self.assertEqual(self.f.core.read_bytes(), self.f.originals["amd64"])
        self.assertEqual(self.f.agent.read_bytes(), self.f.agent_originals["amd64"])
        self.assertEqual(self.f.urls(), before)

    def test_restore_skips_bad_candidates_and_accepts_legacy_backup_directory(self):
        self.ok(self.f.run())
        canonical = self.f.backup / "1panel-core.orig"
        self.f.backup_file(canonical, self.f.originals["amd64"], checksum="0"*64)
        self.f.backup_file(self.f.backup / "core.orig", b"nonofficial alias")
        self.f.backup_file(self.f.panel / "backup/1panel-core.orig", self.f.originals["amd64"])
        for variant in self.f.backup.glob("1panel-core.*.orig"): variant.unlink()
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        self.assertEqual(self.f.core.read_bytes(), self.f.originals["amd64"])

    def test_legacy_url_patcher_and_corrupt_restore_fail(self):
        self.before_stop(self.f.run(LEGACY_PATCHER="1"))
        self.ok(self.f.run())
        (self.f.backup / "1panel-core.orig").write_bytes(self.f.originals["amd64"]+b"tampered")
        for variant in self.f.backup.glob("1panel-core.*.orig"): variant.unlink()
        before = self.f.log().count("systemctl stop")
        result = self.f.run("restore", FAIL_CURL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.log().count("systemctl stop"), before)

    def test_pending_foreign_license_without_current_ca_never_reuses_foreign_signature(self):
        tools, foreign = self.f.real_foreign_fixture()
        old_rows = self.f.rows("licenses"); old_roots = self.f.root_values()
        (self.f.state / "license.key").unlink(); (self.f.state / "license.crt").unlink()
        self.f.agent.write_bytes(b"foreign installed agent")
        result = self.f.run(); self.ok(result)
        self.assertEqual(self.f.rows("licenses"), old_rows)
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "pending")
        self.assertEqual(self.f.core.read_bytes(), self.f.outputs["amd64"])
        self.assertEqual(self.f.agent.read_bytes(), self.f.agent_originals["amd64"].replace(b"ORIG", b"KEEP"))
        self.assertNotEqual(self.f.root_values(), old_roots)
        self.assertEqual(list(self.f.work.glob("run.*/license.txt")), [])
        self.assertEqual(list(self.f.backup.glob("foreign-licenses.*.json")), [])
        self.assertNotIn("offline license applied", result.stdout)
        self.assertIn("import a project-signed license", result.stdout.lower())
        self.assertFalse((tools / "license.key").exists())
        self.assertTrue((foreign / "license.key").is_file())

    def test_current_foreign_core_and_agent_are_archived_immutably_not_executed(self):
        marker = self.f.base / "foreign-binary-executed"
        core = ("#!/bin/sh\ntouch "+str(marker)+"\nexit 1\n").encode()
        agent = b"foreign agent binary exact bytes"
        self.f.installed_version("v2.3.2")
        self.f.core.write_bytes(core); self.f.core.chmod(0o755); self.f.agent.write_bytes(agent)
        self.ok(self.f.run())
        first = {}
        for name, raw in (("core", core), ("agent", agent)):
            path = self.f.backup / ("1panel-"+name+".previous."+sha(raw))
            self.assertEqual(path.read_bytes(), raw)
            self.assertTrue(path.name.endswith(sha(path.read_bytes())))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            first[path] = (path.read_bytes(), path.stat().st_mtime_ns)
        self.f.core.write_bytes(b"next foreign core"); self.f.agent.write_bytes(agent)
        self.ok(self.f.run())
        for path, original in first.items(): self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), original)
        self.assertFalse(marker.exists())
        self.assertEqual((self.f.backup / "1panel-core.orig").read_bytes(), self.f.originals["amd64"])
        self.assertEqual((self.f.backup / "1panel-agent.orig").read_bytes(), self.f.agent_originals["amd64"])
        self.assertEqual((self.f.backup / ("1panel-core.previous."+sha(b"next foreign core"))).read_bytes(), b"next foreign core")

    def test_lower_release_exits_before_archiving_foreign_state_with_single_api(self):
        self.f.real_foreign_fixture()
        self.f.installed_version("v2.10.0")
        self.f.agent.write_bytes(b"foreign agent retained on unsupported downgrade")
        before = self.f.machine_snapshot(); self.f.guard_first_api()
        self.assert_version_preflight_exit(self.f.run(), before)
        self.assertEqual(self.f.urls(), [API_URL])
        self.assertEqual(list(self.f.base.glob("backup*")), [])

    def test_preserved_foreign_roots_repeat_restore_exact_raw_values_and_other_metadata(self):
        self.f.real_foreign_fixture()
        roots = self.f.root_values(); unrelated = self.f.rows("core_settings")[0]
        self.ok(self.f.run())
        preserved = self.f.backup / "core_settings_license_rootcert.json.preserved.json"
        self.assertEqual(json.loads(preserved.read_text()), roots)
        original = preserved.read_bytes()
        archives = list(self.f.backup.glob("core_settings_license_rootcert.preserved.*.json"))
        self.assertTrue(archives)
        for path in archives:
            self.assertIn(sha(path.read_bytes()), path.name)
        self.ok(self.f.run())
        self.assertEqual(preserved.read_bytes(), original)
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        self.assertEqual(self.f.root_values(), roots)
        self.assertEqual(self.f.rows("core_settings")[0], unrelated)

    def test_real_foreign_bound_signed_import_preserves_license_and_archives_all_metadata(self):
        tools, _ = self.f.real_foreign_fixture()
        before = self.f.rows("licenses")[0]
        issued = self.f.real_project_license(tools)
        (self.f.state / "license.key").unlink()
        self.ok(self.f.run(LICENSE_FILE=str(issued)))
        rows = self.f.rows("licenses"); self.assertEqual(len(rows), 2)
        foreign = next(row for row in rows if row["id"] == before["id"])
        self.assertEqual(foreign["license"], before["license"])
        for field in ("license_name", "usage_name", "assignee_name", "version_constraint", "device_id", "offline",
                      "trial", "issuer", "product_pro", "last_sync_at", "sms_total", "sms_used", "free_count", "created_at"):
            self.assertEqual(foreign[field], before[field], field)
        archives = list(self.f.backup.glob("foreign-licenses.*.json")); self.assertEqual(len(archives), 1)
        data = json.loads(archives[0].read_text())
        self.assertEqual(data["rows"], [before])
        self.assertIn(sha(archives[0].read_bytes()), archives[0].name)
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "applied")
        code = r'''
import sqlite3, sys
sys.path.insert(0, sys.argv[1]); import gen_license as g
with sqlite3.connect(sys.argv[2]) as c:
    c.row_factory = sqlite3.Row
    rows = [g.decrypt_row(dict(row)) for row in c.execute("select * from licenses order by id")]
assert rows[0]["bind_node_id"] in ("", "0")
assert rows[1]["bind_node_id"] == "17"
assert g.verify_license(rows[1]["license"])["products"][0]["maxNodeCount"] == 42
'''
        self.ok(subprocess.run([sys.executable, "-c", code, str(tools), str(self.f.db)],
                               env=self.f.env, capture_output=True, text=True, timeout=30))

    def test_explicit_bad_project_signature_and_wrong_issuer_abort_before_changes(self):
        tools, _ = self.f.real_foreign_fixture()
        issued = self.f.real_project_license(tools)
        with sqlite3.connect(self.f.db) as c: foreign_blob = c.execute("select license from licenses").fetchone()[0]
        code = "import sys; sys.path.insert(0, sys.argv[1]); import gen_license as g; print(g.decrypt_blob(sys.argv[2]))"
        foreign = subprocess.run([sys.executable, "-c", code, str(tools), foreign_blob],
                                 env=self.f.env, capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        parts = issued.read_text().split("-")
        parts[1] = ("A" if parts[1][0] != "A" else "B")+parts[1][1:]
        for text in (foreign, "-".join(parts)):
            with self.subTest(kind="wrong-issuer" if text == foreign else "bad-signature"):
                explicit = self.f.base / "invalid-project-license.txt"; explicit.write_text(text)
                before = self.f.machine_snapshot(); self.f.events.unlink(missing_ok=True)
                self.before_stop(self.f.run(LICENSE_FILE=str(explicit)))
                self.assertEqual(self.f.machine_snapshot(), before)
                self.assertNotIn("offline license applied", self.f.log())
                self.assertEqual(list(self.f.backup.glob("foreign-licenses.*.json")), [])

    def test_pending_verify_checks_binaries_roots_services_without_network_or_bound_claim(self):
        self.f.real_foreign_fixture()
        (self.f.state / "license.key").unlink()
        self.ok(self.f.run())
        before_urls = self.f.urls(); rows = self.f.rows("licenses")
        self.f.events.unlink(missing_ok=True)
        result = self.f.run("verify", FAIL_CURL="1"); self.ok(result)
        self.assertEqual(self.f.urls(), [])
        self.assertEqual(self.f.rows("licenses"), rows)
        self.assertNotIn("--verify-db", self.f.log())
        self.assertIn("code patch_core", self.f.log())
        self.assertIn("systemctl is-active --quiet fixture-core", self.f.log())
        self.assertIn("pending", result.stdout.lower()); self.assertNotIn('"status": "Bound"', result.stdout)
        self.assertNotIn("offline license applied", result.stdout)
        self.assertTrue(before_urls)

    def test_no_apply_signed_foreign_license_leaves_all_foreign_binding_fields_unchanged(self):
        tools, _ = self.f.real_foreign_fixture()
        issued = self.f.real_project_license(tools); before = self.f.rows("licenses")
        result = self.f.run(LICENSE_FILE=str(issued), NO_APPLY="1"); self.ok(result)
        self.assertEqual(self.f.rows("licenses"), before)
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "not-applied")
        self.assertEqual(list(self.f.backup.glob("foreign-licenses.*.json")), [])
        self.assertNotIn("offline license applied", result.stdout)
        self.ok(self.f.run("verify", FAIL_CURL="1"))
        self.assertEqual(self.f.rows("licenses"), before)

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
                real_agent = None
                if arch == "amd64":
                    official_agent = ROOT / "build/release-v2.3.2/agent-linux-amd64.orig"
                    self.assertTrue(official_agent.is_file(), "Fresh official agent release fixture is required")
                    real_agent = official_agent.read_bytes()
                    f.set_agent(arch, real_agent); f.write_manifest()
                    agent_patch = subprocess.run([sys.executable, str(tools / "patch_agent.py"), "--patch",
                                                  "--in", str(f.assets / "agent-linux-amd64.orig"),
                                                  "--out", str(f.agent), "--orig", str(f.assets / "agent-linux-amd64.orig"),
                                                  "--manifest", str(f.base / "local-agent-patch.json")],
                                                 env=f.env, capture_output=True, text=True, timeout=120)
                    self.ok(agent_patch)
                    dirty_agent = f.agent.read_bytes()
                    f.backup_file(f.backup / "1panel-agent.orig", dirty_agent)
                self.ok(f.run(NODES="43", EXPIRES="2036-01-01"))
                if real_agent is not None:
                    self.assertEqual(sha((f.backup / "1panel-agent.orig").read_bytes()), sha(real_agent))
                    self.assertEqual(sha((f.backup / ("1panel-agent.invalid."+sha(dirty_agent)+".orig")).read_bytes()),
                                     sha(dirty_agent))
                    self.assertEqual(sha(f.agent.read_bytes()), sha(dirty_agent))
                    f.agent.write_bytes(b"unrecognized previous tool agent")
                    f.backup_file(f.backup / "1panel-agent.orig", b"unrecognized previous tool backup")
                self.ok(f.run(NODES="44", EXPIRES="2037-01-01"))
                if real_agent is not None:
                    self.assertEqual(sha(f.agent.read_bytes()), sha(dirty_agent))
                    self.assertEqual(sha((f.backup / "1panel-agent.orig").read_bytes()), sha(real_agent))
                    self.assertEqual(sum(url.endswith("/agent-linux-amd64.orig") for url in f.urls()), 2)
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
                if real_agent is not None: self.assertEqual(sha(f.agent.read_bytes()), sha(real_agent))


if __name__ == "__main__":
    unittest.main()
