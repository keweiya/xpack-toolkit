"""Opt-in foreign-root migrations archive ciphertext and preserve ownership boundaries."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import cert_store as cs
import gen_license as gl


class RootMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(prefix="root-migration-keys-")
        cls.keydir = Path(cls.material.name)
        cls.pems = {}
        for name in ("project", "foreign", "rotated"):
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(cls.keydir / (name + ".key")),
                            "-out", str(cls.keydir / (name + ".crt")), "-days", "1",
                            "-subj", "/CN=temporary-" + name], capture_output=True, check=True)
            cls.pems[name] = (cls.keydir / (name + ".crt")).read_text()
        cls.fps = {name: cs.fingerprint(pem) for name, pem in cls.pems.items()}
        cls.raw = {name: cls.root_values(pem, cls.fps[name]) for name, pem in cls.pems.items()}
        cls.official = json.loads(Path(cs.OFFICIAL_JSON).read_text())

    @classmethod
    def tearDownClass(cls):
        cls.material.cleanup()

    @staticmethod
    def root_values(pem, fp):
        return {cs.KEYS["cert_" + region]: cs.encrypt(pem) for region in ("hk", "cn")} | {
            cs.KEYS["fp_" + region]: cs.encrypt(fp) for region in ("hk", "cn")}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="root-migration-db-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.db = self.base / "xpack.db"
        self.bak = self.base / "backup" / "core_settings_license_rootcert.json"
        self.pointer = Path(str(self.bak) + ".preserved.json")
        with sqlite3.connect(self.db) as con:
            con.executescript("create table core_settings(id integer primary key, created_at text,"
                              "updated_at text,key text,value text,description text);"
                              "insert into core_settings(key,value) values('WebsiteRootCertificate','unchanged');"
                              "create table website_certificates(id integer primary key,pem text);"
                              "insert into website_certificates values(1,'website-cert-raw');"
                              "create table licenses(id integer primary key,license text);"
                              "insert into licenses values(17,'original-license-ciphertext');")

    def install(self, rows):
        with sqlite3.connect(self.db) as con:
            for key, value in rows.items():
                con.execute("delete from core_settings where key=?", (key,))
                con.execute("insert into core_settings(key,value) values(?,?)", (key, value))

    def rows(self):
        with sqlite3.connect(self.db) as con:
            return cs._root_rows(con)

    def snapshot(self):
        with sqlite3.connect(self.db) as con:
            return list(con.iterdump())

    def assert_unrelated_preserved(self):
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute("select * from website_certificates").fetchall(),
                             [(1, "website-cert-raw")])
            self.assertEqual(con.execute("select value from core_settings where key='WebsiteRootCertificate'").fetchone(),
                             ("unchanged",))
            self.assertEqual(con.execute("select * from licenses").fetchall(),
                             [(17, "original-license-ciphertext")])

    def migrate(self, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            keys = cs.write(str(self.db), self.pems["project"], self.fps["project"],
                            preserve_foreign=True, backup_path=self.bak, **kwargs)
        self.assertEqual(keys, list(cs.KEYS.values()))
        return output.getvalue()

    def archive_path(self, payload):
        return self.bak.parent / ("core_settings_license_rootcert.preserved.%s.json" %
                                  hashlib.sha256(payload).hexdigest())

    def test_foreign_classification_never_promotes_ownership(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "foreign root"):
            cs.check_owned_roots(str(self.db), self.pems["project"])
        known_before = cs.project_fingerprints(self.fps["project"])
        self.assertEqual(cs.check_owned_roots(str(self.db), self.pems["project"], preserve_foreign=True),
                         {"ready": True, "roots": {"hk": "foreign", "cn": "foreign"}})
        self.assertEqual(cs.project_fingerprints(self.fps["project"]), known_before)
        self.assertNotIn(self.fps["foreign"], known_before)
        with self.assertRaisesRegex(ValueError, "established project ownership"):
            cs.check_owned_roots(str(self.db), self.pems["project"], [self.fps["foreign"]],
                                 preserve_foreign=True)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.bak.parent.exists())

    def test_foreign_signed_license_remains_unowned_after_migration(self):
        self.install(self.raw["foreign"])
        with mock.patch.multiple(gl, SIGN_KEY=str(self.keydir / "foreign.key"),
                                 SIGN_CRT=str(self.keydir / "foreign.crt")):
            content, _ = gl.build("enterprise", "2099-12-31", 10, "Fixture", "device",
                                  "fixture", 0, False, True, "2.x")
            foreign_license = {"license": gl.encode_license(content)}
        with mock.patch.object(gl, "SIGN_CRT", str(self.keydir / "project.crt")):
            known = gl._known_roots()
            self.assertFalse(gl._owned_license(foreign_license, known))
            self.migrate()
            self.assertEqual(gl._known_roots(), known)
            self.assertFalse(gl._owned_license(foreign_license, gl._known_roots()))
            self.assertNotIn(self.fps["foreign"], known)
        self.assert_unrelated_preserved()

    def test_content_addressed_snapshot_exact_ciphertext_and_mode(self):
        self.install(self.raw["foreign"])
        self.bak.parent.mkdir()
        self.bak.write_bytes(b"existing-official-backup-must-remain")
        output = self.migrate()
        payload = self.pointer.read_bytes()
        archive = self.archive_path(payload)
        self.assertEqual(json.loads(payload), self.raw["foreign"])
        self.assertEqual(archive.read_bytes(), payload)
        self.assertEqual(archive.stat().st_ino, self.pointer.stat().st_ino)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.pointer.stat().st_mode), 0o600)
        self.assertIn(str(archive), output)
        self.assertEqual(self.bak.read_bytes(), b"existing-official-backup-must-remain")
        self.assertEqual(cs.check_owned_roots(str(self.db), self.pems["project"])["roots"],
                         {"hk": "project", "cn": "project"})
        self.assert_unrelated_preserved()

    def test_repeated_migration_and_rotation_keep_first_snapshot(self):
        self.install(self.raw["foreign"])
        self.migrate()
        first = self.pointer.read_bytes()
        initial_inode = self.pointer.stat().st_ino
        self.migrate()
        self.assertEqual(len(list(self.bak.parent.glob("*.preserved.*.json"))), 1)
        self.install(self.raw["foreign"])
        self.migrate()
        self.assertEqual(len(list(self.bak.parent.glob("*.preserved.*.json"))), 1)
        self.install(self.raw["rotated"])
        self.migrate()
        archives = list(self.bak.parent.glob("*.preserved.*.json"))
        self.assertEqual(len(archives), 2)
        self.assertEqual(self.pointer.read_bytes(), first)
        self.assertEqual(self.pointer.stat().st_ino, initial_inode)
        self.assertEqual({p.read_bytes() for p in archives},
                         {cs._snapshot_bytes(self.raw["foreign"]), cs._snapshot_bytes(self.raw["rotated"])})
        cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual(self.rows(), self.raw["foreign"])
        self.assert_unrelated_preserved()

    def test_restore_prefers_initial_foreign_snapshot_over_official_backup(self):
        original = dict(self.official)
        for key in (cs.KEYS["cert_cn"], cs.KEYS["fp_cn"]):
            original[key] = self.raw["foreign"][key]
        self.install(original)
        self.bak.parent.mkdir()
        self.bak.write_text(json.dumps(self.official))
        self.migrate()
        cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual(self.rows(), original)
        before = self.snapshot()
        cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual(self.snapshot(), before)
        self.assert_unrelated_preserved()

    def test_restore_leaves_current_foreign_region_untouched(self):
        self.install(self.raw["foreign"])
        self.migrate()
        cn = {key: self.raw["rotated"][key] for key in (cs.KEYS["cert_cn"], cs.KEYS["fp_cn"])}
        self.install(cn)
        with sqlite3.connect(self.db) as con:
            before = con.execute("select * from core_settings where key in (?,?)", tuple(cn)).fetchall()
        cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        with sqlite3.connect(self.db) as con:
            after = con.execute("select * from core_settings where key in (?,?)", tuple(cn)).fetchall()
        self.assertEqual(after, before)
        for key in (cs.KEYS["cert_hk"], cs.KEYS["fp_hk"]):
            self.assertEqual(self.rows()[key], self.raw["foreign"][key])
        self.assert_unrelated_preserved()

    def test_restore_all_foreign_current_is_noop_even_with_missing_backup(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.bak.parent.exists())

    def test_optin_requires_backup_and_dry_run_remains_readonly(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "backup_path"):
            cs.write(str(self.db), self.pems["project"], self.fps["project"], preserve_foreign=True)
        self.migrate(dry_run=True)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.bak.parent.exists())

    def test_malformed_incomplete_duplicate_and_incoherent_rows_rejected(self):
        for case in ("malformed", "incomplete", "duplicate", "incoherent"):
            with self.subTest(case=case):
                self.install(self.raw["foreign"])
                with sqlite3.connect(self.db) as con:
                    if case == "malformed":
                        con.execute("update core_settings set value='invalid' where key=?", (cs.KEYS["cert_hk"],))
                    elif case == "incomplete":
                        con.execute("delete from core_settings where key=?", (cs.KEYS["fp_hk"],))
                    elif case == "duplicate":
                        con.execute("insert into core_settings(key,value) values(?,?)",
                                    (cs.KEYS["fp_hk"], self.raw["foreign"][cs.KEYS["fp_hk"]]))
                    else:
                        con.execute("update core_settings set value=? where key=?",
                                    (self.raw["project"][cs.KEYS["fp_hk"]], cs.KEYS["fp_hk"]))
                before = self.snapshot()
                for operation in (lambda: cs.check_owned_roots(str(self.db), self.pems["project"], preserve_foreign=True),
                                  self.migrate,
                                  lambda: cs.archive_current(str(self.db), self.bak, self.pems["project"]),
                                  lambda: cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)):
                    with self.assertRaises(ValueError):
                        operation()
                    self.assertEqual(self.snapshot(), before)
                self.assertFalse(self.bak.parent.exists())

    def test_failed_backup_has_zero_database_writes(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        for operation in ("open", "link", "fsync"):
            with self.subTest(operation=operation):
                target = "_backup_directory" if operation == "open" else operation
                owner = cs if operation == "open" else cs.os
                with mock.patch.object(owner, target, side_effect=OSError("injected archive failure")):
                    with self.assertRaisesRegex(OSError, "injected archive failure"):
                        self.migrate()
                self.assertEqual(self.snapshot(), before)
        self.assert_unrelated_preserved()

    def test_symlink_snapshot_and_parent_are_never_followed(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        target = self.base / "target"
        target.mkdir()
        self.bak.parent.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            self.migrate()
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(self.snapshot(), before)
        self.bak.parent.unlink()
        self.bak.parent.mkdir()
        sentinel = target / "sentinel"
        sentinel.write_bytes(b"must-remain")
        self.pointer.symlink_to(sentinel)
        with self.assertRaises(OSError):
            self.migrate()
        self.assertEqual(sentinel.read_bytes(), b"must-remain")
        self.assertEqual(self.snapshot(), before)

    def test_existing_archive_tamper_never_overwrites_or_mutates_database(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        payload = cs._snapshot_bytes(self.raw["foreign"])
        archive = self.archive_path(payload)
        archive.parent.mkdir()
        archive.write_bytes(b"existing-different-content")
        archive.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "content hash"):
            self.migrate()
        self.assertEqual(archive.read_bytes(), b"existing-different-content")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.pointer.exists())

    def test_preserved_backup_tamper_rejected_before_restore_writes(self):
        self.install(self.raw["foreign"])
        self.migrate()
        before = self.snapshot()
        self.pointer.write_bytes(cs._snapshot_bytes(self.raw["rotated"]))
        with self.assertRaises((ValueError, OSError)):
            cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual(self.snapshot(), before)

    def test_duplicate_backup_json_rejected_and_extra_keys_filtered(self):
        self.install(self.raw["project"])
        self.bak.parent.mkdir()
        loaded = dict(self.raw["foreign"], WebsiteRootCertificate="attempted-overwrite")
        self.bak.write_text(json.dumps(loaded))
        cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual(self.rows(), self.raw["foreign"])
        self.assert_unrelated_preserved()
        self.install(self.raw["project"])
        before = self.snapshot()
        value = json.dumps(self.raw["foreign"][cs.KEYS["fp_hk"]])
        self.bak.write_text('{"LicenseRootCertHKFingerprint":' + value + ',"LicenseRootCertHKFingerprint":' + value + '}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual(self.snapshot(), before)

    def test_archive_current_readonly_and_write_rechecks_fresh_rotation(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        initial = cs.archive_current(str(self.db), self.bak, self.pems["project"])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(json.loads(Path(initial).read_bytes()), self.raw["foreign"])
        original = cs.check_owned_roots
        def changed(db, pem=None, extra_fps=(), preserve_foreign=False):
            result = original(db, pem, extra_fps, preserve_foreign)
            self.install(self.raw["rotated"])
            return result
        with mock.patch.object(cs, "check_owned_roots", side_effect=changed):
            self.migrate()
        archives = list(self.bak.parent.glob("*.preserved.*.json"))
        self.assertEqual(len(archives), 2)
        self.assertEqual({p.read_bytes() for p in archives},
                         {cs._snapshot_bytes(self.raw["foreign"]), cs._snapshot_bytes(self.raw["rotated"])})
        self.assertEqual(json.loads(self.pointer.read_bytes()), self.raw["foreign"])

    def test_archive_skips_project_missing_and_preserves_official(self):
        self.assertIsNone(cs.archive_current(str(self.db), self.bak, self.pems["project"]))
        self.install(self.raw["project"])
        self.assertIsNone(cs.archive_current(str(self.db), self.bak, self.pems["project"]))
        self.assertFalse(self.bak.parent.exists())
        self.install(self.official)
        before = self.snapshot()
        path = cs.archive_current(str(self.db), self.bak, self.pems["project"])
        self.assertEqual(json.loads(Path(path).read_bytes()), self.official)
        self.assertEqual(self.snapshot(), before)

    def test_missing_original_region_is_not_deleted_during_restore(self):
        hk = {key: self.raw["foreign"][key] for key in (cs.KEYS["cert_hk"], cs.KEYS["fp_hk"])}
        self.install(hk)
        self.migrate()
        before_cn = {key: self.rows()[key] for key in (cs.KEYS["cert_cn"], cs.KEYS["fp_cn"])}
        cs.restore(str(self.db), str(self.bak), self.pems["project"], preserve_foreign=True)
        self.assertEqual({key: self.rows()[key] for key in hk}, hk)
        self.assertEqual({key: self.rows()[key] for key in before_cn}, before_cn)
        self.assert_unrelated_preserved()

    def test_cli_check_archive_write_restore_with_foreign_optin(self):
        self.install(self.raw["foreign"])
        before = self.snapshot()
        common = [sys.executable, str(ROOT / "tools/cert_store.py"), "--db", str(self.db),
                  "--cert", str(self.keydir / "project.crt"), "--bak", str(self.bak)]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(common + ["--check-owned"], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        result = subprocess.run(common + ["--check-owned", "--preserve-foreign"],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["roots"], {"hk": "foreign", "cn": "foreign"})
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.bak.parent.exists())
        result = subprocess.run(common + ["--archive-current", "--preserve-foreign"],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.pointer.exists())
        result = subprocess.run(common + ["--preserve-foreign"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("preserved root snapshot:", result.stdout)
        result = subprocess.run(common + ["--restore", "--preserve-foreign"],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rows(), self.raw["foreign"])
        self.assert_unrelated_preserved()


if __name__ == "__main__":
    unittest.main()
