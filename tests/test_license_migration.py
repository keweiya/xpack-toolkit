"""Opt-in migration archives foreign rows and changes only master-bind metadata."""
import base64
import hashlib
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


class LicenseMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(prefix="license-migration-keys-")
        cls.keydir = Path(cls.material.name)
        for name in ("project", "foreign"):
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(cls.keydir / (name + ".key")),
                            "-out", str(cls.keydir / (name + ".crt")), "-days", "1",
                            "-subj", "/CN=temporary-" + name], capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.material.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="license-migration-db-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.db = self.base / "xpack.db"
        self.serial = self.base / ".serial"
        self.serial.write_text("temporary-device")
        patcher = mock.patch.multiple(gl, SIGN_KEY=str(self.keydir / "project.key"),
                                      SIGN_CRT=str(self.keydir / "project.crt"))
        patcher.start()
        self.addCleanup(patcher.stop)
        with sqlite3.connect(self.db) as con:
            con.executescript("create table nodes(id integer primary key,name text);"
                              "insert into nodes values(17,'local');insert into nodes values(23,'other');"
                              "create table website_certificates(id integer primary key,pem text);"
                              "insert into website_certificates values(1,'untouched certificate');")
            fields = "license_name usage_name assignee_name version_constraint device_id license offline trial issuer product_pro last_sync_at sms_total sms_used bind_node_id free_count free_nodes status message"
            con.execute("create table licenses(id integer primary key,created_at text,updated_at text," +
                        ",".join('"%s" text' % name for name in fields.split()) +
                        ",signature text,unknown_metadata blob)")

    def issue(self, foreign=False, expires="2099-12-31", offline=True, device="temporary-device"):
        content, _ = gl.build("enterprise", expires, 10, "Fixture", device,
                              "fixture", 0, False, offline, "2.x")
        if foreign:
            with mock.patch.multiple(gl, SIGN_KEY=str(self.keydir / "foreign.key"),
                                     SIGN_CRT=str(self.keydir / "foreign.crt")):
                text = gl.encode_license(content)
        else:
            text = gl.encode_license(content)
        return gl.row_from_content(content, text=text)

    def insert(self, row, bound="", encrypted=True, raw_binding=False):
        row = dict(row, bind_node_id=str(bound), free_nodes='["foreign-child"]')
        stored = gl.encrypt_row(row) if encrypted else row
        if raw_binding:
            stored["bind_node_id"] = str(bound)
        stored.update(created_at="original-created", updated_at="original-updated",
                      signature="standalone-signature-untouched", unknown_metadata=None)
        with sqlite3.connect(self.db) as con:
            cursor = con.execute("insert into licenses (%s) values (%s)" % (
                ",".join(stored), ",".join("?" * len(stored))), list(stored.values()))
            return cursor.lastrowid

    def rows(self):
        with sqlite3.connect(self.db) as con:
            con.row_factory = sqlite3.Row
            return {row["id"]: dict(row) for row in con.execute("select * from licenses")}

    def snapshot(self):
        with sqlite3.connect(self.db) as con:
            return list(con.iterdump())

    def apply(self, row=None, **kwargs):
        return gl.apply_row(row or self.issue(), str(self.db), restart=False,
                            serial_path=str(self.serial), preserve_foreign=True, **kwargs)

    def archives(self, directory=None):
        return sorted((directory or self.base).glob("foreign-licenses.*.json"))

    def assert_no_backups(self):
        self.assertFalse(Path(str(self.db) + ".pre-license").exists())
        self.assertEqual(self.archives(), [])
        self.assertEqual(list(self.base.glob(".*.tmp")), [])

    def licenses_digest(self):
        """Full licenses table content plus the raw database bytes."""
        with sqlite3.connect(self.db) as con:
            con.row_factory = sqlite3.Row
            table = [dict(row) for row in con.execute("select * from licenses order by id")]
        return table, self.db.read_bytes()

    def test_replace_foreign_archives_then_deletes_every_foreign_row_and_binds_project_row(self):
        master_foreign = self.insert(self.issue(foreign=True), 17)
        other_foreign = self.insert(self.issue(foreign=True), 23)
        unbound_foreign = self.insert(self.issue(foreign=True))
        other_owned = self.insert(self.issue(), 23)
        before = self.rows()
        project = self.issue()
        result = self.apply(project, replace_foreign=True)
        after = self.rows()
        self.assertEqual(result["dropped"], 3)
        self.assertEqual(result["backup"], str(self.db) + ".pre-license")
        self.assertTrue(os.path.isfile(result))
        with sqlite3.connect(result) as con:
            con.row_factory = sqlite3.Row
            saved = {row["id"]: dict(row) for row in con.execute("select * from licenses")}
        self.assertEqual(saved, before)
        for row_id in (master_foreign, other_foreign, unbound_foreign):
            self.assertNotIn(row_id, after)
        self.assertEqual(after[other_owned], before[other_owned])
        new_id, = set(after) - set(before)
        imported = gl.decrypt_row(after[new_id])
        self.assertEqual(imported["bind_node_id"], "17")
        self.assertEqual(imported["license"], project["license"])
        self.assertEqual(self.serial.read_text(), "temporary-device")
        self.assertTrue(gl.verify_database(str(self.db), str(self.serial))["signatureVerified"])
        archive = Path(result["archive"])
        payload = archive.read_bytes()
        self.assertEqual(archive.name,
                         "foreign-licenses.%s.json" % hashlib.sha256(payload).hexdigest())
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        data = json.loads(payload)
        self.assertEqual(data["master"], "17")
        self.assertEqual(data["columns"], list(before[master_foreign]))
        self.assertEqual(data["rows"],
                         [before[i] for i in (master_foreign, other_foreign, unbound_foreign)])
        self.assertEqual(self.archives(), [archive])
        stable_rows = self.rows()
        baseline = Path(str(self.db) + ".pre-license").read_bytes()
        again = self.apply(project, replace_foreign=True)
        self.assertEqual(again["dropped"], 0)
        self.assertNotIn("archive", again)
        self.assertEqual(set(self.rows()), set(stable_rows))
        self.assertEqual(self.rows()[other_owned], before[other_owned])
        rebound = gl.decrypt_row(self.rows()[new_id])
        self.assertEqual(rebound["bind_node_id"], "17")
        self.assertEqual(rebound["license"], project["license"])
        self.assertEqual(self.archives(), [archive])
        self.assertEqual(archive.read_bytes(), payload)
        self.assertEqual(Path(str(self.db) + ".pre-license").read_bytes(), baseline)

    def test_replace_foreign_rolls_back_every_delete_when_a_later_write_fails(self):
        self.insert(self.issue(foreign=True), 17)
        self.insert(self.issue(foreign=True), 23)
        self.insert(self.issue(foreign=True))
        before = self.rows()
        project = self.issue()
        rollback_serial = self.base / ".serial-rollback"
        failures = (
            ("later insert", mock.patch.object(gl, "encrypt_row",
                                               side_effect=ValueError("insert failed"))),
            ("serial check", mock.patch.object(gl.os, "chmod",
                                               side_effect=OSError("serial write failed"))),
        )
        for label, patcher in failures:
            with self.subTest(failure=label):
                with patcher:
                    with self.assertRaises((ValueError, OSError)):
                        gl.apply_row(project, str(self.db), restart=False,
                                     serial_path=str(rollback_serial),
                                     preserve_foreign=True, replace_foreign=True)
                self.assertEqual(self.rows(), before)
                self.assertEqual(self.serial.read_text(), "temporary-device")
                self.assertEqual(gl.preflight_database(str(self.db), str(rollback_serial),
                                                       None, (), True, True)
                                 ["foreignLicenseCount"], 3)

    def test_replace_and_archive_reject_preserve_foreign_free_replacement(self):
        self.insert(self.issue(foreign=True), 17)
        before = self.licenses_digest()
        project = self.issue()
        operations = (
            lambda: gl.apply_row(project, str(self.db), False, None, str(self.serial),
                                 (), False, None, True),
            lambda: gl.preflight_database(str(self.db), str(self.serial), None, (), False, True),
            lambda: gl.archive_foreign_database(project, str(self.db),
                                                serial_path=str(self.serial),
                                                preserve_foreign=False, replace_foreign=True),
        )
        for operation in operations:
            with self.assertRaisesRegex(ValueError, "preserve-foreign"):
                operation()
            self.assertEqual(self.licenses_digest(), before)
            self.assert_no_backups()

    def test_cli_replace_and_drop_require_preserve_foreign_with_zero_writes(self):
        self.insert(self.issue(foreign=True), 17)
        before = self.licenses_digest()
        env = dict(os.environ, SIGN_CRT=str(self.keydir / "project.crt"),
                   SIGN_KEY=str(self.keydir / "project.key"), PYTHONDONTWRITEBYTECODE="1")
        command = [sys.executable, str(ROOT / "tools/gen_license.py"), "--db", str(self.db),
                   "--serial-path", str(self.serial)]
        for flag in ("--replace-foreign", "--drop-foreign-licenses"):
            with self.subTest(flag=flag):
                result = subprocess.run(command + [flag], env=env, capture_output=True,
                                        text=True, timeout=60)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--preserve-foreign", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.licenses_digest(), before)
                self.assert_no_backups()

    def test_archive_foreign_database_with_replace_foreign_archives_all_rows_read_only(self):
        self.insert(self.issue(foreign=True), 17)
        self.insert(self.issue(foreign=True), 23)
        self.insert(self.issue(foreign=True))
        before = self.licenses_digest()
        result = gl.archive_foreign_database(self.issue(), str(self.db),
                                            serial_path=str(self.serial),
                                            preserve_foreign=True, replace_foreign=True)
        self.assertEqual(result["foreignLicenseCount"], 3)
        self.assertEqual(self.licenses_digest(), before)
        self.assertFalse(Path(str(self.db) + ".pre-license").exists())
        self.assertEqual(len(json.loads(Path(result["archive"]).read_text())["rows"]), 3)

    def test_drop_foreign_database_archives_and_deletes_without_license_material(self):
        master_foreign = self.insert(self.issue(foreign=True), 17)
        other_foreign = self.insert(self.issue(foreign=True), 23)
        unbound_foreign = self.insert(self.issue(foreign=True))
        before = self.rows()
        with mock.patch.object(gl, "sign_payload",
                               side_effect=AssertionError("unexpected signing")):
            result = gl.drop_foreign_database(str(self.db), serial_path=str(self.serial))
        self.assertTrue(result["ready"])
        self.assertEqual(result["bindNodeID"], "17")
        self.assertEqual(result["foreignLicenseCount"], 3)
        self.assertEqual(result["dropped"], 3)
        self.assertEqual(self.rows(), {})
        self.assertEqual(self.licenses_digest()[0], [])
        self.assertEqual(self.serial.read_text(), "temporary-device")
        self.assertFalse(Path(str(self.db) + ".pre-license").exists())
        archive = Path(result["archive"])
        payload = archive.read_bytes()
        self.assertEqual(archive.name,
                         "foreign-licenses.%s.json" % hashlib.sha256(payload).hexdigest())
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        data = json.loads(payload)
        self.assertEqual(data["master"], "17")
        self.assertEqual(data["columns"], list(before[master_foreign]))
        self.assertEqual(data["rows"],
                         [before[i] for i in (master_foreign, other_foreign, unbound_foreign)])
        self.assertEqual(self.archives(), [archive])

    def test_drop_foreign_database_is_a_zero_write_noop_without_foreign_rows(self):
        owned_master = self.insert(self.issue(), 17)
        owned_other = self.insert(self.issue(), 23)
        before = self.licenses_digest()
        result = gl.drop_foreign_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(result["foreignLicenseCount"], 0)
        self.assertEqual(result["dropped"], 0)
        self.assertIsNone(result["archive"])
        self.assertEqual(self.licenses_digest(), before)
        self.assertEqual(set(self.rows()), {owned_master, owned_other})
        self.assert_no_backups()
        with sqlite3.connect(self.db) as con:
            con.execute("delete from licenses")
        empty = self.licenses_digest()
        result = gl.drop_foreign_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(result["dropped"], 0)
        self.assertIsNone(result["archive"])
        self.assertEqual(self.licenses_digest(), empty)
        self.assert_no_backups()

    def test_cli_drop_foreign_licenses_needs_no_signing_key_or_license_file(self):
        self.insert(self.issue(foreign=True), 17)
        self.insert(self.issue(foreign=True), 23)
        env = dict(os.environ, SIGN_CRT=str(self.keydir / "project.crt"),
                   SIGN_KEY=str(self.base / "missing-key"), PYTHONDONTWRITEBYTECODE="1")
        command = [sys.executable, str(ROOT / "tools/gen_license.py"), "--db", str(self.db),
                   "--serial-path", str(self.serial), "--preserve-foreign",
                   "--drop-foreign-licenses"]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["dropped"], 2)
        self.assertEqual(payload["foreignLicenseCount"], 2)
        self.assertTrue(Path(payload["archive"]).is_file())
        self.assertEqual(self.rows(), {})
        again = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(json.loads(again.stdout)["dropped"], 0)
        self.assertIsNone(json.loads(again.stdout)["archive"])
        self.assertEqual(self.archives(), [Path(payload["archive"])])

    def test_cli_apply_replace_foreign_replaces_the_third_party_authorization(self):
        self.insert(self.issue(foreign=True), 17)
        self.insert(self.issue(foreign=True), 23)
        project = self.issue()
        license_file = self.base / "license.txt"
        license_file.write_text(project["license"])
        backup_dir = self.base / "installation-backup"
        backup_dir.mkdir()
        env = dict(os.environ, SIGN_CRT=str(self.keydir / "project.crt"),
                   SIGN_KEY=str(self.keydir / "project.key"), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/gen_license.py"), "--db", str(self.db),
             "--serial-path", str(self.serial), "--preserve-foreign", "--replace-foreign",
             "--foreign-backup-dir", str(backup_dir), "--import-file", str(license_file),
             "--apply", "--no-restart"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("主节点已绑定", result.stdout)
        remaining = self.rows()
        project_id, = remaining
        self.assertEqual(gl.decrypt_row(remaining[project_id])["license"], project["license"])
        archive, = self.archives(backup_dir)
        self.assertEqual(len(json.loads(archive.read_text())["rows"]), 2)
        self.assertTrue(gl.verify_database(str(self.db), str(self.serial))["signatureVerified"])

    def test_malformed_duplicate_and_unknown_root_rows_keep_strict_default_path(self):
        unknown = self.base / "unknown"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(unknown.with_suffix(".key")),
                        "-out", str(unknown.with_suffix(".crt")), "-days", "1",
                        "-subj", "/CN=temporary-unknown"], capture_output=True, check=True)
        content, _ = gl.build("enterprise", "2099-12-31", 10, "Fixture", "temporary-device",
                              "fixture", 0, False, True, "2.x")
        with mock.patch.multiple(gl, SIGN_KEY=str(unknown.with_suffix(".key")),
                                 SIGN_CRT=str(unknown.with_suffix(".crt"))):
            unknown_root = self.insert(
                gl.row_from_content(content, text=gl.encode_license(content)), 17)
        shared = self.issue(foreign=True)
        duplicate_a = self.insert(shared, 17)
        duplicate_b = self.insert(shared, 17)
        malformed = self.insert({"license_name": "!!not-base64!!",
                                 "license": "!!not-base64!!"}, 17, encrypted=False)
        rows_before = self.rows()
        digest_before = self.licenses_digest()
        for operation in (lambda: gl.preflight_database(str(self.db), str(self.serial)),
                          lambda: gl.apply_row(self.issue(), str(self.db), False, None,
                                               str(self.serial))):
            with self.assertRaisesRegex(ValueError, "different issuer"):
                operation()
            self.assertEqual(self.licenses_digest(), digest_before)
            self.assert_no_backups()
        result = self.apply(replace_foreign=True)
        self.assertEqual(result["dropped"], 4)
        remaining = self.rows()
        project_id, = remaining
        self.assertEqual(gl.decrypt_row(remaining[project_id])["bind_node_id"], "17")
        data = json.loads(Path(result["archive"]).read_text())
        self.assertEqual(data["rows"],
                         [rows_before[i] for i in (unknown_root, duplicate_a, duplicate_b,
                                                   malformed)])

    def test_signed_foreign_master_changes_only_binding_and_archives_all_raw_rows(self):
        foreign_row = self.issue(foreign=True)
        master = self.insert(foreign_row, 17)
        other_foreign = self.insert(self.issue(foreign=True), 23)
        unbound_foreign = self.insert(self.issue(foreign=True))
        other_project = self.insert(self.issue(), 23)
        before = self.rows()
        project = self.issue()
        backup = self.apply(project)
        after = self.rows()
        self.assertEqual({k for k in before[master] if before[master][k] != after[master][k]},
                         {"bind_node_id"})
        self.assertEqual(gl.decrypt_row(after[master])["bind_node_id"], "")
        self.assertEqual(gl.decrypt_blob(after[master]["license"]), foreign_row["license"])
        self.assertEqual(gl._verify_signed_license(foreign_row["license"], {
            cs.fingerprint((self.keydir / "foreign.crt").read_text())}),
            gl.decode_license(foreign_row["license"]))
        for row_id in (other_foreign, unbound_foreign, other_project):
            self.assertEqual(after[row_id], before[row_id])
        new_id, = set(after) - set(before)
        imported = gl.decrypt_row(after[new_id])
        self.assertEqual(imported["bind_node_id"], "17")
        self.assertEqual(imported["license"], project["license"])
        self.assertNotEqual(after[new_id]["bind_node_id"], "17")
        self.assertTrue(gl.verify_database(str(self.db), str(self.serial))["signatureVerified"])
        archive, = self.archives()
        payload = archive.read_bytes()
        self.assertEqual(archive.name, "foreign-licenses.%s.json" % hashlib.sha256(payload).hexdigest())
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        data = json.loads(payload)
        self.assertEqual(data["schema"], 1)
        self.assertEqual(data["name"], "xpack-toolkit-foreign-licenses")
        self.assertEqual(data["master"], "17")
        self.assertEqual(data["columns"], list(before[master]))
        self.assertEqual(data["rows"], [before[i] for i in (master, other_foreign, unbound_foreign)])
        with sqlite3.connect(backup) as con:
            con.row_factory = sqlite3.Row
            saved = {row["id"]: dict(row) for row in con.execute("select * from licenses")}
            self.assertEqual(saved, before)
            self.assertEqual(con.execute("select * from website_certificates").fetchall()[0][1],
                             "untouched certificate")
        self.assertEqual(stat.S_IMODE(Path(backup).stat().st_mode), 0o600)

    def test_repeat_keeps_foreign_ciphertext_and_archive_stable(self):
        master = self.insert(self.issue(foreign=True), 17)
        project = self.issue()
        self.apply(project)
        before = self.rows()
        archive, = self.archives()
        archive_bytes = archive.read_bytes()
        baseline = Path(str(self.db) + ".pre-license").read_bytes()
        self.apply(project)
        self.assertEqual(self.rows()[master], before[master])
        self.assertEqual(set(self.rows()), set(before))
        self.assertEqual(self.archives(), [archive])
        self.assertEqual(archive.read_bytes(), archive_bytes)
        self.assertEqual(Path(str(self.db) + ".pre-license").read_bytes(), baseline)

    def test_plaintext_foreign_binding_stays_plaintext_when_name_is_plaintext(self):
        master = self.insert(self.issue(foreign=True), 17, encrypted=False)
        before = self.rows()[master]
        self.apply()
        after = self.rows()[master]
        self.assertEqual(after, dict(before, bind_node_id=""))

    def test_raw_binding_with_encrypted_name_is_unbound_using_repository_key(self):
        master = self.insert(self.issue(foreign=True), 17, raw_binding=True)
        before = self.rows()[master]
        self.apply()
        after = self.rows()[master]
        self.assertEqual({k for k in before if before[k] != after[k]}, {"bind_node_id"})
        name = gl.decrypt_blob(before["license_name"])
        self.assertEqual(gl.decrypt_blob(after["bind_node_id"], gl.repository_key(name)), "")
        self.assertNotEqual(after["bind_node_id"], "")

    def test_default_guards_remain_strict(self):
        self.insert(self.issue(foreign=True), 17)
        before = self.snapshot()
        for operation in (lambda: gl.preflight_database(str(self.db), str(self.serial)),
                          lambda: gl.apply_row(self.issue(), str(self.db), False, None,
                                               str(self.serial))):
            with self.assertRaisesRegex(ValueError, "different issuer"):
                operation()
            self.assertEqual(self.snapshot(), before)
            self.assert_no_backups()

    def test_opt_in_preflight_without_new_license_only_reads_counts(self):
        self.insert(self.issue(foreign=True), 17)
        self.insert(self.issue(foreign=True), 23)
        self.insert(self.issue())
        before = self.snapshot()
        with mock.patch.object(gl, "sign_payload", side_effect=AssertionError("unexpected signing")):
            result = gl.preflight_database(str(self.db), str(self.serial), None, (), True)
        self.assertTrue(result["ready"])
        self.assertEqual(result["ownedLicenseCount"], 1)
        self.assertEqual(result["foreignLicenseCount"], 2)
        self.assertEqual(self.snapshot(), before)
        self.assert_no_backups()

    def test_invalid_signed_project_and_serial_fail_before_any_archive_or_change(self):
        self.insert(self.issue(foreign=True), 17)
        good = self.issue()
        bad_signature = dict(good)
        parts = good["license"].split("-")
        parts[1] = base64.b64encode(b"invalid-signature").decode()
        bad_signature["license"] = "-".join(parts)
        missing_device = gl.decode_license(good["license"])
        missing_device["deviceID"] = ""
        invalid_rows = (bad_signature, self.issue(foreign=True),
                        self.issue(expires="2001-01-01"), self.issue(offline=False),
                        self.issue(device="wrong-device"),
                        {"license": gl.encode_license(missing_device)})
        before = self.snapshot()
        for row in invalid_rows:
            with self.subTest(row=row["license"][:24]):
                with self.assertRaises(ValueError):
                    self.apply(row)
                self.assertEqual(self.snapshot(), before)
                self.assert_no_backups()

    def test_archival_publish_failure_leaves_database_and_serial_unchanged(self):
        self.insert(self.issue(foreign=True), 17)
        before = self.snapshot()
        with mock.patch.object(gl.os, "link", side_effect=OSError("archive publication failed")):
            with self.assertRaisesRegex(OSError, "archive publication failed"):
                self.apply()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.serial.read_text(), "temporary-device")
        self.assert_no_backups()

    def test_archival_directory_failure_leaves_existing_baseline_unchanged(self):
        self.insert(self.issue(foreign=True), 17)
        baseline = Path(str(self.db) + ".pre-license")
        baseline.write_bytes(b"old-baseline-sentinel")
        before = self.snapshot()
        with self.assertRaises(FileNotFoundError):
            self.apply(foreign_backup_dir=str(self.base / "missing-directory"))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(baseline.read_bytes(), b"old-baseline-sentinel")
        self.assertEqual(self.archives(), [])

    def test_snapshot_fsync_failure_prevents_mutation(self):
        self.insert(self.issue(foreign=True), 17)
        before = self.snapshot()
        with mock.patch.object(gl.os, "fsync", side_effect=OSError("durability failed")):
            with self.assertRaisesRegex(OSError, "durability failed"):
                self.apply()
        self.assertEqual(self.snapshot(), before)
        self.assert_no_backups()

    def test_snapshot_target_symlink_and_different_file_are_never_followed_or_replaced(self):
        payload = b'{"schema":1}\n'
        target = self.base / "snapshot.json"
        victim = self.base / "victim"
        victim.write_bytes(b"keep-victim")
        target.symlink_to(victim)
        with self.assertRaises(OSError):
            gl._publish_snapshot(str(self.base), target.name, payload)
        self.assertEqual(victim.read_bytes(), b"keep-victim")
        self.assertTrue(target.is_symlink())
        target.unlink()
        target.write_bytes(b"keep-target")
        target.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "differs"):
            gl._publish_snapshot(str(self.base), target.name, payload)
        self.assertEqual(target.read_bytes(), b"keep-target")
        self.assertEqual(list(self.base.glob(".foreign-licenses-*.tmp")), [])

    def test_preinstall_archive_validates_project_and_does_zero_database_writes(self):
        master = self.insert(self.issue(foreign=True), 17)
        before = self.snapshot()
        project = self.issue()
        backup_dir = self.base / "installation-backup"
        backup_dir.mkdir()
        result = gl.archive_foreign_database(project, str(self.db), serial_path=str(self.serial),
                                             preserve_foreign=True,
                                             foreign_backup_dir=str(backup_dir))
        self.assertTrue(result["ready"])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.rows()[master]["bind_node_id"],
                         json.loads(Path(result["archive"]).read_text())["rows"][0]["bind_node_id"])
        archive, = self.archives(backup_dir)
        content = archive.read_bytes()
        self.assertFalse(Path(str(self.db) + ".pre-license").exists())
        self.apply(project, foreign_backup_dir=str(backup_dir))
        self.assertEqual(self.archives(backup_dir), [archive])
        self.assertEqual(archive.read_bytes(), content)
        self.assertEqual(self.archives(), [])

    def test_preinstall_archive_invalid_project_has_no_backup(self):
        self.insert(self.issue(foreign=True), 17)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "device ID differs"):
            gl.archive_foreign_database(self.issue(device="wrong-device"), str(self.db),
                                       serial_path=str(self.serial), preserve_foreign=True)
        self.assertEqual(self.snapshot(), before)
        self.assert_no_backups()

    def test_foreign_preservation_never_trusts_arbitrary_root_fingerprint(self):
        self.insert(self.issue(foreign=True), 17)
        foreign_fp = cs.fingerprint((self.keydir / "foreign.crt").read_text())
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "established project ownership"):
            gl.preflight_database(str(self.db), preserve_foreign=True,
                                  replace_root_fingerprints=[foreign_fp])
        self.assertEqual(self.snapshot(), before)
        self.assert_no_backups()

    def test_preflight_cli_export_pending_and_archive_cli_need_no_private_key(self):
        self.insert(self.issue(foreign=True), 17)
        before = self.snapshot()
        env = dict(os.environ, SIGN_CRT=str(self.keydir / "project.crt"),
                   SIGN_KEY=str(self.base / "missing-key"), PYTHONDONTWRITEBYTECODE="1")
        command = [sys.executable, str(ROOT / "tools/gen_license.py"), "--db", str(self.db),
                   "--serial-path", str(self.serial), "--preserve-foreign"]
        result = subprocess.run(command + ["--preflight-db"], env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["foreignLicenseCount"], 1)
        output = self.base / "project.txt"
        result = subprocess.run(command + ["--export-existing", str(output)], env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn("project offline certificate", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(self.snapshot(), before)
        self.assert_no_backups()
        project_file = self.base / "import.txt"
        project_file.write_text(self.issue()["license"])
        result = subprocess.run(command + ["--archive-foreign", "--import-file", str(project_file)],
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(Path(json.loads(result.stdout)["archive"]).is_file())
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(Path(str(self.db) + ".pre-license").exists())

    def test_expired_owned_duplicates_are_replaced_without_touching_other_nodes(self):
        expired = self.issue(expires="2001-01-01")
        master = self.insert(expired, 17)
        duplicate = self.insert(expired, 17)
        unbound = self.insert(expired)
        other_owned = self.insert(expired, 23)
        foreign = self.insert(self.issue(foreign=True), 17)
        before = self.rows()
        self.apply()
        after = self.rows()
        self.assertIn(master, after)
        self.assertNotIn(duplicate, after)
        self.assertNotIn(unbound, after)
        self.assertEqual(after[other_owned], before[other_owned])
        self.assertEqual(gl.decrypt_row(after[master])["free_nodes"], '["foreign-child"]')
        self.assertEqual({k for k in before[foreign] if before[foreign][k] != after[foreign][k]},
                         {"bind_node_id"})


if __name__ == "__main__":
    unittest.main()
