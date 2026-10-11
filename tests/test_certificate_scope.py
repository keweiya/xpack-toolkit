"""Certificate mutations stay inside verified project ownership in temporary DBs."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import cert_store as cs
import gen_license as gl


class CertificateScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(prefix="certificate-scope-keys-")
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
        self.temp = tempfile.TemporaryDirectory(prefix="certificate-scope-db-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.db = self.base / "xpack.db"
        self.serial = self.base / ".serial"
        self.serial.write_text("temporary-device")
        self.pem = (self.keydir / "project.crt").read_text()
        self.fp = cs.fingerprint(self.pem)
        self.foreign_pem = (self.keydir / "foreign.crt").read_text()
        self.foreign_fp = cs.fingerprint(self.foreign_pem)
        self.patch = mock.patch.multiple(gl, SIGN_KEY=str(self.keydir / "project.key"),
                                        SIGN_CRT=str(self.keydir / "project.crt"))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        with sqlite3.connect(self.db) as con:
            con.executescript("create table core_settings(id integer primary key,created_at text,"
                              "updated_at text,key text,value text,description text);"
                              "create table nodes(id integer primary key,name text);"
                              "insert into nodes values(17,'local');insert into nodes values(23,'other');"
                              "create table website_certificates(id integer primary key,pem text);"
                              "insert into website_certificates values(1,'unrelated website certificate');"
                              "insert into core_settings(key,value) values('UnrelatedCertificate','keep-me');")
            fields = "license_name usage_name assignee_name version_constraint device_id license offline trial issuer product_pro last_sync_at sms_total sms_used bind_node_id free_count free_nodes status message"
            con.execute("create table licenses(id integer primary key,created_at text,updated_at text," +
                        ",".join('"%s" text' % name for name in fields.split()) + ")")

    def snapshot(self):
        with sqlite3.connect(self.db) as con:
            return list(con.iterdump())

    def issue(self, expires="2099-12-31", foreign=False):
        content, _ = gl.build("enterprise", expires, 10, "Fixture", "temporary-device",
                              "fixture", 0, False, True, "2.x")
        if foreign:
            with mock.patch.multiple(gl, SIGN_KEY=str(self.keydir / "foreign.key"),
                                     SIGN_CRT=str(self.keydir / "foreign.crt")):
                text = gl.encode_license(content)
        else:
            text = gl.encode_license(content)
        return gl.row_from_content(content, text=text)

    def insert_license(self, row, bound="", free_nodes="[]"):
        stored = gl.encrypt_row(dict(row, bind_node_id=str(bound), free_nodes=free_nodes))
        with sqlite3.connect(self.db) as con:
            cursor = con.execute("insert into licenses (%s) values (%s)" % (
                ",".join(stored), ",".join("?" * len(stored))), list(stored.values()))
            return cursor.lastrowid

    def roots(self, hk=None, cn=None):
        with sqlite3.connect(self.db) as con:
            for region, pem in (("hk", hk), ("cn", cn)):
                if pem is None:
                    continue
                for key, value in ((cs.KEYS["cert_" + region], pem),
                                   (cs.KEYS["fp_" + region], cs.fingerprint(pem))):
                    con.execute("insert into core_settings(key,value) values(?,?)", (key, cs.encrypt(value)))

    def test_copied_known_certificate_with_forged_signature_is_preserved(self):
        row = self.issue()
        parts = row["license"].split("-")
        parts[1] = base64.b64encode(b"forged signature").decode()
        row["license"] = "-".join(parts)
        forged_id = self.insert_license(row)
        gl.apply_row(self.issue(), str(self.db), restart=False, serial_path=str(self.serial))
        with sqlite3.connect(self.db) as con:
            forged = dict(zip([d[0] for d in con.execute("select * from licenses").description],
                              con.execute("select * from licenses where id=?", (forged_id,)).fetchone()))
            self.assertEqual(gl.decrypt_blob(forged["license"]), row["license"])
            self.assertEqual(con.execute("select count(*) from licenses").fetchone()[0], 2)

    def test_expired_verified_project_rows_replace_only_project_duplicates(self):
        expired = self.issue("2001-01-01")
        keep = self.insert_license(expired, 17, '["kept-child"]')
        duplicate = self.insert_license(expired, 17)
        unbound = self.insert_license(expired)
        other_owned = self.insert_license(expired, 23)
        foreign = self.insert_license(self.issue(foreign=True), 23)
        with sqlite3.connect(self.db) as con:
            untouched = con.execute("select * from licenses where id in (?,?)", (other_owned, foreign)).fetchall()
        self.assertTrue(gl.preflight_database(str(self.db), str(self.serial))["ready"])
        gl.apply_row(self.issue(), str(self.db), restart=False, serial_path=str(self.serial))
        with sqlite3.connect(self.db) as con:
            con.row_factory = sqlite3.Row
            rows = {r["id"]: dict(r) for r in con.execute("select * from licenses")}
            self.assertEqual(set(rows), {keep, other_owned, foreign})
            self.assertEqual(gl.decrypt_row(rows[keep])["free_nodes"], '["kept-child"]')
            self.assertNotIn(duplicate, rows)
            self.assertNotIn(unbound, rows)
            actual = [tuple(rows[i].values()) for i in (other_owned, foreign)]
            self.assertEqual(actual, untouched)

    def test_foreign_master_preflight_and_apply_have_zero_writes(self):
        self.insert_license(self.issue(foreign=True), 17)
        before = self.snapshot()
        for operation in (lambda: gl.preflight_database(str(self.db), str(self.serial)),
                          lambda: gl.apply_row(self.issue(), str(self.db), restart=False,
                                               serial_path=str(self.serial))):
            with self.assertRaisesRegex(ValueError, "different issuer"):
                operation()
            self.assertEqual(self.snapshot(), before)
            self.assertFalse(Path(str(self.db) + ".pre-license").exists())

    def test_only_verified_plaintext_or_encrypted_signed_license_establishes_ownership(self):
        row = self.issue()
        known = gl._known_roots()
        self.assertTrue(gl._owned_license(row, known))
        self.assertTrue(gl._owned_license(gl.encrypt_row(row), known))
        content = gl.decode_license(row["license"])
        content["licenseName"] = "1Panel Enterprise"
        content["license"] = "1P-" + hashlib.sha256(("%s|%s|%s" % (
            content["assigneeName"], content["products"][0]["expiresAt"],
            content["products"][0]["maxNodeCount"])).encode()).hexdigest()[:24].upper()
        self.assertFalse(gl._owned_license({"license": gl.encrypt_blob(json.dumps(content).encode())}, known))
        row["version_constraint"] = "2.x"
        self.assertFalse(gl._owned_license({"license": "", "version_constraint": "2.x"}, known))
        self.assertFalse(gl._owned_license({"license": 12345}, known))

    def test_arbitrary_replacement_fingerprint_is_rejected(self):
        self.roots(self.foreign_pem, self.foreign_pem)
        before = self.snapshot()
        for operation in (lambda: gl.preflight_database(str(self.db), replace_root_fingerprints=[self.foreign_fp]),
                          lambda: cs.check_owned_roots(str(self.db), self.pem, [self.foreign_fp]),
                          lambda: cs.write(str(self.db), self.pem, self.fp, extra_fps=[self.foreign_fp])):
            with self.assertRaisesRegex(ValueError, "established project ownership"):
                operation()
            self.assertEqual(self.snapshot(), before)

    def test_foreign_and_mixed_roots_preserved_by_write_and_restore(self):
        self.roots(self.pem, self.foreign_pem)
        before = self.snapshot()
        for operation in (lambda: cs.check_owned_roots(str(self.db), self.pem),
                          lambda: cs.write(str(self.db), self.pem, self.fp),
                          lambda: cs.restore(str(self.db), str(self.base / "missing.json"), self.pem)):
            with self.assertRaisesRegex(ValueError, "foreign root"):
                operation()
            self.assertEqual(self.snapshot(), before)

    def test_malformed_and_incoherent_root_pairs_are_preserved(self):
        self.roots(self.pem, self.pem)
        with sqlite3.connect(self.db) as con:
            con.execute("update core_settings set value=? where key=?", (cs.encrypt(self.foreign_fp), cs.KEYS["fp_hk"]))
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "fingerprint differ"):
            cs.write(str(self.db), self.pem, self.fp)
        self.assertEqual(self.snapshot(), before)
        with sqlite3.connect(self.db) as con:
            con.execute("update core_settings set value='malformed' where key=?", (cs.KEYS["cert_hk"],))
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "malformed root"):
            cs.write(str(self.db), self.pem, self.fp)
        self.assertEqual(self.snapshot(), before)

    def test_initial_and_repeated_root_write_leave_other_certificates_untouched(self):
        for _ in range(2):
            self.assertTrue(cs.check_owned_roots(str(self.db), self.pem)["ready"])
            cs.write(str(self.db), self.pem, self.fp)
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute("select * from website_certificates").fetchall(),
                             [(1, "unrelated website certificate")])
            self.assertEqual(con.execute("select value from core_settings where key='UnrelatedCertificate'").fetchone()[0], "keep-me")
        self.assertEqual(cs.check_owned_roots(str(self.db), self.pem)["roots"],
                         {"hk": "project", "cn": "project"})

    def test_official_backup_coherence_and_restore_key_whitelist(self):
        official = json.loads(Path(cs.OFFICIAL_JSON).read_text())
        self.assertTrue(cs.is_official(official))
        backup = self.base / "official.json"
        backup.write_text(json.dumps(dict(official, UnrelatedCertificate="overwrite-attempt")))
        self.roots(self.pem, self.pem)
        cs.restore(str(self.db), str(backup), self.pem)
        with sqlite3.connect(self.db) as con:
            roots = dict(con.execute("select key,value from core_settings where key like 'LicenseRootCert%'"))
            self.assertTrue(cs.is_official(roots))
            self.assertEqual(con.execute("select value from core_settings where key='UnrelatedCertificate'").fetchone()[0], "keep-me")
        before = self.snapshot()
        cs.restore(str(self.db), str(backup), self.pem)
        self.assertEqual(self.snapshot(), before)

    def test_preflight_cli_produces_ready_without_export_sign_or_backup(self):
        env = dict(os.environ, SIGN_CRT=str(self.keydir / "project.crt"),
                   SIGN_KEY=str(self.base / "missing-private-key"), PYTHONDONTWRITEBYTECODE="1")
        output = self.base / "must-not-export.txt"
        before = self.snapshot()
        commands = ([sys.executable, str(ROOT / "tools/gen_license.py"), "--preflight-db",
                     "--db", str(self.db), "--serial-path", str(self.serial),
                     "--export-existing", str(output)],
                    [sys.executable, str(ROOT / "tools/cert_store.py"), "--check-owned",
                     "--db", str(self.db), "--cert", str(self.keydir / "project.crt"),
                     "--bak", str(self.base / "never-backup.json")])
        for command in commands:
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["ready"])
            self.assertEqual(self.snapshot(), before)
        self.assertFalse(output.exists())
        self.assertFalse((self.base / "never-backup.json").exists())

    def test_transaction_rechecks_roots_after_read_only_preflight(self):
        self.roots(self.pem, self.pem)
        check = cs.check_owned_roots
        def changed(db, pem=None, extra_fps=()):
            result = check(db, pem, extra_fps)
            with sqlite3.connect(db) as con:
                for region in ("hk", "cn"):
                    for key, value in ((cs.KEYS["cert_" + region], self.foreign_pem),
                                       (cs.KEYS["fp_" + region], self.foreign_fp)):
                        con.execute("update core_settings set value=? where key=?", (cs.encrypt(value), key))
            return result
        with mock.patch.object(cs, "check_owned_roots", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "foreign root"):
                cs.write(str(self.db), self.pem, self.fp)
        with sqlite3.connect(self.db) as con:
            rows = dict(con.execute("select key,value from core_settings where key like 'LicenseRootCert%'"))
        for region in ("hk", "cn"):
            self.assertEqual(cs.decrypt(rows[cs.KEYS["cert_" + region]]), self.foreign_pem)
            self.assertEqual(cs.decrypt(rows[cs.KEYS["fp_" + region]]), self.foreign_fp)

    def test_transaction_rechecks_master_before_creating_license_backup(self):
        preflight = gl.preflight_database
        def changed(*args, **kwargs):
            result = preflight(*args, **kwargs)
            self.insert_license(self.issue(foreign=True), 17)
            return result
        with mock.patch.object(gl, "preflight_database", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "different issuer"):
                gl.apply_row(self.issue(), str(self.db), restart=False, serial_path=str(self.serial))
        self.assertFalse(Path(str(self.db) + ".pre-license").exists())
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute("select count(*) from licenses").fetchone()[0], 1)

    def test_restore_keeps_existing_official_region_bytes_unchanged(self):
        official = json.loads(Path(cs.OFFICIAL_JSON).read_text())
        self.roots(self.pem, None)
        with sqlite3.connect(self.db) as con:
            for key in (cs.KEYS["cert_cn"], cs.KEYS["fp_cn"]):
                con.execute("insert into core_settings(key,value) values(?,?)", (key, official[key]))
            before = con.execute("select * from core_settings where key in (?,?)",
                                 (cs.KEYS["cert_cn"], cs.KEYS["fp_cn"])).fetchall()
        cs.restore(str(self.db), str(self.base / "missing.json"), self.pem)
        with sqlite3.connect(self.db) as con:
            after = con.execute("select * from core_settings where key in (?,?)",
                                (cs.KEYS["cert_cn"], cs.KEYS["fp_cn"])).fetchall()
        self.assertEqual(after, before)

    def test_database_uri_encodes_reserved_path_characters(self):
        renamed = self.base / "xpack?#fixture.db"
        self.db.rename(renamed)
        self.db = renamed
        self.assertTrue(gl.preflight_database(str(self.db))["ready"])
        self.assertTrue(cs.check_owned_roots(str(self.db), self.pem)["ready"])

    def test_empty_official_backup_is_rejected_without_changes(self):
        self.roots(self.pem, self.pem)
        backup = self.base / "empty.json"
        backup.write_text("{}")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "coherent official"):
            cs.restore(str(self.db), str(backup), self.pem)
        self.assertEqual(self.snapshot(), before)

    def test_signed_but_malformed_payload_never_establishes_ownership(self):
        for content in ({}, {"licenseName": "fixture", "deviceID": "fixture", "license": "fixture",
                             "products": [{"name": "product-1panel-pro", "expiresAt": "bad-date"}]}):
            text = gl.encode_license(content)
            self.assertFalse(gl._owned_license({"license": gl.encrypt_blob(text.encode())}, gl._known_roots()))


if __name__ == "__main__":
    unittest.main()
