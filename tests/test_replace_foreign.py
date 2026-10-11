"""Direct replacement of third-party licenses by the project-signed license.

Run: python3 -m unittest discover -s tests -p test_replace_foreign.py -v
Real generator semantics run against temporary databases; the installer tests use
the temporary Fixture, so no live panel, database or signing key is touched.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_unlock import Fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import gen_license as gl


class ReplaceForeignRowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(prefix="replace-foreign-keys-")
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
        self.temp = tempfile.TemporaryDirectory(prefix="replace-foreign-db-")
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
                              "insert into nodes values(17,'local');insert into nodes values(23,'other');")
            fields = ("license_name usage_name assignee_name version_constraint device_id license "
                      "offline trial issuer product_pro last_sync_at sms_total sms_used bind_node_id "
                      "free_count free_nodes status message")
            con.execute("create table licenses(id integer primary key,created_at text,updated_at text," +
                        ",".join('"%s" text' % name for name in fields.split()) + ")")

    def issue(self, foreign=False):
        content, _ = gl.build("enterprise", "2099-12-31", 10, "Fixture", "temporary-device",
                              "fixture", 0, False, True, "2.x")
        if foreign:
            with mock.patch.multiple(gl, SIGN_KEY=str(self.keydir / "foreign.key"),
                                     SIGN_CRT=str(self.keydir / "foreign.crt")):
                text = gl.encode_license(content)
        else:
            text = gl.encode_license(content)
        return gl.row_from_content(content, text=text)

    def insert(self, row, bound=""):
        stored = gl.encrypt_row(dict(row, bind_node_id=str(bound), free_nodes='["child"]'))
        with sqlite3.connect(self.db) as con:
            cursor = con.execute("insert into licenses (%s) values (%s)" % (
                ",".join(stored), ",".join("?" * len(stored))), list(stored.values()))
            return cursor.lastrowid

    def rows(self):
        with sqlite3.connect(self.db) as con:
            con.row_factory = sqlite3.Row
            return {row["id"]: dict(row) for row in con.execute("select * from licenses")}

    def archives(self):
        return sorted(self.base.glob("foreign-licenses.*.json"))

    def apply(self, row=None, **kwargs):
        return gl.apply_row(row or self.issue(), str(self.db), restart=False,
                            serial_path=str(self.serial), preserve_foreign=True, **kwargs)

    def fixture_rows(self):
        master = self.insert(self.issue(foreign=True), 17)
        other_foreign = self.insert(self.issue(foreign=True), 23)
        unbound_foreign = self.insert(self.issue(foreign=True))
        other_project = self.insert(self.issue(), 23)
        return master, other_foreign, unbound_foreign, other_project

    def test_replace_foreign_drops_every_third_party_row_and_archives_it(self):
        master, other_foreign, unbound_foreign, other_project = self.fixture_rows()
        before = self.rows()
        project = self.issue()
        self.apply(project, replace_foreign=True)
        after = self.rows()
        self.assertEqual(len(after), 2)
        self.assertEqual(after[other_project], before[other_project])
        new_id, = set(after) - set(before)
        for dropped in (master, other_foreign, unbound_foreign):
            self.assertNotIn(dropped, after)
        imported = gl.decrypt_row(after[new_id])
        self.assertEqual(imported["bind_node_id"], "17")
        self.assertEqual(imported["license"], project["license"])
        archive, = self.archives()
        payload = archive.read_bytes()
        self.assertEqual(archive.name, "foreign-licenses.%s.json" % hashlib.sha256(payload).hexdigest())
        self.assertEqual(json.loads(payload)["rows"],
                         [before[i] for i in (master, other_foreign, unbound_foreign)])
        self.assertTrue(gl.verify_database(str(self.db), str(self.serial))["signatureVerified"])

    def test_replace_foreign_requires_preserve_foreign(self):
        self.fixture_rows()
        before = self.rows()
        with self.assertRaisesRegex(ValueError, "requires --preserve-foreign"):
            gl.apply_row(self.issue(), str(self.db), False, None, str(self.serial),
                         (), False, None, True)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.archives(), [])

    def test_preserve_mode_still_keeps_foreign_rows(self):
        master, other_foreign, unbound_foreign, other_project = self.fixture_rows()
        before = self.rows()
        self.apply(self.issue())
        after = self.rows()
        self.assertEqual(len(after), 5)
        for kept in (master, other_foreign, unbound_foreign, other_project):
            self.assertIn(kept, after)
        self.assertEqual(after[unbound_foreign], before[unbound_foreign])
        self.assertEqual({key for key in before[master] if before[master][key] != after[master][key]},
                         {"bind_node_id"})
        self.assertEqual(gl.decrypt_row(after[master])["bind_node_id"], "")
        archive, = self.archives()
        self.assertEqual([row["id"] for row in json.loads(archive.read_bytes())["rows"]],
                         [master, other_foreign, unbound_foreign])

    def test_archive_before_install_captures_unbound_rows_in_replace_mode(self):
        master, other_foreign, unbound_foreign, other_project = self.fixture_rows()
        project = self.issue()
        row = {"license": project["license"]}
        with sqlite3.connect(self.db) as con:
            con.execute("delete from licenses where id=?", (master,))
        # With no foreign row holding the master binding, preserve mode archives nothing.
        self.assertIsNone(gl.archive_foreign_database(row, str(self.db), None, str(self.serial), (),
                                                      True, str(self.base))["archive"])
        result = gl.archive_foreign_database(row, str(self.db), None, str(self.serial), (),
                                             True, str(self.base), True)
        self.assertEqual(result["foreignLicenseCount"], 2)
        self.assertEqual([entry["id"] for entry in json.loads(Path(result["archive"]).read_bytes())["rows"]],
                         [other_foreign, unbound_foreign])
        # Archiving never changes rows; the replace itself happens on apply.
        self.assertEqual(len(self.rows()), 3)
        with sqlite3.connect(self.db) as con:
            con.execute("delete from licenses where id in (?, ?)", (other_foreign, unbound_foreign))
        self.assertIsNone(gl.archive_foreign_database(row, str(self.db), None, str(self.serial), (),
                                                      True, str(self.base), True)["archive"])

    def test_cli_apply_replace_foreign(self):
        master, other_foreign, unbound_foreign, other_project = self.fixture_rows()
        issued = self.base / "issued.txt"
        issued.write_text(self.issue()["license"] + "\n")
        env = {**os.environ, "SIGN_KEY": str(self.keydir / "project.key"),
               "SIGN_CRT": str(self.keydir / "project.crt")}
        result = subprocess.run([sys.executable, str(ROOT / "tools/gen_license.py"),
                                 "--import-file", str(issued), "--apply", "--no-restart",
                                 "--preserve-foreign", "--replace-foreign", "--foreign-backup-dir",
                                 str(self.base), "--db", str(self.db), "--serial-path", str(self.serial)],
                                env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = self.rows()
        self.assertEqual(len(after), 2)
        self.assertIn(other_project, after)
        for dropped in (master, other_foreign, unbound_foreign):
            self.assertNotIn(dropped, after)
        self.assertEqual(len(self.archives()), 1)
        rejected = subprocess.run([sys.executable, str(ROOT / "tools/gen_license.py"),
                                   "--import-file", str(issued), "--apply", "--no-restart",
                                   "--replace-foreign", "--db", str(self.db),
                                   "--serial-path", str(self.serial)],
                                  env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("--replace-foreign requires --preserve-foreign", rejected.stderr)


class ReplaceForeignInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="replace-foreign-installer-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_replace_foreign_env_replaces_third_party_rows_with_project_license(self):
        tools, _ = self.f.real_foreign_fixture()
        foreign_id = self.f.rows("licenses")[0]["id"]
        issued = self.f.real_project_license(tools)
        (self.f.state / "license.key").unlink()
        result = self.f.run(LICENSE_FILE=str(issued), REPLACE_FOREIGN="1")
        self.ok(result)
        rows = self.f.rows("licenses")
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0]["id"], foreign_id)
        archive, = self.f.backup.glob("foreign-licenses.*.json")
        self.assertEqual([row["id"] for row in json.loads(archive.read_text())["rows"]], [foreign_id])
        self.assertIn("third-party licenses will be archived", result.stdout.lower())
        self.assertIn("replaced by the project-signed license", result.stdout)
        code = r'''
import sqlite3, sys
sys.path.insert(0, sys.argv[1]); import gen_license as g
with sqlite3.connect(sys.argv[2]) as c:
    c.row_factory = sqlite3.Row
    rows = [g.decrypt_row(dict(row)) for row in c.execute("select * from licenses order by id")]
assert len(rows) == 1, rows
assert rows[0]["bind_node_id"] == "17", rows[0]["bind_node_id"]
assert g.verify_license(rows[0]["license"])["products"][0]["maxNodeCount"] == 42
'''
        self.ok(subprocess.run([sys.executable, "-c", code, str(tools), str(self.f.db)],
                               env=self.f.env, capture_output=True, text=True, timeout=30))

    def test_replace_foreign_without_project_license_fails_before_replacement(self):
        self.f.real_foreign_fixture()
        before = self.f.rows("licenses")
        (self.f.state / "license.key").unlink()
        (self.f.state / "license.crt").unlink()
        result = self.f.run(REPLACE_FOREIGN="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("REPLACE_FOREIGN=1", result.stderr)
        self.assertEqual(self.f.rows("licenses"), before)
        self.assertEqual(list(self.f.backup.glob("foreign-licenses.*.json")), [])
        self.assertEqual(self.f.core.read_bytes(), b"fixture installed core, not a live binary")


if __name__ == "__main__":
    unittest.main()
