"""Offline license generation / import / binding regressions (mock SQLite, no services)."""

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("gen_license", ROOT / "tools/gen_license.py")
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)


def make_db(path):
    con = sqlite3.connect(path)
    con.execute("create table nodes (id integer primary key, name text)")
    con.execute("insert into nodes(name) values('local')")
    con.execute("""create table licenses (
        id integer primary key autoincrement,
        license_name text, usage_name text, assignee_name text, version_constraint text,
        device_id text, license text, offline text, trial text, issuer text, product_pro text,
        last_sync_at text, sms_total text, sms_used text, bind_node_id text,
        free_count text, free_nodes text, status text, message text,
        created_at text, updated_at text)""")
    con.execute("""create table core_settings (
        id integer primary key autoincrement, created_at text, updated_at text,
        key text, value text, description text)""")
    con.commit()
    con.close()


class LicenseCodecTests(unittest.TestCase):
    def test_three_segment_roundtrip(self):
        content, _row = gen.build("enterprise", "2099-12-31", 999, "YG",
                                  "0" * 32, "lxware", 100000, False, True, "2.x")
        text = gen.encode_license(content)
        parts = text.split("-")
        self.assertGreaterEqual(len(parts), 3)
        decoded = gen.decode_license(text)
        self.assertEqual(decoded["licenseName"], content["licenseName"])
        self.assertEqual(decoded["products"][0]["maxNodeCount"], 999)

    def test_permanent_enterprise_fields(self):
        content, row = gen.build("enterprise", "2099-12-31", 999, "YG",
                                 "d" * 32, "lxware", 100000, False, True, "2.x")
        self.assertEqual(len(content["products"]), 2)  # pro + xpack
        for product in content["products"]:
            self.assertEqual(product["maxNodeCount"], 999)
            self.assertTrue(product["expiresAt"].startswith("2099-12-31"))
        self.assertEqual(content["annotations"]["lxware.cn/edition"], "enterprise")
        self.assertEqual(row["offline"], "true")
        self.assertEqual(row["free_count"], "999")
        self.assertEqual(row["status"], "Bound")
        self.assertGreater(int(row["product_pro"]), 0)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "xpack.db"
        make_db(self.db)
        self.serial = Path(self.tmp.name) / ".serial"
        self.serial.write_text("a" * 32)

    def tearDown(self):
        self.tmp.cleanup()

    def _apply(self):
        content, _ = gen.build("enterprise", "2099-12-31", 999, "YG",
                               self.serial.read_text(), "lxware", 100000, False, True, "2.x")
        text = gen.encode_license(content)
        row = gen.row_from_content(content, text=text)
        return gen.apply_row(row, str(self.db), restart=False,
                             serial_path=str(self.serial))

    def test_apply_then_verify(self):
        self._apply()
        result = gen.verify_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(result["maxNodeCount"], 999)
        self.assertEqual(result["status"], "Bound")
        self.assertTrue(result["offline"])

    def test_reapply_preserves_and_unbinds(self):
        self._apply()
        first = gen.preflight_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(first["licenseCount"], 1)
        self.assertEqual(len(first["boundLicenses"]), 1)

        result = self._apply()
        self.assertEqual(result["unbound"], 1)  # 旧绑定已解除

        after = gen.preflight_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(after["licenseCount"], 2)  # 旧证书保留，不删除
        self.assertEqual(len(after["boundLicenses"]), 1)  # 仅新证书绑定
        self.assertEqual(after["boundLicenses"], [gen.verify_database(
            str(self.db), serial_path=str(self.serial))["licenseName"]])

    def test_serial_mismatch_rejected(self):
        content, _ = gen.build("enterprise", "2099-12-31", 999, "YG",
                               "f" * 32, "lxware", 100000, False, True, "2.x")
        text = gen.encode_license(content)
        row = gen.row_from_content(content, text=text)
        with self.assertRaises(ValueError):
            gen.apply_row(row, str(self.db), restart=False, serial_path=str(self.serial))


if __name__ == "__main__":
    unittest.main()
