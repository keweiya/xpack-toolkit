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

    def test_year_ge_9999_is_permanent(self):
        # 年份 >= 9999 视为永久：product_pro 写 "0"，面板跳过过期比较。
        content, row = gen.build("enterprise", "9999-12-31", 999, "YG",
                                 "d" * 32, "lxware", 100000, False, True, "all")
        self.assertEqual(row["product_pro"], "0")
        self.assertEqual(row["version_constraint"], "all")
        self.assertEqual(content["products"][0]["expiresAt"], "9999-12-31T00:00:00Z")
        # 往返导入后仍是永久标记
        back = gen.row_from_content(content, text="dummy")
        self.assertEqual(back["product_pro"], "0")


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

    def test_reapply_replaces_toolkit_license(self):
        self._apply()
        first = gen.preflight_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(first["licenseCount"], 1)
        self.assertEqual(len(first["boundLicenses"]), 1)

        result = self._apply()
        self.assertEqual(result["deleted"], 1)  # 旧脚本证书被删除
        self.assertEqual(result["unbound"], 0)  # 旧绑定随删除消失，无需解绑

        after = gen.preflight_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(after["licenseCount"], 1)  # 只保留新脚本证书，不累积
        self.assertEqual(len(after["boundLicenses"]), 1)
        self.assertEqual(after["boundLicenses"], [gen.verify_database(
            str(self.db), serial_path=str(self.serial))["licenseName"]])

    def test_thirdparty_license_preserved_and_unbound(self):
        # 第三方证书：licenseName 用面板导入格式，不带 xpack-toolkit 标记。
        content, _ = gen.build("enterprise", "2099-12-31", 999, "waaaater",
                               self.serial.read_text(), "lxware", 100000, False, True, "2.x")
        content["licenseName"] = "license-Panel-VSExQ"  # 模拟面板导入的第三方证书
        content["annotations"].pop("lxware.cn/xpack-toolkit", None)
        text = gen.encode_license(content)
        third = gen.row_from_content(content, text=text)
        gen.apply_row(third, str(self.db), restart=False, serial_path=str(self.serial))

        # 应用脚本证书：第三方保留、解绑，脚本证书插入并绑定。
        result = self._apply()
        self.assertEqual(result["deleted"], 0)   # 第三方不删除
        self.assertEqual(result["unbound"], 1)   # 第三方的主节点绑定被解除

        after = gen.preflight_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(after["licenseCount"], 2)  # 第三方 + 脚本证书
        self.assertEqual(len(after["boundLicenses"]), 1)

    def test_legacy_toolkit_license_name_recognized(self):
        # 旧版脚本证书无标记，但 licenseName 前缀可识别为脚本证书，仍会删除。
        content, _ = gen.build("enterprise", "2099-12-31", 999, "YG",
                               self.serial.read_text(), "lxware", 100000, False, True, "2.x")
        content["annotations"].pop("lxware.cn/xpack-toolkit", None)  # 模拟旧版无标记
        text = gen.encode_license(content)
        legacy = gen.row_from_content(content, text=text)
        gen.apply_row(legacy, str(self.db), restart=False, serial_path=str(self.serial))

        result = self._apply()
        self.assertEqual(result["deleted"], 1)  # 旧脚本证书（无标记）仍被删除
        after = gen.preflight_database(str(self.db), serial_path=str(self.serial))
        self.assertEqual(after["licenseCount"], 1)

    def test_child_nodes_migrate_to_new_license(self):
        # 旧脚本证书绑定主节点 + 2 个子节点，重跑后子节点绑定迁移到新证书。
        content, _ = gen.build("enterprise", "2099-12-31", 999, "YG",
                               self.serial.read_text(), "lxware", 100000, False, True, "2.x")
        text = gen.encode_license(content)
        old = gen.row_from_content(content, text=text)
        old["free_nodes"] = json.dumps([
            {"id": 2, "addr": "192.168.1.2", "name": "node2", "isXpack": False},
            {"id": 3, "addr": "192.168.1.3", "name": "node3", "isXpack": False},
        ])
        gen.apply_row(old, str(self.db), restart=False, serial_path=str(self.serial))

        result = self._apply()
        self.assertEqual(result["deleted"], 1)

        # 新绑定证书继承了子节点绑定
        with sqlite3.connect(self.db) as con:
            con.row_factory = sqlite3.Row
            master = str(con.execute("select id from nodes where name='local'").fetchone()["id"])
            migrated = None
            for raw in con.execute("select * from licenses"):
                plain = gen.decrypt_row(dict(raw))
                if plain.get("bind_node_id") == master:
                    migrated = json.loads(plain.get("free_nodes") or "[]")
            self.assertIsNotNone(migrated)
            self.assertEqual(sorted(n["name"] for n in migrated), ["node2", "node3"])

    def test_serial_mismatch_rejected(self):
        content, _ = gen.build("enterprise", "2099-12-31", 999, "YG",
                               "f" * 32, "lxware", 100000, False, True, "2.x")
        text = gen.encode_license(content)
        row = gen.row_from_content(content, text=text)
        with self.assertRaises(ValueError):
            gen.apply_row(row, str(self.db), restart=False, serial_path=str(self.serial))


if __name__ == "__main__":
    unittest.main()
