#!/usr/bin/env python3
"""1Panel 授权证书（license certificate）生成器 —— 内网本地破解内核配套。

破解内核已移除全部授权校验（见 patch_core.py），因此本工具**不再需要签名私钥**：
生成的授权文件保持官方三段式结构（base64(JSON)-base64(签名占位)-base64(证书)）
供面板 `getLicenseContent` 正常解析、字段落库与界面展示；签名段仅在检测到本机
SIGN_KEY 时才做真实 RSA 签名，没有私钥就用占位符，内核不会校验它。

授权内容：
    edition       enterprise（企业版）
    maxNodeCount  999
    expiresAt     2099-12-31（永久）
    offline       true（不回连授权服务器）
    annotations   lxware.cn/username=Bound, lxware.cn/edition=enterprise

写入数据库（xpack.db 的 licenses 表）时：
    * 不删除、不移除任何既有证书/许可证行（保留原文）。
    * 若主节点已绑定到其它证书，先把旧绑定解除（bind_node_id 置空）再绑定新证书；
      交互终端下可提示用户确认（--prompt-unbind），非交互默认自动解绑。

Usage:
  # 生成一份 999 节点、永久有效的企业版授权文件（不写库）
  python3 tools/gen_license.py --out /tmp/license.txt

  # 直接写库 + 绑定主节点（保留旧证书，自动解除旧绑定）
  python3 tools/gen_license.py --apply --db /opt/1panel/db/xpack.db

  # 只解析已有授权文件
  python3 tools/gen_license.py --show license.txt
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import secrets
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aes128 import cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad  # noqa: E402

LICENSE_KEY = b"nel1Pa2520pack@x"
XPACK_DB = "/opt/1panel/db/xpack.db"
SERIAL = "/opt/1panel/db/.serial"

# LicenseRepo 加密：固定盐字段与「名称+盐」字段
STATIC_FIELDS = {"license_name", "license"}
TEXT_FIELDS = (
    "license_name", "usage_name", "assignee_name", "version_constraint",
    "device_id", "license", "offline", "trial", "issuer", "product_pro",
    "last_sync_at", "bind_node_id", "free_count", "free_nodes", "status", "message",
)

EDITIONS = {
    "free": ("Free", "1Panel Free", 0),
    "pro": ("Bound", "1Panel Professional", 0),
    "enterprise": ("Bound", "1Panel Enterprise", 0),
}

STATE_DIR = os.environ.get("STATE") or next((p for p in
    (os.path.join(ROOT, "web", "state"), os.path.join(ROOT, "state"))
    if os.path.isfile(os.path.join(p, "license.crt"))), os.path.join(ROOT, "state"))
SIGN_KEY = os.environ.get("SIGN_KEY", os.path.join(STATE_DIR, "license.key"))
SIGN_CRT = os.environ.get("SIGN_CRT", os.path.join(STATE_DIR, "license.crt"))


# --------------------------------------------------------------------------- #
# 授权文件编解码（三段式，与官方 getLicenseContent 解析兼容）
# --------------------------------------------------------------------------- #
def sign_payload(raw: bytes) -> str:
    """有本地私钥时做 RSA-SHA256 签名；否则返回占位符（内核不校验）。"""
    if os.path.isfile(SIGN_KEY):
        try:
            out = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", SIGN_KEY],
                input=raw, capture_output=True, check=True).stdout
            return base64.b64encode(out).decode()
        except (OSError, subprocess.CalledProcessError):
            pass
    # 占位签名：等长 64 字节 0x00（base64 后为合法串）
    return base64.b64encode(b"\x00" * 64).decode()


def cert_chain() -> str:
    """签名证书（DER）的 base64；无证书时用占位 DER。"""
    if os.path.isfile(SIGN_CRT):
        try:
            with open(SIGN_CRT) as fh:
                der = ssl.PEM_cert_to_DER_cert(fh.read())
            return base64.b64encode(der).decode()
        except (OSError, ValueError):
            pass
    return base64.b64encode(b"\x00" * 16).decode()


def encode_license(content: dict) -> str:
    """打包成面板认识的三段式授权文件（内容 + 签名 + 证书）。"""
    raw = json.dumps(content, ensure_ascii=False, separators=(",", ":")).encode()
    payload = base64.b64encode(raw).decode()
    return "-".join((payload, sign_payload(raw), cert_chain()))


def decode_license(text: str) -> dict:
    """按 getLicenseContent 的逻辑解析授权文件（至少 3 段，仅解析第 1 段）。"""
    text = text.strip()
    parts = text.split("-")
    if len(parts) < 3:
        raise ValueError("授权文件至少需要 3 段（用 '-' 分隔），当前 %d 段" % len(parts))
    raw = base64.b64decode(parts[0], validate=False)
    return json.loads(raw.decode())


# --------------------------------------------------------------------------- #
# 数据库字段加密（与面板 LicenseRepo.encrypt 一致）
# --------------------------------------------------------------------------- #
def encrypt_blob(plain: bytes, key: bytes = LICENSE_KEY) -> str:
    iv = secrets.token_bytes(16)
    return base64.b64encode(iv + cbc_encrypt(pkcs7_pad(plain), key[:16], iv)).decode()


def decrypt_blob(value, key=LICENSE_KEY):
    raw = base64.b64decode(value, validate=True)
    if len(raw) < 32 or len(raw) % 16:
        raise ValueError("invalid encrypted license field")
    return pkcs7_unpad(cbc_decrypt(raw[16:], key[:16], raw[:16])).decode()


def repository_key(name, date=None):
    suffix = "-" + date if date is not None else "2520pack@x"
    key = (name.replace("license-Panel-", "") + suffix).encode()
    return (key + b"u" * max(0, 16 - len(key)))[:16]


def encrypt_row(row):
    key = repository_key(row["license_name"])
    status_key = repository_key(row["license_name"],
                                dt.datetime.now().astimezone().strftime("%Y%m%d"))
    return {k: (encrypt_blob(str(v).encode(), LICENSE_KEY if k in STATIC_FIELDS
                            else status_key if k == "status" else key)
                if k in TEXT_FIELDS and str(v) else v) for k, v in row.items()}


def decrypt_row(row):
    name = decrypt_blob(row["license_name"])
    now = dt.datetime.now().astimezone()
    for date in (now.strftime("%Y%m%d"), (now - dt.timedelta(days=1)).strftime("%Y%m%d")):
        try:
            key = repository_key(name)
            status_key = repository_key(name, date)
            result = {k: (decrypt_blob(v, LICENSE_KEY if k in STATIC_FIELDS
                                      else status_key if k == "status" else key)
                          if k in TEXT_FIELDS and v else v) for k, v in row.items()}
            if result.get("offline") not in ("true", "false"):
                raise ValueError("invalid decrypted offline flag")
            return result
        except (ValueError, UnicodeError):
            continue
    raise ValueError("license repository key mismatch")


def machine_id(path=SERIAL):
    if os.path.exists(path):
        return open(path).read().strip()
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(p):
            return open(p).read().strip()
    return "0" * 32


def database_uri(db, mode="ro"):
    from pathlib import Path
    return Path(db).resolve().as_uri() + "?mode=" + mode


# --------------------------------------------------------------------------- #
# 证书构造
# --------------------------------------------------------------------------- #
def build(edition, expires, nodes, assignee, device_id, issuer,
          sms_total, trial, offline, version):
    status, _product, _ = EDITIONS[edition]
    exp = dt.datetime.strptime(expires, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    pro_unix = str(int(exp.timestamp()))
    pro_iso = exp.strftime("%Y-%m-%dT%H:%M:%SZ")

    products = [{
        "name": "product-1panel-pro",
        "expiresAt": pro_iso,
        "maxNodeCount": int(nodes),
        "versionConstraint": version,
    }]
    if edition == "enterprise":
        products.append({
            "name": "product-1panel-xpack",
            "expiresAt": pro_iso,
            "maxNodeCount": int(nodes),
            "versionConstraint": version,
        })

    content = {
        "licenseName": "1Panel-%s-%s" % (
            "Enterprise" if edition == "enterprise" else "Professional",
            secrets.token_hex(6).upper()),
        "usageName": "1panel",
        "assigneeName": assignee,
        "versionConstraint": version,
        "deviceID": device_id,
        "license": "1P-" + secrets.token_hex(12).upper(),
        "trial": bool(trial),
        "offline": bool(offline),
        "timerDiff": "0",
        "issuer": issuer,
        "products": products,
        "annotations": {
            "lxware.cn/username": "Bound" if not trial else "Free",
            "lxware.cn/edition": edition,
            "lxware.cn/nodes": str(nodes),
        },
        "smsTotal": int(sms_total),
        "smsUsed": 0,
    }
    row = {
        "license_name": content["licenseName"],
        "usage_name": "1panel",
        "assignee_name": assignee,
        "version_constraint": version,
        "device_id": device_id,
        "license": "",
        "offline": "true" if offline else "false",
        "trial": "true" if trial else "false",
        "issuer": issuer,
        "product_pro": pro_unix,          # 授权期限（Unix 秒）
        "last_sync_at": str(int(now.timestamp())),
        "sms_total": int(sms_total),
        "sms_used": 0,
        "bind_node_id": "",
        "free_count": str(nodes),         # 子节点数量
        "free_nodes": "[]",
        "status": status,
        "message": "",
    }
    return content, row


def row_from_content(content, device_id=None, text=""):
    """把一份证书内容还原成 licenses 表的一行（导入用）。"""
    products = content.get("products") or []
    pro = next((p for p in products if p.get("name") == "product-1panel-pro"), None)
    if pro is None:
        raise ValueError("missing product-1panel-pro")
    expires = str(pro.get("expiresAt") or "")
    ts = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        raise ValueError("certificate expiration requires a timezone")
    nodes = int(pro.get("maxNodeCount") or 0)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return {
        "license_name": content.get("licenseName") or "1Panel Enterprise",
        "usage_name": content.get("usageName") or "1panel",
        "assignee_name": content.get("assigneeName") or "YG",
        "version_constraint": content.get("versionConstraint") or "2.x",
        "device_id": content.get("deviceID") or device_id or machine_id(),
        "license": text,
        "offline": "true" if content.get("offline") else "false",
        "trial": "true" if content.get("trial") else "false",
        "issuer": content.get("issuer") or "lxware",
        "product_pro": str(int(ts.timestamp())),
        "last_sync_at": str(int(now.timestamp())),
        "sms_total": int(content.get("smsTotal") or 0),
        "sms_used": int(content.get("smsUsed") or 0),
        "bind_node_id": "",
        "free_count": str(nodes),
        "free_nodes": "[]",
        "status": "Bound",
        "message": "",
    }


# --------------------------------------------------------------------------- #
# 数据库写库 / 绑定
# --------------------------------------------------------------------------- #
def _binding_fields(stored):
    try:
        return decrypt_row(stored)
    except (ValueError, UnicodeError, TypeError):
        plain = dict(stored)
        try:
            name = decrypt_blob(stored["license_name"])
            key = repository_key(name)
            for field in ("bind_node_id", "free_nodes"):
                if stored.get(field):
                    plain[field] = decrypt_blob(stored[field], key)
        except (ValueError, UnicodeError, TypeError):
            pass
        return plain


def _unbound_value(stored):
    """bind_node_id 置空后的加密值。"""
    try:
        name = decrypt_blob(stored["license_name"])
    except (ValueError, UnicodeError, TypeError):
        return ""
    return encrypt_blob(b"", repository_key(name))


def _master_id(con, bind_node_id=None):
    if bind_node_id is None:
        nodes = con.execute("select id from nodes where name='local'").fetchall()
    else:
        nodes = con.execute("select id from nodes where id=?", (bind_node_id,)).fetchall()
    if len(nodes) != 1:
        raise ValueError("expected exactly one master node")
    return str(nodes[0]["id"])


def preflight_database(db=XPACK_DB, serial_path=None, bind_node_id=None):
    """只读检查：主节点 id、serial、已绑定证书数量，不改动任何数据。"""
    with sqlite3.connect(database_uri(db), uri=True) as con:
        con.row_factory = sqlite3.Row
        master_id = _master_id(con, bind_node_id)
        rows = [dict(r) for r in con.execute("select * from licenses").fetchall()]
        bound = []
        for raw in rows:
            try:
                plain = _binding_fields(raw)
            except (ValueError, UnicodeError, TypeError):
                plain = {}
            if str(plain.get("bind_node_id") or "") == master_id:
                bound.append(plain.get("license_name", ""))
    serial_path = serial_path or os.path.join(os.path.dirname(db), ".serial")
    serial = None
    if os.path.isfile(serial_path):
        with open(serial_path) as fh:
            serial = fh.read().strip()
    return {"ready": True, "bindNodeID": master_id, "serial": serial,
            "licenseCount": len(rows), "boundLicenses": bound}


def _backup_database(db, backup):
    """写库前备份现有库（首次）。"""
    if os.path.lexists(backup):
        return
    directory = os.path.dirname(os.path.abspath(db))
    fd, temporary = tempfile.mkstemp(prefix=".pre-license-", suffix=".db", dir=directory)
    os.close(fd)
    try:
        with sqlite3.connect(database_uri(db), uri=True) as source:
            with sqlite3.connect(temporary) as dest:
                source.backup(dest)
        with open(temporary, "rb") as fh:
            os.fsync(fh.fileno())
        try:
            os.link(temporary, backup, follow_symlinks=False)
        except FileExistsError:
            pass
    finally:
        os.unlink(temporary)


class _ApplyResult(dict):
    def __init__(self, backup, unbound=0, inserted=0, kept=0):
        super().__init__(backup=backup, unbound=unbound, inserted=inserted, kept=kept)

    def __fspath__(self):
        return self["backup"]

    def __str__(self):
        return self["backup"]


def apply_row(row, db=XPACK_DB, restart=True, bind_node_id=None,
              serial_path=None, prompt_unbind=False):
    """写库 + 绑定主节点；保留全部既有证书，解除主节点的旧绑定。

    ``prompt_unbind`` 为 True 且主节点已绑定时，先在交互终端询问是否解绑。
    """
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    serial_path = serial_path or os.path.join(os.path.dirname(db), ".serial")

    con = sqlite3.connect(database_uri(db, "rw"), uri=True, timeout=30)
    con.row_factory = sqlite3.Row
    backup = db + ".pre-license"
    try:
        con.execute("begin immediate")
        master_id = _master_id(con, bind_node_id)

        # 盘点现有证书；主节点已绑定则先解除绑定（不删除任何行）。
        rows = [dict(r) for r in con.execute("select * from licenses").fetchall()]
        unbound = 0
        for raw in rows:
            try:
                plain = _binding_fields(raw)
            except (ValueError, UnicodeError, TypeError):
                plain = {}
            if str(plain.get("bind_node_id") or "") == master_id:
                if prompt_unbind:
                    answer = input("主节点已绑定证书「%s」，是否先解绑再绑定新证书？[Y/n] "
                                   % plain.get("license_name", "?"))
                    if answer.strip().lower() in ("n", "no", "0"):
                        raise ValueError("existing master binding left in place; "
                                         "unbind it first or re-run without prompt")
                con.execute("update licenses set bind_node_id=? where id=?",
                            (_unbound_value(raw), raw["id"]))
                unbound += 1

        _backup_database(db, backup)

        # 绑定新证书：优先复用同名行（保留既有字段），否则插入新行。
        row = dict(row, bind_node_id=master_id)
        existing = [r for r in rows if _binding_fields(r).get("license_name") == row["license_name"]]
        inserted, kept = 0, 0
        if existing:
            stamp = dt.datetime.now().astimezone().isoformat(" ")
            stored = encrypt_row(dict(row, updated_at=stamp))
            keep_id = existing[0]["id"]
            con.execute("update licenses set %s where id=?" % ",".join(
                '"%s"=?' % k for k in stored), list(stored.values()) + [keep_id])
            kept = 1
        else:
            stamp = dt.datetime.now().astimezone().isoformat(" ")
            stored = encrypt_row(dict(row, updated_at=stamp, created_at=stamp))
            con.execute("insert into licenses (%s) values (%s)" % (
                ",".join(stored), ",".join("?" * len(stored))), list(stored.values()))
            inserted = 1

        # 绑定 serial（不覆盖既有 serial）。
        if os.path.exists(serial_path):
            with open(serial_path) as fh:
                existing_serial = fh.read().strip()
            if existing_serial != row["device_id"]:
                raise ValueError("certificate device ID differs from panel serial")
        else:
            with open(serial_path, "x") as fh:
                fh.write(row["device_id"])
            os.chmod(serial_path, 0o600)

        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

    if restart:
        subprocess.run(["systemctl", "restart", "1panel-core"], check=True)
        subprocess.run(["systemctl", "is-active", "--quiet", "1panel-core"], check=True)
    return _ApplyResult(backup, unbound, inserted, kept)


def verify_database(db=XPACK_DB, serial_path=None, bind_node_id=None):
    """回读校验：主节点有且仅有一条绑定证书，字段与签名内容一致。"""
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    with sqlite3.connect("file:" + db + "?mode=ro", uri=True) as con:
        con.row_factory = sqlite3.Row
        node_id = _master_id(con, bind_node_id)
        matches = []
        for stored in con.execute("select * from licenses"):
            try:
                row = decrypt_row(dict(stored))
            except (ValueError, UnicodeError):
                continue
            if row.get("bind_node_id") == node_id:
                matches.append(row)
    if len(matches) != 1:
        raise ValueError("expected one master-bound license")
    row = matches[0]
    content = decode_license(row["license"])
    expected = row_from_content(content, text=row["license"])
    for field in ("license_name", "usage_name", "assignee_name", "version_constraint",
                  "device_id", "offline", "trial", "issuer", "product_pro",
                  "free_count", "status"):
        if row[field] != expected[field]:
            raise ValueError("database metadata differs from certificate: " + field)
    if row["offline"] != "true" or int(row["product_pro"]) <= int(dt.datetime.now().timestamp()):
        raise ValueError("master-bound license must be offline and unexpired")
    serial_path = serial_path or os.path.join(os.path.dirname(db), ".serial")
    with open(serial_path) as fh:
        if fh.read().strip() != row["device_id"]:
            raise ValueError("certificate device ID differs from panel serial")
    return {
        "licenseName": row["license_name"], "assigneeName": row["assignee_name"],
        "versionConstraint": row["version_constraint"], "status": row["status"],
        "expiresAt": dt.datetime.fromtimestamp(int(row["product_pro"]),
            dt.timezone.utc).isoformat(), "maxNodeCount": int(row["free_count"]),
        "bindNodeID": node_id, "offline": True,
    }


# --------------------------------------------------------------------------- #
def sql_for(row):
    cols = ",".join("`%s`" % c for c in row)
    vals = ",".join("'%s'" % str(v).replace("'", "''") for v in row.values())
    return "insert into licenses (%s) values (%s);\n" % (cols, vals)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edition", choices=sorted(EDITIONS), default="enterprise",
                    help="授权类型：free / pro / enterprise（默认 enterprise 企业版）")
    ap.add_argument("--expires", default="2099-12-31",
                    help="授权期限 YYYY-MM-DD（默认 2099-12-31 永久）")
    ap.add_argument("--nodes", type=int, default=999,
                    help="允许绑定的子节点数量（默认 999）")
    ap.add_argument("--assignee", default="YG", help="被授权人")
    ap.add_argument("--device-id", default=None, help="设备号，默认取 machine-id")
    ap.add_argument("--issuer", default="lxware", help="签发者")
    ap.add_argument("--sms-total", type=int, default=100000, help="短信条数")
    ap.add_argument("--version", default="2.x", help="版本约束")
    ap.add_argument("--trial", action="store_true", help="标记为试用授权")
    ap.add_argument("--offline", action=argparse.BooleanOptionalAction, default=True,
                    help="离线授权（默认开启）")
    ap.add_argument("--out", default=None, help="授权文件输出路径")
    ap.add_argument("--sql", action="store_true", help="打印 licenses 表 SQL")
    ap.add_argument("--apply", action="store_true",
                    help="写入 %s 并重启 1panel-core" % XPACK_DB)
    ap.add_argument("--db", default=XPACK_DB, help="initialized panel database")
    ap.add_argument("--serial-path", default=None, help="panel serial file")
    ap.add_argument("--bind-node-id", type=int, default=None, help="master node ID (auto: local)")
    ap.add_argument("--no-restart", action="store_true", help="caller manages service lifecycle")
    ap.add_argument("--prompt-unbind", action="store_true",
                    help="主节点已绑定时，交互询问是否先解绑（默认自动解绑）")
    ap.add_argument("--verify-db", action="store_true", help="verify master binding and metadata")
    ap.add_argument("--preflight-db", action="store_true", help="read-only license preflight")
    ap.add_argument("--show", metavar="FILE", help="解析并打印已有授权文件")
    ap.add_argument("--import-file", metavar="FILE", dest="import_file",
                    help="导入一份证书文件并绑定主节点")
    a = ap.parse_args()

    if a.preflight_db:
        print(json.dumps(preflight_database(a.db, a.serial_path, a.bind_node_id),
                         ensure_ascii=False))
        return 0

    if a.verify_db:
        print(json.dumps(verify_database(a.db, a.serial_path, a.bind_node_id),
                         indent=2, ensure_ascii=False))
        return 0

    if a.show:
        print(json.dumps(decode_license(open(a.show).read()),
                         indent=2, ensure_ascii=False))
        return 0

    if a.import_file:
        with open(a.import_file) as fh:
            text = fh.read().strip()
        content = decode_license(text)
        row = row_from_content(content, a.device_id, text)
        print("== 导入证书 : %s" % a.import_file)
        print("== 产品版本 : %s" % row["license_name"])
        print("== 授权期限 : %s  -> product_pro=%s" % (
            (content.get("products") or [{}])[0].get("expiresAt", ""), row["product_pro"]))
        print("== 子节点数 : %s" % row["free_count"])
        print("== 授权对象 : %s" % row["assignee_name"])
        if a.sql:
            print("== SQL ==\n%s" % sql_for(encrypt_row(row)))
        if a.apply:
            result = apply_row(row, a.db, not a.no_restart, a.bind_node_id,
                               a.serial_path, a.prompt_unbind)
            print("已写入 %s（备份 %s）；解除旧绑定 %d，插入 %d，复用 %d"
                  % (a.db, result["backup"], result["unbound"],
                     result["inserted"], result["kept"]))
        return 0

    content, row = build(a.edition, a.expires, a.nodes, a.assignee,
                         a.device_id or machine_id(a.serial_path or os.path.join(
                             os.path.dirname(a.db), ".serial")), a.issuer,
                         a.sms_total, a.trial, a.offline, a.version)
    text = encode_license(content)
    row = row_from_content(content, a.device_id, text)

    # 自校验：走一遍面板解析路径
    assert decode_license(text)["products"][0]["maxNodeCount"] == a.nodes
    assert decode_license(text)["products"][0]["expiresAt"].startswith(a.expires)

    print("== 授权类型 : %s (%s)" % (a.edition, EDITIONS[a.edition][1]))
    print("== 授权期限 : %s  -> product_pro=%s" % (a.expires, row["product_pro"]))
    print("== 子节点数 : %s  -> free_count=%s / maxNodeCount=%s"
          % (a.nodes, row["free_count"], content["products"][0]["maxNodeCount"]))
    print("== 设备号   : %s" % row["device_id"])
    print("== 授权文件 :\n%s\n" % text)

    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text + "\n")
        print("已写出 %s" % a.out)
    if a.sql:
        print("== SQL ==\n%s" % sql_for(encrypt_row(row)))
    if a.apply:
        result = apply_row(row, a.db, not a.no_restart, a.bind_node_id,
                           a.serial_path, a.prompt_unbind)
        print("已写入 %s（备份 %s）；解除旧绑定 %d，插入 %d，复用 %d"
              % (a.db, result["backup"], result["unbound"],
                 result["inserted"], result["kept"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
