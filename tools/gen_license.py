#!/usr/bin/env python3
"""1Panel 授权证书（license certificate）生成器 —— 自选授权期限与子节点数量。

逆向结论（1panel-core v2.3.2）
------------------------------
授权文件 = `<base64(JSON)>-<seg2>-<seg3>`，用 `-` 切分后至少 3 段。
解析器 `xpack/app/service.getLicenseContent` @ 0x01422640：

    parts := strings.genSplit(content, "-", 0, -1)   // 分隔符 1 字节 0x2d
    if len(parts) < 3 { return ErrLicense }          // cmp rbx,3 ; jge ok
    raw, err := base64.StdEncoding.DecodeString(parts[0])
    json.Unmarshal(raw, &LicenseContent)
    v, ok := Content.Annotations["lxware.cn/username"]
    ... LoadProductStr(v)                            // "Free" / "Bound"

LicenseContent（struct size 0xb8，type vaddr 0x18b55a0）字段与 json tag：

    licenseName        string            json:"licenseName"
    usageName          string            json:"usageName"
    assigneeName       string            json:"assigneeName"
    versionConstraint  string            json:"versionConstraint"
    deviceID           string            json:"deviceID"
    license            string            json:"license"
    trial              bool              json:"trial"
    offline            bool              json:"offline"
    timerDiff          string            json:"timerDiff"
    issuer             string            json:"issuer"
    products           []LicenseProduct  json:"products"
    annotations        map[string]string json:"annotations,omitempty"
    smsTotal           int               json:"smsTotal"
    smsUsed            int               json:"smsUsed"

LicenseProduct（struct size 0x40，type vaddr 0x183f880）：

    name               string     json:"name"
    expiresAt          time.Time  json:"expiresAt"        <- 授权期限
    maxNodeCount       int        json:"maxNodeCount"     <- 子节点数量
    versionConstraint  string     json:"versionConstraint"

`xpack.db` 的 `licenses` 表列（与 LicenseContent 一一对应，另有绑定信息）：

    license_name usage_name assignee_name version_constraint device_id license
    offline trial issuer product_pro last_sync_at sms_total sms_used
    bind_node_id free_count free_nodes status message

    product_pro 是 Unix 秒字符串，前端用 `Date.now()/1e3` 比较；面板里看到的就是它。
    free_count  是"可绑定节点数"，`CheckLicenseStatus` 里 `currentBind < freeCount` 才放行。

用法
----
  # 生成一份 2035-12-31 到期、允许 200 个子节点的专业版授权文件
  python3 tools/gen_license.py --expires 2035-12-31 --nodes 200 \\
      --assignee YG --device-id $(cat /etc/machine-id) --out license.txt

  # 同时输出 xpack.db 可直接执行的 SQL
  python3 tools/gen_license.py --expires 2035-12-31 --nodes 200 --sql

  # 直接写入运行中的面板（需要 root，会重启 1panel-core）
  python3 tools/gen_license.py --expires 2035-12-31 --nodes 200 --apply

  # 只解析已有的授权文件，打印内容
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
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aes128 import cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad  # noqa: E402

LICENSE_KEY = b"nel1Pa2520pack@x"
XPACK_DB = "/opt/1panel/db/xpack.db"
SERIAL = "/opt/1panel/db/.serial"

# LicenseRepo uses a static key for name/file, name+salt for ordinary text,
# and name+date for status (the last encrypted field in LicenseRepo.encrypt).
STATIC_FIELDS = {"license_name", "license"}
TEXT_FIELDS = (
    "license_name", "usage_name", "assignee_name", "version_constraint",
    "device_id", "license", "offline", "trial", "issuer", "product_pro",
    "last_sync_at", "bind_node_id", "free_count", "free_nodes", "status", "message",
)

# 面板内置的授权类型（middleware / license_helper 里出现的状态串）
EDITIONS = {
    "free": ("Free", "1Panel Free", 0),
    "pro": ("Bound", "1Panel Professional", 0),
    "enterprise": ("Bound", "1Panel Enterprise", 0),
}


# --------------------------------------------------------------------------- #
# 授权文件编解码
# --------------------------------------------------------------------------- #
# 本地签名材料：授权文件第 2 段 = RSA-SHA256 签名，第 3 段 = 签名证书链
# （形状与官方签发站一致：base64(内容)-base64(签名)-base64(证书)）
STATE_DIR = os.environ.get("STATE") or next((p for p in
    (os.path.join(ROOT, "web", "state"), os.path.join(ROOT, "state"))
    if os.path.isfile(os.path.join(p, "license.crt"))), os.path.join(ROOT, "state"))
SIGN_KEY = os.environ.get("SIGN_KEY", os.path.join(STATE_DIR, "license.key"))
SIGN_CRT = os.environ.get("SIGN_CRT", os.path.join(STATE_DIR, "license.crt"))


def sign_payload(raw: bytes) -> str:
    """对「第 1 段解码后的内容字节」做 RSA-SHA256 签名，返回 base64。

    面板的 license_helper.CheckInLocal 校验的是
        rsa.VerifyPKCS1v15(leafPub, SHA256, sha256(base64decode(seg1)), base64decode(seg2))
    也就是签名对象是**解码后的 JSON 字节**，不是第 1 段那串 base64 文本。
    """
    try:
        out = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", SIGN_KEY],
            input=raw, capture_output=True, check=True).stdout
        return base64.b64encode(out).decode()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("RSA signing failed: %s" % exc) from exc


def cert_chain() -> str:
    """签名证书（DER）的 base64，作为第 3 段。"""
    try:
        with open(SIGN_CRT) as fh:
            pem = fh.read()
        der = ssl.PEM_cert_to_DER_cert(pem)
        return base64.b64encode(der).decode()
    except (OSError, ValueError) as exc:
        raise ValueError("signing certificate failed: %s" % exc) from exc


def encode_license(content: dict, extra_segments=None) -> str:
    """打包成面板认识的三段式授权文件（完整内容：内容 + 签名 + 证书链）。"""
    raw = json.dumps(content, ensure_ascii=False, separators=(",", ":")).encode()
    payload = base64.b64encode(raw).decode()
    segs = tuple(extra_segments) if extra_segments else (sign_payload(raw), cert_chain())
    return "-".join((payload,) + segs)


def decode_license(text: str) -> dict:
    """按 getLicenseContent 的逻辑解析授权文件。"""
    text = text.strip()
    parts = text.split("-")
    if len(parts) < 3:
        raise ValueError("授权文件至少需要 3 段（用 '-' 分隔），当前 %d 段" % len(parts))
    raw = base64.b64decode(parts[0], validate=False)
    return json.loads(raw.decode())


def encrypt_blob(plain: bytes, key: bytes = LICENSE_KEY) -> str:
    """LicenseRepo.encrypt：base64(iv[16] || AES-128-CBC-PKCS7(plain, key[:16]))。"""
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


# --------------------------------------------------------------------------- #
# 服务端校验（授权服务器 /api/v1/licenses/report 用）
#
# 与面板 license_helper.CheckInLocal 完全一致的校验链：
#   1) 第 3 段必须是本站根证书（sha256(cert.Raw) == 本站根证书指纹）
#   2) rsa.VerifyPKCS1v15(叶子公钥, SHA256, sha256(第 1 段解码字节), 第 2 段签名)
# --------------------------------------------------------------------------- #
def public_pem() -> str:
    """本站根证书的公钥 PEM。"""
    out = subprocess.run(["openssl", "x509", "-in", SIGN_CRT, "-pubkey", "-noout"],
                         capture_output=True, check=True).stdout
    return out.decode()


def sign_response(message: bytes) -> str:
    """远端响应签名：base64(RSA-SHA256(message))，放进 X-License-Signature-V2。

    面板 license_helper.handleRequest 校验响应时构造的消息是
        fmt.Sprintf("%s\\n%s\\n%s", 请求头 X-License-Timestamp,
                                  请求头 X-License-Nonce,
                                  响应体)
    然后用授权文件第 3 段证书的公钥 + 内置根证书指纹验签（checkResp ->
    CheckInLocal(parts, host, offline=true, msg, sig)）。
    """
    out = subprocess.run(["openssl", "dgst", "-sha256", "-sign", SIGN_KEY],
                         input=message, capture_output=True, check=True).stdout
    return base64.b64encode(out).decode()


def verify_license(text: str) -> dict:
    """校验授权文件；通过返回内容 dict，失败抛 ValueError。"""
    parts = text.strip().split("-")
    if len(parts) != 3:
        raise ValueError("expected 3 segments, got %d" % len(parts))
    try:
        raw = base64.b64decode(parts[0], validate=True)
        sig = base64.b64decode(parts[1], validate=True)
        der = base64.b64decode(parts[2], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("base64 decode failed: %s" % exc)

    with open(SIGN_CRT) as fh:
        root_der = ssl.PEM_cert_to_DER_cert(fh.read())
    if hashlib.sha256(der).digest() != hashlib.sha256(root_der).digest():
        raise ValueError("leaf certificate is not issued by this site")

    with tempfile.TemporaryDirectory() as td:
        sigf = os.path.join(td, "sig.bin")
        rawf = os.path.join(td, "content.bin")
        pubf = os.path.join(td, "pub.pem")
        with open(sigf, "wb") as fh:
            fh.write(sig)
        with open(rawf, "wb") as fh:
            fh.write(raw)
        with open(pubf, "w") as fh:
            fh.write(public_pem())
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pubf,
                            "-signature", sigf, rawf], capture_output=True)
    if r.returncode != 0:
        raise ValueError("signature verification failed")
    try:
        return json.loads(raw.decode())
    except Exception as exc:  # noqa: BLE001
        raise ValueError("content is not valid json: %s" % exc)


def machine_id(path=SERIAL):
    if os.path.exists(path):
        return open(path).read().strip()
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(p):
            return open(p).read().strip()
    return "0" * 32


# --------------------------------------------------------------------------- #
# 证书构造
# --------------------------------------------------------------------------- #
def build(edition, expires, nodes, assignee, device_id, issuer,
          sms_total, trial, offline, version):
    status, _product, _ = EDITIONS[edition]
    exp = dt.datetime.strptime(expires, "%Y-%m-%d").replace(
        tzinfo=dt.timezone.utc)
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


def sql_for(row):
    cols = ",".join("`%s`" % c for c in row)
    vals = ",".join("'%s'" % str(v).replace("'", "''") for v in row.values())
    return "insert into licenses (%s) values (%s);\n" % (cols, vals)


def row_from_content(content, device_id=None, text=""):
    """把一份已签发的证书还原成 licenses 表的一行（导入用）。"""
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
        "license_name": content.get("licenseName") or "1Panel Professional",
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


def _owned_license(stored, fingerprints):
    value = stored.get("license") or ""
    try:
        value = decrypt_blob(value)
    except (ValueError, UnicodeError):
        pass
    parts = value.strip().split("-")
    if len(parts) == 3:
        try:
            der = base64.b64decode(parts[2], validate=True)
            return hashlib.sha256(der).hexdigest() in fingerprints
        except ValueError:
            return False
    # Migrate only the deterministic JSON-only rows produced by the old script.
    try:
        content = json.loads(value)
        exp = content["products"][0]["expiresAt"]
        nodes = content["products"][0]["maxNodeCount"]
        serial = "1P-" + hashlib.sha256(("%s|%s|%s" % (
            content["assigneeName"], exp, nodes)).encode()).hexdigest()[:24].upper()
        return content.get("licenseName") in ("1Panel Professional", "1Panel Enterprise") \
            and content.get("license") == serial
    except (ValueError, KeyError, TypeError, IndexError):
        return False


def apply_row(row, db=XPACK_DB, restart=True, bind_node_id=None,
              serial_path=None, replace_root_fingerprints=()):
    content = verify_license(row["license"])
    row = row_from_content(content, text=row["license"])
    if not row["device_id"] or int(row["free_count"]) < 1:
        raise ValueError("missing device ID or invalid node allowance")
    if content.get("offline") is not True:
        raise ValueError("local import requires a signed offline certificate")
    if int(row["product_pro"]) <= int(dt.datetime.now(dt.timezone.utc).timestamp()):
        raise ValueError("certificate has expired")
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    serial_path = serial_path or os.path.join(os.path.dirname(db), ".serial")
    with open(SIGN_CRT) as fh:
        fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(fh.read())).hexdigest()
    fingerprints = set(replace_root_fingerprints) | {fp}
    con = sqlite3.connect(db, timeout=30)
    con.row_factory = sqlite3.Row
    backup = db + ".pre-license"
    try:
        if not os.path.exists(backup):
            with sqlite3.connect(backup) as dest:
                con.backup(dest)
            os.chmod(backup, 0o600)
        con.execute("begin immediate")
        if bind_node_id is None:
            nodes = con.execute("select id from nodes where name='local'").fetchall()
        else:
            nodes = con.execute("select id from nodes where id=?", (bind_node_id,)).fetchall()
        if len(nodes) != 1:
            raise ValueError("expected exactly one master node")
        master_id = str(nodes[0]["id"])
        row = dict(row, bind_node_id=master_id)
        replace_ids, keep_id = [], None
        for stored in con.execute("select * from licenses").fetchall():
            stored = dict(stored)
            try:
                plain = decrypt_row(stored)
            except (ValueError, UnicodeError):
                plain = dict(stored)
                try:
                    name = decrypt_blob(stored["license_name"])
                    key = repository_key(name)
                    for field in ("bind_node_id", "free_nodes"):
                        if stored.get(field):
                            plain[field] = decrypt_blob(stored[field], key)
                except (ValueError, UnicodeError):
                    pass
            owned = _owned_license(stored, fingerprints)
            bound = str(plain.get("bind_node_id") or "")
            if bound == master_id and not owned:
                raise ValueError("master already bound to a different issuer's license")
            if owned and bound in ("", "0", master_id):
                if bound == master_id and keep_id is None:
                    keep_id = stored["id"]
                    row["free_nodes"] = plain.get("free_nodes") or "[]"
                else:
                    replace_ids.append(stored["id"])
        for old_id in replace_ids:
            con.execute("delete from licenses where id=?", (old_id,))
        stamp = dt.datetime.now().astimezone().isoformat(" ")
        stored = encrypt_row(dict(row, updated_at=stamp))
        if keep_id is not None:
            con.execute("update licenses set %s where id=?" % ",".join(
                '"%s"=?' % k for k in stored), list(stored.values()) + [keep_id])
        else:
            stored["created_at"] = stamp
            con.execute("insert into licenses (%s) values (%s)" % (
                ",".join(stored), ",".join("?" * len(stored))), list(stored.values()))
        assert decrypt_row(stored)["license"] == row["license"]
        if os.path.exists(serial_path):
            with open(serial_path) as fh:
                existing = fh.read().strip()
            if existing != row["device_id"]:
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
    return backup


def existing_license(db=XPACK_DB):
    """Read back an existing signed certificate without trusting display fields."""
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    matches = set()
    with sqlite3.connect("file:" + db + "?mode=ro", uri=True) as con:
        for (stored,) in con.execute("select license from licenses"):
            if not stored:
                continue
            candidates = [stored]
            try:
                candidates.append(decrypt_blob(stored, LICENSE_KEY))
            except (ValueError, UnicodeError):
                pass
            for text in candidates:
                try:
                    content = verify_license(text)
                    row = row_from_content(content, text=text)
                    if row["offline"] == "true" and row["device_id"] and int(row["free_count"]) >= 1:
                        if int(row["product_pro"]) > int(dt.datetime.now().timestamp()):
                            matches.add(text.strip())
                except (ValueError, UnicodeError, KeyError, TypeError, subprocess.CalledProcessError):
                    continue
    if len(matches) != 1:
        raise ValueError("expected one valid existing offline certificate; provide LICENSE_FILE or a local signing key")
    return matches.pop()


def verify_database(db=XPACK_DB, serial_path=None, bind_node_id=None):
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    with sqlite3.connect("file:" + db + "?mode=ro", uri=True) as con:
        con.row_factory = sqlite3.Row
        if bind_node_id is None:
            nodes = con.execute("select id,name from nodes where name='local'").fetchall()
        else:
            nodes = con.execute("select id,name from nodes where id=?", (bind_node_id,)).fetchall()
        if len(nodes) != 1:
            raise ValueError("expected exactly one master node")
        node = dict(nodes[0])
        matches = []
        for stored in con.execute("select * from licenses"):
            try:
                row = decrypt_row(dict(stored))
            except (ValueError, UnicodeError):
                continue
            if row.get("bind_node_id") == str(node["id"]):
                matches.append(row)
    if len(matches) != 1:
        raise ValueError("expected one encrypted master-bound license")
    row = matches[0]
    content = verify_license(row["license"])
    expected = row_from_content(content, text=row["license"])
    for field in ("license_name", "usage_name", "assignee_name", "version_constraint",
                  "device_id", "license", "offline", "trial", "issuer", "product_pro",
                  "free_count", "status"):
        if row[field] != expected[field]:
            raise ValueError("database metadata differs from signed certificate: " + field)
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
        "bindNodeID": node["id"], "bindNodeName": node["name"],
        "offline": True, "signatureVerified": True,
    }


# --------------------------------------------------------------------------- #
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
    ap.add_argument("--version", default="2.x",
                    help="版本约束，面板只认 all / 1.x / 2.x（license_helper.CheckVersion）")
    ap.add_argument("--trial", action="store_true", help="标记为试用授权")
    ap.add_argument("--offline", action=argparse.BooleanOptionalAction, default=True,
                    help="离线授权（默认开启，永久版不回连校验；用 --no-offline 关闭）")
    ap.add_argument("--out", default=None, help="授权文件输出路径")
    ap.add_argument("--sql", action="store_true", help="打印 licenses 表 SQL")
    ap.add_argument("--apply", action="store_true",
                    help="写入 %s 并重启 1panel-core" % XPACK_DB)
    ap.add_argument("--db", default=XPACK_DB, help="initialized panel database")
    ap.add_argument("--serial-path", default=None, help="panel serial file")
    ap.add_argument("--bind-node-id", type=int, default=None, help="master node ID (auto: local)")
    ap.add_argument("--no-restart", action="store_true", help="caller manages service lifecycle")
    ap.add_argument("--verify-db", action="store_true", help="verify master binding and encrypted display metadata")
    ap.add_argument("--export-existing", metavar="FILE", help="export one existing verified certificate without a signing key")
    ap.add_argument("--replace-root-fingerprint", action="append", default=[],
                    help="previous script CA fingerprint to replace during rotation")
    ap.add_argument("--serial", action="store_true",
                    help="with --apply, create serial if missing (never replace existing)")
    ap.add_argument("--show", metavar="FILE", help="解析并打印已有授权文件")
    ap.add_argument("--import-file", metavar="FILE", dest="import_file",
                    help="verify signed file -> encrypted local import -> bind master")
    a = ap.parse_args()
    if a.serial and not a.apply:
        ap.error("--serial requires --apply")
    if a.export_existing:
        text = existing_license(a.db)
        fd = os.open(a.export_existing, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text + "\n")
        print("Existing signed certificate exported: " + a.export_existing)
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
        content = verify_license(text)
        row = row_from_content(content, a.device_id, text)
        pro = (content.get("products") or [{}])[0]
        print("== 导入证书 : %s" % a.import_file)
        print("== 产品版本 : %s" % row["license_name"])
        print("== 授权期限 : %s  -> product_pro=%s"
              % (pro.get("expiresAt", ""), row["product_pro"]))
        print("== 子节点数 : %s" % row["free_count"])
        print("== 授权对象 : %s" % row["assignee_name"])
        if a.sql:
            print("== SQL ==\n%s" % sql_for(encrypt_row(row)))
        if a.apply:
            backup = apply_row(row, a.db, not a.no_restart, a.bind_node_id,
                               a.serial_path, a.replace_root_fingerprint)
            print("已写入 %s（备份 %s）；主节点已绑定" % (a.db, backup))
        return 0

    content, row = build(a.edition, a.expires, a.nodes, a.assignee,
                         a.device_id or machine_id(a.serial_path or os.path.join(
                             os.path.dirname(a.db), ".serial")), a.issuer,
                         a.sms_total, a.trial, a.offline, a.version)
    text = encode_license(content)
    verify_license(text)
    row = row_from_content(content, a.device_id, text)

    # 自校验：走一遍面板的解析路径
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
        backup = apply_row(row, a.db, not a.no_restart, a.bind_node_id,
                           a.serial_path, a.replace_root_fingerprint)
        print("已写入 %s（备份 %s）；主节点已绑定" % (a.db, backup))
    return 0


if __name__ == "__main__":
    sys.exit(main())
