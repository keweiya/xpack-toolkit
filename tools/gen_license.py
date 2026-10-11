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
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aes128 import cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad  # noqa: E402
from cert_store import database_uri, fingerprint, project_fingerprints  # noqa: E402

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


def _verify_signed_license(text: str, fingerprints) -> dict:
    """Verify a signed payload against established roots, including expired roots."""
    parts = text.strip().split("-")
    if len(parts) != 3:
        raise ValueError("expected 3 segments, got %d" % len(parts))
    try:
        raw = base64.b64decode(parts[0], validate=True)
        sig = base64.b64decode(parts[1], validate=True)
        der = base64.b64decode(parts[2], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("base64 decode failed: %s" % exc)

    if hashlib.sha256(der).hexdigest() not in fingerprints:
        raise ValueError("certificate root lacks established project ownership")

    with tempfile.TemporaryDirectory() as td:
        sigf = os.path.join(td, "sig.bin")
        rawf = os.path.join(td, "content.bin")
        pubf = os.path.join(td, "pub.pem")
        with open(sigf, "wb") as fh:
            fh.write(sig)
        with open(rawf, "wb") as fh:
            fh.write(raw)
        with open(pubf, "w") as fh:
            cert = subprocess.run(["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"],
                                  input=der, capture_output=True)
            if cert.returncode:
                raise ValueError("invalid embedded signing certificate")
            fh.write(cert.stdout.decode())
        rsa = subprocess.run(["openssl", "rsa", "-pubin", "-in", pubf, "-noout"],
                             capture_output=True)
        if rsa.returncode:
            raise ValueError("embedded signing certificate requires an RSA key")
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pubf,
                            "-signature", sigf, rawf], capture_output=True)
    if r.returncode != 0:
        raise ValueError("signature verification failed")
    try:
        content = json.loads(raw.decode())
        if not isinstance(content, dict):
            raise ValueError("license content must be an object")
        return content
    except Exception as exc:  # noqa: BLE001
        raise ValueError("content is not valid json: %s" % exc)


def verify_license(text: str) -> dict:
    """Verify issuance against the current signing root, independently of expiry."""
    with open(SIGN_CRT) as fh:
        fp = fingerprint(fh.read())
    return _verify_signed_license(text, {fp})


def _known_roots(replace_root_fingerprints=()):
    current = None
    if os.path.isfile(SIGN_CRT):
        with open(SIGN_CRT) as fh:
            current = fingerprint(fh.read())
    return project_fingerprints(current, replace_root_fingerprints)


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
        value = decrypt_blob(value, LICENSE_KEY)
    except (ValueError, UnicodeError, TypeError):
        pass
    if not isinstance(value, str):
        return False
    try:
        content = _verify_signed_license(value, fingerprints)
        if any(not isinstance(content.get(field), str) or not content[field]
               for field in ("licenseName", "deviceID", "license")):
            return False
        row_from_content(content, text=value)
        return True
    except (ValueError, UnicodeError, TypeError, AttributeError, KeyError,
            OSError, subprocess.SubprocessError):
        return False


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


def _database_scope(con, fingerprints, bind_node_id=None, preserve_foreign=False,
                    replace_foreign=False):
    if replace_foreign and not preserve_foreign:
        raise ValueError("foreign replacement requires --preserve-foreign")
    if bind_node_id is None:
        nodes = con.execute("select id from nodes where name='local'").fetchall()
    else:
        nodes = con.execute("select id from nodes where id=?", (bind_node_id,)).fetchall()
    if len(nodes) != 1:
        raise ValueError("expected exactly one master node")
    master_id = str(nodes[0]["id"])
    scoped = []
    for raw in con.execute("select * from licenses").fetchall():
        stored = dict(raw)
        plain = _binding_fields(stored)
        owned = _owned_license(stored, fingerprints)
        bound = str(plain.get("bind_node_id") or "")
        if bound == master_id and not owned and not preserve_foreign:
            raise ValueError("master already bound to a different issuer's license")
        scoped.append((stored, plain, owned, bound))
    return master_id, scoped


def preflight_database(db=XPACK_DB, serial_path=None, bind_node_id=None,
                       replace_root_fingerprints=(), preserve_foreign=False,
                       replace_foreign=False):
    """Check master ownership without exporting, signing or changing any file."""
    fingerprints = _known_roots(replace_root_fingerprints)
    with sqlite3.connect(database_uri(db), uri=True) as con:
        con.row_factory = sqlite3.Row
        master_id, scoped = _database_scope(con, fingerprints, bind_node_id, preserve_foreign,
                                            replace_foreign)
    serial_path = serial_path or os.path.join(os.path.dirname(db), ".serial")
    serial = None
    if os.path.isfile(serial_path):
        with open(serial_path) as fh:
            serial = fh.read().strip()
    return {"ready": True, "bindNodeID": master_id, "serial": serial,
            "ownedLicenseCount": sum(owned for _, _, owned, _ in scoped),
            "foreignLicenseCount": sum(not owned for _, _, owned, _ in scoped)}


def _publish_snapshot(directory, name, payload):
    """Publish a complete, private archive without following or replacing a target."""
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".foreign-licenses-%s.tmp" % secrets.token_hex(16)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(fd, "wb") as fh:
                os.fchmod(fh.fileno(), 0o600)
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(temporary, name, src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd, follow_symlinks=False)
            except FileExistsError:
                existing_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                      dir_fd=directory_fd)
                with os.fdopen(existing_fd, "rb") as fh:
                    info = os.fstat(fh.fileno())
                    if (not stat.S_ISREG(info.st_mode) or
                            stat.S_IMODE(info.st_mode) != 0o600 or fh.read() != payload):
                        raise ValueError("foreign license archive target differs from snapshot")
                    os.fsync(fh.fileno())
            os.fsync(directory_fd)
        finally:
            os.unlink(temporary, dir_fd=directory_fd)
            os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return os.path.join(directory, name)


def _archive_foreign_licenses(con, db, master_id, scoped, foreign_backup_dir=None,
                              all_foreign=False):
    """Capture all foreign raw rows under the same writer lock as the migration.

    ``all_foreign`` widens the trigger from "a foreign row is bound to master" to
    "any foreign row exists", so replacement and drop never delete a row that was
    not archived first. The archive always holds every foreign raw row.
    """
    if not any(not owned and (all_foreign or bound == master_id)
               for _, _, owned, bound in scoped):
        return None
    archive = {
        "schema": 1, "name": "xpack-toolkit-foreign-licenses",
        "database": os.path.abspath(db), "master": master_id,
        "columns": [r[1] for r in con.execute("pragma table_info(licenses)")],
        "rows": [stored for stored, _, owned, _ in scoped if not owned],
    }
    archive["rows"].sort(key=lambda row: row["id"])
    payload = (json.dumps(archive, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                          default=lambda value: {"$base64": base64.b64encode(value).decode()})
               + "\n").encode("ascii")
    name = "foreign-licenses.%s.json" % hashlib.sha256(payload).hexdigest()
    directory = os.path.abspath(foreign_backup_dir or os.path.dirname(db) or ".")
    return _publish_snapshot(directory, name, payload)


def _backup_database(db, backup):
    """Keep an existing baseline untouched and publish a consistent new one once."""
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
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.unlink(temporary)


def _unbound_foreign_value(stored):
    try:
        name = decrypt_blob(stored["license_name"])
    except (ValueError, UnicodeError, TypeError):
        return ""
    # The repository expects encrypted metadata whenever the stored name decrypts.
    return encrypt_blob(b"", repository_key(name))


def _validated_project_row(row):
    content = verify_license(row["license"])
    if any(not isinstance(content.get(field), str) or not content[field]
           for field in ("licenseName", "deviceID", "license")):
        raise ValueError("signed certificate requires license name, device ID and license")
    row = row_from_content(content, text=row["license"])
    if not row["device_id"] or int(row["free_count"]) < 1:
        raise ValueError("missing device ID or invalid node allowance")
    if content.get("offline") is not True:
        raise ValueError("local import requires a signed offline certificate")
    if int(row["product_pro"]) <= int(dt.datetime.now(dt.timezone.utc).timestamp()):
        raise ValueError("certificate has expired")
    return row


def _check_serial(serial_path, device_id):
    if os.path.exists(serial_path):
        with open(serial_path) as fh:
            if fh.read().strip() != device_id:
                raise ValueError("certificate device ID differs from panel serial")


def archive_foreign_database(row, db=XPACK_DB, bind_node_id=None, serial_path=None,
                            replace_root_fingerprints=(), preserve_foreign=False,
                            foreign_backup_dir=None, replace_foreign=False):
    """Archive before component replacement, without changing any database row."""
    if replace_foreign and not preserve_foreign:
        raise ValueError("foreign replacement requires --preserve-foreign")
    if not preserve_foreign:
        raise ValueError("foreign archival requires --preserve-foreign")
    row = _validated_project_row(row)
    serial_path = serial_path or os.path.join(os.path.dirname(db), ".serial")
    fingerprints = _known_roots(replace_root_fingerprints)
    with sqlite3.connect(database_uri(db), uri=True) as con:
        con.row_factory = sqlite3.Row
        con.execute("begin")
        master_id, scoped = _database_scope(con, fingerprints, bind_node_id, True,
                                            replace_foreign)
        _check_serial(serial_path, row["device_id"])
        archive = _archive_foreign_licenses(con, db, master_id, scoped, foreign_backup_dir,
                                            replace_foreign)
    return {"ready": True, "bindNodeID": master_id, "archive": archive,
            "foreignLicenseCount": sum(not owned for _, _, owned, _ in scoped)}


class _ApplyResult(dict):
    """apply_row() outcome: a dict of paths that still behaves like the backup path.

    ``backup`` is always present, ``archive`` is added when a foreign-license
    archive was written and ``dropped`` when the replacement action deleted
    foreign rows. ``os.fspath()``/``str()`` keep returning the backup path so
    callers that treated the historical return value as a path are unaffected.
    """

    def __init__(self, backup, archive=None, dropped=None):
        super().__init__(backup=backup)
        if archive is not None:
            self["archive"] = archive
        if dropped is not None:
            self["dropped"] = dropped

    def __fspath__(self):
        return self["backup"]

    def __str__(self):
        return self["backup"]

    def __format__(self, spec):
        return format(self["backup"], spec)

    def __eq__(self, other):
        if isinstance(other, (str, os.PathLike)):
            return self["backup"] == os.fspath(other)
        return dict.__eq__(self, other)

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


def drop_foreign_database(db=XPACK_DB, bind_node_id=None, serial_path=None,
                          replace_root_fingerprints=(), foreign_backup_dir=None):
    """Archive and delete every foreign license row without any project license.

    Standalone replacement action: it never creates or imports a license row, so
    it needs neither a private key nor a license file. ``serial_path`` is accepted
    for symmetry with the other actions; dropping never reads the panel serial.
    """
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    fingerprints = _known_roots(replace_root_fingerprints)
    con = sqlite3.connect(database_uri(db, "rw"), uri=True, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        con.execute("begin immediate")
        master_id, scoped = _database_scope(con, fingerprints, bind_node_id, True)
        foreign_ids = [stored["id"] for stored, _, owned, _ in scoped if not owned]
        archive = None
        if foreign_ids:
            archive = _archive_foreign_licenses(con, db, master_id, scoped,
                                                foreign_backup_dir, True)
            for row_id in foreign_ids:
                con.execute("delete from licenses where id=?", (row_id,))
            con.commit()
        else:
            # No foreign row: release the write lock without touching the database.
            con.rollback()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    return {"ready": True, "bindNodeID": master_id, "archive": archive,
            "foreignLicenseCount": len(foreign_ids), "dropped": len(foreign_ids)}


def apply_row(row, db=XPACK_DB, restart=True, bind_node_id=None,
              serial_path=None, replace_root_fingerprints=(), preserve_foreign=False,
              foreign_backup_dir=None, replace_foreign=False):
    if replace_foreign and not preserve_foreign:
        raise ValueError("foreign replacement requires --preserve-foreign")
    row = _validated_project_row(row)
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    serial_path = serial_path or os.path.join(os.path.dirname(db), ".serial")
    fingerprints = _known_roots(replace_root_fingerprints)
    preflight_database(db, serial_path, bind_node_id, replace_root_fingerprints,
                       preserve_foreign, replace_foreign)
    con = sqlite3.connect(database_uri(db, "rw"), uri=True, timeout=30)
    con.row_factory = sqlite3.Row
    backup = db + ".pre-license"
    archive = None
    dropped = None
    try:
        con.execute("begin immediate")
        master_id, scoped = _database_scope(con, fingerprints, bind_node_id,
                                            preserve_foreign, replace_foreign)
        _check_serial(serial_path, row["device_id"])
        if preserve_foreign:
            archive = _archive_foreign_licenses(con, db, master_id, scoped,
                                                foreign_backup_dir, replace_foreign)
        _backup_database(db, backup)
        if replace_foreign:
            dropped = 0
            for foreign, _, owned, _bound in scoped:
                if not owned:
                    con.execute("delete from licenses where id=?", (foreign["id"],))
                    dropped += 1
        else:
            for foreign, _, owned, bound in scoped:
                if not owned and bound == master_id:
                    con.execute("update licenses set bind_node_id=? where id=?",
                                (_unbound_foreign_value(foreign), foreign["id"]))
        row = dict(row, bind_node_id=master_id)
        replace_ids, keep_id = [], None
        for stored, plain, owned, bound in scoped:
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
    return _ApplyResult(backup, archive, dropped)


def existing_license(db=XPACK_DB):
    """Read back an existing signed certificate without trusting display fields."""
    if not os.path.isfile(db):
        raise ValueError("missing initialized database: %s" % db)
    matches = set()
    with sqlite3.connect(database_uri(db), uri=True) as con:
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
        raise ValueError("expected one valid project offline certificate; awaiting LICENSE_FILE import or a local signing key")
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
    ap.add_argument("--preflight-db", action="store_true", help="read-only master license ownership preflight")
    ap.add_argument("--export-existing", metavar="FILE", help="export one existing verified certificate without a signing key")
    ap.add_argument("--replace-root-fingerprint", action="append", default=[],
                    help="previous script CA fingerprint to replace during rotation")
    ap.add_argument("--preserve-foreign", action="store_true",
                    help="archive foreign licenses and release only their master binding")
    ap.add_argument("--replace-foreign", action="store_true",
                    help="with --preserve-foreign, archive and then delete every foreign row "
                         "instead of releasing only its master binding")
    ap.add_argument("--foreign-backup-dir", default=None,
                    help="foreign raw-license archive directory (apply only; default: database parent)")
    ap.add_argument("--archive-foreign", action="store_true",
                    help="archive foreign rows before install; requires --preserve-foreign --import-file")
    ap.add_argument("--drop-foreign-licenses", action="store_true",
                    help="archive and delete every foreign row without a license file; "
                         "requires --preserve-foreign")
    ap.add_argument("--serial", action="store_true",
                    help="with --apply, create serial if missing (never replace existing)")
    ap.add_argument("--show", metavar="FILE", help="解析并打印已有授权文件")
    ap.add_argument("--import-file", metavar="FILE", dest="import_file",
                    help="verify signed file -> encrypted local import -> bind master")
    a = ap.parse_args()
    if a.serial and not a.apply:
        ap.error("--serial requires --apply")
    if a.replace_foreign and not a.preserve_foreign:
        ap.error("--replace-foreign requires --preserve-foreign")
    if a.archive_foreign:
        if not a.preserve_foreign or not a.import_file:
            ap.error("--archive-foreign requires --preserve-foreign --import-file")
        with open(a.import_file) as fh:
            row = {"license": fh.read().strip()}
        print(json.dumps(archive_foreign_database(row, a.db, a.bind_node_id,
                                                 a.serial_path, a.replace_root_fingerprint,
                                                 True, a.foreign_backup_dir,
                                                 a.replace_foreign)))
        return 0
    if a.drop_foreign_licenses:
        if not a.preserve_foreign:
            ap.error("--drop-foreign-licenses requires --preserve-foreign")
        print(json.dumps(drop_foreign_database(a.db, a.bind_node_id, a.serial_path,
                                               a.replace_root_fingerprint,
                                               a.foreign_backup_dir)))
        return 0
    if a.preflight_db:
        print(json.dumps(preflight_database(a.db, a.serial_path, a.bind_node_id,
                                           a.replace_root_fingerprint, a.preserve_foreign,
                                           a.replace_foreign)))
        return 0
    if a.export_existing:
        try:
            text = existing_license(a.db)
        except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
            print("Project certificate export failed: %s" % exc, file=sys.stderr)
            return 1
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
            result = apply_row(row, a.db, not a.no_restart, a.bind_node_id,
                               a.serial_path, a.replace_root_fingerprint,
                               a.preserve_foreign, a.foreign_backup_dir, a.replace_foreign)
            print("已写入 %s（备份 %s）；主节点已绑定" % (a.db, result["backup"]))
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
        result = apply_row(row, a.db, not a.no_restart, a.bind_node_id,
                           a.serial_path, a.replace_root_fingerprint,
                           a.preserve_foreign, a.foreign_backup_dir, a.replace_foreign)
        print("已写入 %s（备份 %s）；主节点已绑定" % (a.db, result["backup"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
