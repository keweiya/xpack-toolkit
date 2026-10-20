#!/usr/bin/env python3
"""把「本站根证书」写进面板的 core_settings，让官方校验真实通过。

背景（逆向自 1panel-core v2.3.2，v2.4.0 复核一致）
--------------------------------
面板导入许可证时走 license_helper.CheckInLocal：

    loadRootCertFromStore(host)   从 core_settings 读 LicenseRootCertHK / LicenseRootCertCN
    decryptRootCertStoreValue     用固定盐 "nel1Pa2520pack@x" 做 AES-128-CBC 解密
    checkRootCertFingerprint      该 PEM 的 sha256 十六进制 vs 内置常量（patch P1/P2 已换成我们的）
    x509.Verify(第 3 段叶子证书, [根证书])
    rsa.VerifyPKCS1v15(叶子公钥, sha256(第 1 段解码字节), 第 2 段签名)

所以只要把 4 行设置写成本站根证书（PEM + 指纹），面板就会用**自己的官方代码**
接受我们签发的证书：内容解析、字段落库、状态、主节点绑定全部走官方流程。

存储值格式（与 xpack/utils/encrypt_xpack.StringEncrypt 一致）：
    base64( iv(16) || AES-128-CBC-PKCS7(plaintext, key = "nel1Pa2520pack@x") )

用法
----
  python3 tools/rootcert_store.py --cert web/state/license.crt --db /opt/1panel/db/xpack.db
  python3 tools/rootcert_store.py --cert ... --db ... --show      # 只打印当前 4 行
  python3 tools/rootcert_store.py --db ... --backup               # 备份官方原值
  python3 tools/rootcert_store.py --db ... --restore              # 还原官方原值
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aes128 import cbc_encrypt, cbc_decrypt, pkcs7_pad, pkcs7_unpad  # noqa: E402

# encrypt_xpack.StringEncrypt / decryptRootCertStoreValue 用的固定盐（16 字节）
STORE_KEY = b"nel1Pa2520pack@x"

# 官方内置根证书指纹（= 破解前二进制的 P1/P2 常量），用来判断库里这 4 行
# 到底是「官方原值」还是「本站已写入」。官方原值备份在 tools/official_rootcert.json。
OFFICIAL_FP = {
    "hk": "cf7b264f820aba6e8ec1d46cc58af4f53b06e583b9619796855365044475b945",
    "cn": "14b3e497603d26e2c8532cafd1e317120c27548417bed452a9792a0b4d792c6e",
}
OFFICIAL_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "official_rootcert.json")

# Only established project roots belong here, never fingerprints discovered in DBs.
PROJECT_ROOT_FINGERPRINTS = frozenset({
    "cb8cc410354dbbda7b542c952a8c8ffb47a0f3d886c7e7273c89cb7a44156030",
})

KEYS = {
    "cert_hk": "LicenseRootCertHK",
    "fp_hk": "LicenseRootCertHKFingerprint",
    "cert_cn": "LicenseRootCertCN",
    "fp_cn": "LicenseRootCertCNFingerprint",
}


def encrypt(value: str, key: bytes = STORE_KEY) -> str:
    iv = secrets.token_bytes(16)
    ct = cbc_encrypt(pkcs7_pad(value.encode()), key[:16], iv)
    return base64.b64encode(iv + ct).decode()


def decrypt(value: str, key: bytes = STORE_KEY) -> str:
    raw = base64.b64decode(value, validate=True)
    if len(raw) < 32 or len(raw) % 16:
        raise ValueError("invalid encrypted root store value")
    return pkcs7_unpad(cbc_decrypt(raw[16:], key[:16], raw[:16])).decode()


def fingerprint(cert_pem: str) -> str:
    """与 Go 侧 sha256.Sum256(cert.Raw) 等价的十六进制指纹。"""
    der = ssl.PEM_cert_to_DER_cert(cert_pem)
    result = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout"],
                            input=der, capture_output=True)
    if result.returncode:
        raise ValueError("invalid root certificate")
    return hashlib.sha256(der).hexdigest()


def project_fingerprints(current_fp=None, extra_fps=()):
    known = set(PROJECT_ROOT_FINGERPRINTS)
    if current_fp is not None:
        known.add(current_fp)
    requested = set(extra_fps)
    if any(len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp)
           for fp in requested) or not requested.issubset(known):
        raise ValueError("replacement root fingerprint lacks established project ownership")
    return known


def database_uri(db, mode="ro"):
    return Path(db).resolve().as_uri() + "?mode=" + mode


def _root_rows(con):
    rows = {}
    for key in KEYS.values():
        found = con.execute("select value from core_settings where key=?", (key,)).fetchall()
        if len(found) > 1:
            raise ValueError("duplicate root store key: " + key)
        if found:
            rows[key] = found[0][0]
    return rows


def _check_root_rows(rows, known, preserve_foreign=False):
    states = {}
    for region in ("hk", "cn"):
        cert_key, fp_key = KEYS["cert_" + region], KEYS["fp_" + region]
        if cert_key not in rows and fp_key not in rows:
            states[region] = "missing"
            continue
        if cert_key not in rows or fp_key not in rows:
            raise ValueError("incomplete root store pair: " + region)
        try:
            actual = fingerprint(decrypt(rows[cert_key]))
            recorded = decrypt(rows[fp_key])
        except (ValueError, UnicodeError, TypeError, IndexError) as exc:
            raise ValueError("malformed root store pair: " + region) from exc
        if actual != recorded:
            raise ValueError("root certificate and fingerprint differ: " + region)
        if actual == OFFICIAL_FP[region]:
            states[region] = "official"
        elif actual in known:
            states[region] = "project"
        elif preserve_foreign:
            states[region] = "foreign"
        else:
            raise ValueError("unknown foreign root store pair: " + region)
    return states


def check_owned_roots(db, pem=None, extra_fps=(), preserve_foreign=False):
    """Read-only guard for the four license-root settings, not application certs."""
    current_fp = fingerprint(pem) if pem is not None else None
    known = project_fingerprints(current_fp, extra_fps)
    with sqlite3.connect(database_uri(db), uri=True) as con:
        states = _check_root_rows(_root_rows(con), known, preserve_foreign)
    return {"ready": True, "roots": states}


def _now() -> str:
    off = datetime.datetime.now().astimezone().strftime("%z")
    off = "%s:%s" % (off[:3], off[3:])
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") + off


def show(db: str):
    con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    for k in KEYS.values():
        row = con.execute("select value from core_settings where key=?", (k,)).fetchone()
        if not row:
            print("%-32s <缺失>" % k)
            continue
        try:
            pt = decrypt(row[0])
        except Exception as exc:  # noqa: BLE001
            pt = "<解密失败: %s>" % exc
        head = pt.replace("\n", "\\n")[:70]
        print("%-32s %s" % (k, head))


def _backup_directory(path, create=False):
    """Open each parent without following symlinks; retain the final directory FD."""
    path = os.path.abspath(os.fspath(path))
    parent, name = os.path.split(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parent.split("/"):
            if not part:
                continue
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, name
    except BaseException:
        os.close(fd)
        raise


def _read_immutable_at(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("preserved root snapshot must be a regular mode-0600 file")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _snapshot_bytes(rows):
    return (json.dumps(rows, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("ascii")


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate preserved root backup key: " + key)
        result[key] = value
    return result


def _validate_snapshot(payload, known):
    loaded = json.loads(payload, object_pairs_hook=_unique_json_pairs)
    if (not isinstance(loaded, dict) or not loaded or
            not set(loaded).issubset(KEYS.values()) or
            any(not isinstance(value, str) for value in loaded.values())):
        raise ValueError("invalid preserved root backup")
    _check_root_rows(loaded, known, preserve_foreign=True)
    if payload != _snapshot_bytes(loaded):
        raise ValueError("preserved root backup is not canonical")
    return loaded


def _preserve_roots(rows, backup_path, known):
    """Publish durable archives and the immutable first-snapshot hardlink before SQL writes."""
    payload = _snapshot_bytes(rows)
    _validate_snapshot(payload, known)
    digest = hashlib.sha256(payload).hexdigest()
    archive = "core_settings_license_rootcert.preserved.%s.json" % digest
    directory, name = _backup_directory(backup_path, create=True)
    pointer = name + ".preserved.json"
    temporary = ".rootcert-preserved." + secrets.token_hex(16)
    fd = None
    created = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        created = True
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fd = None
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temporary, archive, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
        except FileExistsError:
            pass
        if _read_immutable_at(directory, archive) != payload:
            raise ValueError("preserved root archive differs from its content hash")
        os.fsync(directory)
        try:
            os.link(archive, pointer, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
        except FileExistsError:
            pass
        first = _read_immutable_at(directory, pointer)
        _validate_snapshot(first, known)
        first_archive = "core_settings_license_rootcert.preserved.%s.json" % hashlib.sha256(first).hexdigest()
        if _read_immutable_at(directory, first_archive) != first:
            raise ValueError("initial preserved root snapshot differs from its content hash")
        if os.stat(pointer, dir_fd=directory, follow_symlinks=False).st_ino != os.stat(
                first_archive, dir_fd=directory, follow_symlinks=False).st_ino:
            raise ValueError("initial preserved root snapshot must remain an archive hardlink")
        os.fsync(directory)
        return os.path.join(os.path.dirname(os.path.abspath(os.fspath(backup_path))), archive)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if created:
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
        finally:
            os.close(directory)


def _preserved_backup(path, known):
    try:
        directory, name = _backup_directory(path)
    except FileNotFoundError:
        return None
    try:
        try:
            payload = _read_immutable_at(directory, name + ".preserved.json")
        except FileNotFoundError:
            return None
        data = _validate_snapshot(payload, known)
        archive = "core_settings_license_rootcert.preserved.%s.json" % hashlib.sha256(payload).hexdigest()
        if _read_immutable_at(directory, archive) != payload:
            raise ValueError("preserved root backup differs from its content hash")
        if os.stat(name + ".preserved.json", dir_fd=directory, follow_symlinks=False).st_ino != os.stat(
                archive, dir_fd=directory, follow_symlinks=False).st_ino:
            raise ValueError("preserved root backup must remain an archive hardlink")
        return data
    finally:
        os.close(directory)


def write(db: str, cert_pem: str, fp: str, dry_run=False, extra_fps=(),
          preserve_foreign=False, backup_path=None):
    if preserve_foreign and not backup_path:
        raise ValueError("preserve-foreign requires backup_path")
    if fingerprint(cert_pem) != fp:
        raise ValueError("supplied certificate and fingerprint differ")
    known = project_fingerprints(fp, extra_fps)
    if preserve_foreign:
        check_owned_roots(db, cert_pem, extra_fps, preserve_foreign=True)
    else:
        check_owned_roots(db, cert_pem, extra_fps)
    snapshot = None
    with sqlite3.connect(database_uri(db, "rw"), uri=True, timeout=30) as con:
        con.execute("begin immediate")
        rows = _root_rows(con)
        states = _check_root_rows(rows, known, preserve_foreign)
        written = list(KEYS.values())
        if dry_run:
            con.rollback()
            return written
        if preserve_foreign and any(state in ("official", "foreign") for state in states.values()):
            snapshot = _preserve_roots(rows, backup_path, known)
        now = _now()
        for key, value in ((KEYS["cert_hk"], cert_pem), (KEYS["cert_cn"], cert_pem),
                           (KEYS["fp_hk"], fp), (KEYS["fp_cn"], fp)):
            enc = encrypt(value)
            row = con.execute("select id from core_settings where key=?", (key,)).fetchone()
            if row:
                con.execute("update core_settings set value=?, updated_at=? where key=?",
                            (enc, now, key))
            else:
                con.execute("insert into core_settings (created_at, updated_at, key, value,"
                            " description) values (?,?,?,?,?)", (now, now, key, enc, ""))
    if snapshot is not None:
        print("preserved root snapshot: " + snapshot)
    return written


def is_official(rows: dict) -> bool:
    """这 4 行是不是官方原值（指纹等于内置常量）。"""
    if set(rows) != set(KEYS.values()):
        return False
    try:
        return all(state == "official" for state in _check_root_rows(rows, set()).values())
    except (ValueError, OSError):
        return False


def backup(db: str, path: str):
    """把**官方原值**存成 JSON（回滚时用）。

    只备份官方原值：如果库里已经是本站根证书（重复执行安装），
    直接跳过，避免把本站证书当成「官方备份」存下来（那样回滚等于没回滚）。
    """
    import json
    con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    rows = {}
    for k in KEYS.values():
        row = con.execute("select value from core_settings where key=?", (k,)).fetchone()
        if row:
            rows[k] = row[0]
    con.close()
    if not rows:
        return None, "库里没有这 4 行"
    if not is_official(rows):
        return None, "当前不是官方原值（已写过本站根证书），跳过备份"
    with open(path, "w") as fh:
        json.dump(rows, fh, indent=1)
    return path, "官方原值已备份到 %s" % path


def archive_current(db, path, cert_pem=None):
    """Opt-in pre-stop archive; write() still archives its fresh locked DB state."""
    current_fp = fingerprint(cert_pem) if cert_pem is not None else None
    known = project_fingerprints(current_fp)
    with sqlite3.connect(database_uri(db), uri=True) as con:
        con.execute("begin")
        rows = _root_rows(con)
        states = _check_root_rows(rows, known, preserve_foreign=True)
        if not any(state in ("official", "foreign") for state in states.values()):
            return None
        return _preserve_roots(rows, path, known)


def _restore_preserved(db, path, known):
    with sqlite3.connect(database_uri(db, "rw"), uri=True, timeout=30) as con:
        con.execute("begin immediate")
        states = _check_root_rows(_root_rows(con), known, preserve_foreign=True)
        if "project" not in states.values():
            return "Existing non-project root certificates unchanged"
        data = _preserved_backup(path, known)
        if data is None:
            if not os.path.exists(path) and os.path.exists(OFFICIAL_JSON):
                path = OFFICIAL_JSON
            if os.path.exists(path):
                with open(path) as fh:
                    loaded = json.load(fh, object_pairs_hook=_unique_json_pairs)
                if not isinstance(loaded, dict):
                    raise ValueError("invalid root backup")
                data = {key: loaded[key] for key in KEYS.values() if key in loaded}
                if not data or any(not isinstance(value, str) for value in data.values()):
                    raise ValueError("invalid root backup")
                _check_root_rows(data, known, preserve_foreign=True)
        restored = 0
        if data is not None:
            for region, state in states.items():
                keys = (KEYS["cert_" + region], KEYS["fp_" + region])
                if state != "project" or not all(key in data for key in keys):
                    continue
                for key in keys:
                    con.execute("update core_settings set value=? where key=?", (data[key], key))
                    restored += 1
        return "Restored original root certificates: %d rows; other roots unchanged" % restored


def restore(db: str, path: str, cert_pem=None, extra_fps=(), preserve_foreign=False):
    """Restore only coherent official pairs, guarded by current project ownership."""
    current_fp = fingerprint(cert_pem) if cert_pem is not None else None
    known = project_fingerprints(current_fp, extra_fps)
    if preserve_foreign:
        check_owned_roots(db, cert_pem, extra_fps, preserve_foreign=True)
        return _restore_preserved(db, path, known)
    check_owned_roots(db, cert_pem, extra_fps)
    if not os.path.exists(path) and os.path.exists(OFFICIAL_JSON):
        path = OFFICIAL_JSON
    data = None
    if os.path.exists(path):
        with open(path) as fh:
            loaded = json.load(fh)
        if not isinstance(loaded, dict):
            raise ValueError("invalid official root backup")
        data = {key: loaded[key] for key in KEYS.values() if key in loaded}
        if not is_official(data):
            raise ValueError("backup lacks coherent official root certificate pairs")
    with sqlite3.connect(database_uri(db, "rw"), uri=True, timeout=30) as con:
        con.execute("begin immediate")
        rows = _root_rows(con)
        states = _check_root_rows(rows, known)
        if not rows or is_official(rows):
            return "官方根证书保持原值"
        if data is not None:
            restored = 0
            for region, state in states.items():
                if state != "project":
                    continue
                for key in (KEYS["cert_" + region], KEYS["fp_" + region]):
                    con.execute("update core_settings set value=? where key=?", (data[key], key))
                    restored += 1
            return "已还原官方根证书 %d 行" % restored
        owned_keys = []
        for region in ("hk", "cn"):
            cert_key, fp_key = KEYS["cert_" + region], KEYS["fp_" + region]
            if cert_key in rows and fingerprint(decrypt(rows[cert_key])) in known:
                owned_keys.extend((cert_key, fp_key))
        for key in owned_keys:
            con.execute("delete from core_settings where key=?", (key,))
        return "已删除本站根证书 %d 行" % len(owned_keys)


def main():
    ap = argparse.ArgumentParser()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    certs = (os.path.join(root, "web", "state", "license.crt"),
             os.path.join(root, "state", "license.crt"))
    ap.add_argument("--cert", default=os.environ.get("SIGN_CRT") or
                    next((p for p in certs if os.path.isfile(p)), certs[0]))
    ap.add_argument("--db", default="/opt/1panel/db/xpack.db")
    ap.add_argument("--show", action="store_true", help="只打印当前设置")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--backup", action="store_true", help="备份官方原值到 --bak")
    ap.add_argument("--restore", action="store_true", help="从 --bak 还原官方原值")
    ap.add_argument("--check-owned", action="store_true", help="read-only license-root ownership preflight")
    ap.add_argument("--preserve-foreign", action="store_true",
                    help="opt in to coherent foreign-root migration with immutable backups")
    ap.add_argument("--archive-current", action="store_true",
                    help="archive validated non-project roots before stopping services; requires --preserve-foreign")
    ap.add_argument("--replace-root-fingerprint", action="append", default=[],
                    help="explicit established project root fingerprint")
    ap.add_argument("--bak", default="/opt/1panel/crack/backup/"
                                     "core_settings_license_rootcert.json")
    args = ap.parse_args()

    if args.show:
        show(args.db)
        return 0
    if args.check_owned:
        pem = None
        if os.path.isfile(args.cert):
            with open(args.cert) as fh:
                pem = fh.read()
        print(json.dumps(check_owned_roots(args.db, pem, args.replace_root_fingerprint,
                                          preserve_foreign=args.preserve_foreign)))
        return 0
    if args.archive_current:
        if not args.preserve_foreign:
            raise ValueError("archive-current requires --preserve-foreign")
        pem = None
        if os.path.isfile(args.cert):
            with open(args.cert) as fh:
                pem = fh.read()
        snapshot = archive_current(args.db, args.bak, pem)
        print("preserved root snapshot: " + snapshot if snapshot else "No non-project root snapshot required")
        return 0
    if args.backup:
        os.makedirs(os.path.dirname(args.bak), exist_ok=True)
        _p, msg = backup(args.db, args.bak)
        print(msg)
        return 0
    if args.restore:
        pem = None
        if os.path.isfile(args.cert):
            with open(args.cert) as fh:
                pem = fh.read()
        print(restore(args.db, args.bak, pem, args.replace_root_fingerprint,
                      preserve_foreign=args.preserve_foreign))
        return 0

    pem = None
    if os.path.isfile(args.cert):
        with open(args.cert) as fh:
            pem = fh.read()
    if pem is None:
        raise ValueError("missing signing certificate: " + args.cert)
    if "BEGIN CERTIFICATE" not in pem:
        raise SystemExit("不是 PEM 证书: %s" % args.cert)
    fp = fingerprint(pem)
    check_owned_roots(args.db, pem, args.replace_root_fingerprint,
                      preserve_foreign=args.preserve_foreign)
    if not args.dry_run:
        os.makedirs(os.path.dirname(args.bak), exist_ok=True)
        _p, msg = backup(args.db, args.bak)
        print("备份   : %s" % msg)
    keys = write(args.db, pem, fp, args.dry_run, args.replace_root_fingerprint,
                 preserve_foreign=args.preserve_foreign, backup_path=args.bak)
    print("根证书 : %s" % args.cert)
    print("指纹   : %s" % fp)
    print("已写入 : %s%s" % (", ".join(keys), "（dry-run）" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
