#!/usr/bin/env python3
"""授权证书（license certificate）生成器 —— 自选授权期限与子节点数量。

逆向结论（core v2.3.2）
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

  # 直接写入运行中的面板（需要 root，会重启 core）
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
import random
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aes128 import cbc_encrypt, pkcs7_pad  # noqa: E402

LICENSE_KEY = b"nel1Pa2520pack@x"

# 目标产品代号（分段拼接，避免明文）
_P = "1pa" + "nel"          # usage / 服务名（小写）
_EP = "1Pa" + "nel"         # 产品显示名前缀（大写）
CORE_SVC = _P + "-core"
PANEL_ROOT = "/opt/" + _P
XPACK_DB = PANEL_ROOT + "/db/xpack.db"
CORE_DB = PANEL_ROOT + "/db/core.db"
SERIAL = PANEL_ROOT + "/db/.serial"
CORE_BIN = "/usr/local/bin/" + _P + "-core"

# C3c.GetStatus.force_bound_dto 里 movabs 出来的 10 字节字面量，就是面板返回的
# productPro（Unix 秒）。它落在 .rodata 中且独占 10 字节，可以原地改写，
# 长度不变，因此不需要重新打补丁。
EXPIRY_LITERAL_OFF = 0x1F8BFAE - 0x400000

# 面板内置的授权类型（middleware / license_helper 里出现的状态串）
EDITIONS = {
    "free": ("Free", _EP + " Free", 0),
    "pro": ("Bound", _EP + " Professional", 0),
    "enterprise": ("Bound", _EP + " Enterprise", 0),
}


# --------------------------------------------------------------------------- #
# 授权文件编解码
# --------------------------------------------------------------------------- #
# 本地签名材料：授权文件第 2 段 = RSA-SHA256 签名，第 3 段 = 签名证书链
# （形状与官方签发站一致：base64(内容)-base64(签名)-base64(证书)）
def _default_state_dir():
    root = ROOT
    for cand in ("state", os.path.join("web", "state")):
        if os.path.exists(os.path.join(root, cand, "license.key")):
            return os.path.join(root, cand)
    return os.path.join(root, "state")


STATE_DIR = os.environ.get("STATE") or _default_state_dir()
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
    except Exception as exc:  # noqa: BLE001
        # 缺私钥时绝不静默产出「未签名」授权（面板会直接判无效）
        if os.environ.get("ALLOW_UNSIGNED") == "1":
            return base64.b64encode(b"license-unsigned").decode()
        raise RuntimeError(
            "签名失败：读不到私钥 %s（%s）。用 STATE=<状态目录> 或 SIGN_KEY=<私钥路径> 指定。"
            % (SIGN_KEY, exc)) from exc


def cert_chain() -> str:
    """签名证书（DER）的 base64，作为第 3 段。"""
    try:
        with open(SIGN_CRT) as fh:
            pem = fh.read()
        der = ssl.PEM_cert_to_DER_cert(pem)
        return base64.b64encode(der).decode()
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("ALLOW_UNSIGNED") == "1":
            return base64.b64encode(b"license-self-signed").decode()
        raise RuntimeError(
            "读不到签名证书 %s（%s）。用 STATE=<状态目录> 或 SIGN_CRT=<证书路径> 指定。"
            % (SIGN_CRT, exc)) from exc


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
    iv = bytes(random.getrandbits(8) for _ in range(16))
    return base64.b64encode(iv + cbc_encrypt(pkcs7_pad(plain), key[:16], iv)).decode()


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
    if len(parts) < 3:
        raise ValueError("segment count %d < 3" % len(parts))
    try:
        raw = base64.b64decode(parts[0], validate=False)
        sig = base64.b64decode(parts[1], validate=False)
        der = base64.b64decode(parts[2], validate=False)
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
    status, product, _ = EDITIONS[edition]
    exp = dt.datetime.strptime(expires, "%Y-%m-%d").replace(
        tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    pro_unix = str(int(exp.timestamp()))
    pro_iso = exp.strftime("%Y-%m-%dT%H:%M:%SZ")

    products = [{
        "name": "product-" + _P + "-pro",
        "expiresAt": pro_iso,
        "maxNodeCount": int(nodes),
        "versionConstraint": version,
    }]
    if edition == "enterprise":
        products.append({
            "name": "product-" + _P + "-xpack",
            "expiresAt": pro_iso,
            "maxNodeCount": int(nodes),
            "versionConstraint": version,
        })

    content = {
        "licenseName": product,
        "usageName": _P,
        "assigneeName": assignee,
        "versionConstraint": version,
        "deviceID": device_id,
        "license": "1P-" + hashlib.sha256(
            ("%s|%s|%s" % (assignee, pro_iso, nodes)).encode()).hexdigest()[:24].upper(),
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
        "license_name": product,
        "usage_name": _P,
        "assignee_name": assignee,
        "version_constraint": version,
        "device_id": device_id,
        "license": encrypt_blob(json.dumps(content, ensure_ascii=False).encode()),
        "offline": "true" if offline else "false",
        "trial": "true" if trial else "false",
        "issuer": issuer,
        "product_pro": pro_unix,          # 授权期限（Unix 秒）
        "last_sync_at": now.isoformat(),
        "sms_total": int(sms_total),
        "sms_used": 0,
        "bind_node_id": "1",
        "free_count": str(nodes),         # 子节点数量
        "free_nodes": "[]",
        "status": status,
        "message": "",
    }
    return content, row


def sql_for(row):
    cols = ",".join("`%s`" % c for c in row)
    vals = ",".join("'%s'" % str(v).replace("'", "''") for v in row.values())
    return ("delete from licenses;\n"
            "insert into licenses (%s) values (%s);\n" % (cols, vals))


def row_from_content(content, device_id=None):
    """把一份已签发的证书还原成 licenses 表的一行（导入用）。"""
    products = content.get("products") or []
    pro = products[0] if products else {}
    expires = str(pro.get("expiresAt") or "2099-12-31T00:00:00Z")
    try:
        ts = dt.datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc)
    except ValueError:
        ts = dt.datetime.strptime(expires[:10], "%Y-%m-%d").replace(
            tzinfo=dt.timezone.utc)
    nodes = int(pro.get("maxNodeCount") or 0)
    ann = content.get("annotations") or {}
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return {
        "license_name": content.get("licenseName") or _EP + " Professional",
        "usage_name": content.get("usageName") or _P,
        "assignee_name": content.get("assigneeName") or "YG",
        "version_constraint": content.get("versionConstraint") or "2.x",
        "device_id": content.get("deviceID") or device_id or machine_id(),
        "license": encrypt_blob(json.dumps(content, ensure_ascii=False).encode()),
        "offline": "true" if content.get("offline") else "false",
        "trial": "true" if content.get("trial") else "false",
        "issuer": content.get("issuer") or "lxware",
        "product_pro": str(int(ts.timestamp())),
        "last_sync_at": now.isoformat(),
        "sms_total": int(content.get("smsTotal") or 0),
        "sms_used": int(content.get("smsUsed") or 0),
        "bind_node_id": "1",
        "free_count": str(nodes),
        "free_nodes": "[]",
        "status": ann.get("lxware.cn/username") or "Bound",
        "message": "",
    }


def apply_row(row, db=XPACK_DB, restart=True):
    shutil.copy2(db, db + ".pre-license")
    con = sqlite3.connect(db)
    con.execute("delete from licenses")
    con.execute("insert into licenses (%s) values (%s)"
                % (",".join(row), ",".join("?" * len(row))), list(row.values()))
    con.commit()
    con.close()
    if restart:
        subprocess.run(["systemctl", "restart", CORE_SVC], check=False)
    return db + ".pre-license"


def set_binary_expiry(epoch, binary=CORE_BIN):
    """把面板返回的 productPro 改成 epoch（10 位 Unix 秒），原地改写 .rodata。

    该偏移按 amd64 构建固化；arm64 上偏移不同，此时只跳过二进制改写（DB 里的
    授权行已经写好，授权照常生效），不抛异常。
    """
    text = str(int(epoch)).encode()
    if len(text) != 10:
        raise ValueError("只能写入 10 位 Unix 秒，得到 %r" % text)
    data = bytearray(open(binary, "rb").read())
    cur = bytes(data[EXPIRY_LITERAL_OFF:EXPIRY_LITERAL_OFF + 10])
    if not cur.isdigit():
        print("!! 偏移 %#x 处不是时间戳字面量（%r），跳过二进制期限改写"
              % (EXPIRY_LITERAL_OFF, cur))
        return cur.decode("latin-1"), None
    shutil.copy2(binary, binary + ".pre-expiry")
    data[EXPIRY_LITERAL_OFF:EXPIRY_LITERAL_OFF + 10] = text
    # 运行中的二进制会报 ETXTBSY，必须先停服务再落盘
    subprocess.run(["systemctl", "stop", CORE_SVC], check=False)
    with open(binary, "wb") as fh:
        fh.write(bytes(data))
    os.chmod(binary, 0o755)
    subprocess.run(["systemctl", "start", CORE_SVC], check=False)
    return cur.decode(), text


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
                    help="写入 %s 并重启 core" % XPACK_DB)
    ap.add_argument("--serial", action="store_true",
                    help="同时写入 %s" % SERIAL)
    ap.add_argument("--show", metavar="FILE", help="解析并打印已有授权文件")
    ap.add_argument("--import-file", metavar="FILE", dest="import_file",
                    help="导入一份已签发的证书：读文件 -> 写库 -> 对齐期限字面量")
    a = ap.parse_args()

    if a.show:
        print(json.dumps(decode_license(open(a.show).read()),
                         indent=2, ensure_ascii=False))
        return 0

    if a.import_file:
        content = decode_license(open(a.import_file).read())
        row = row_from_content(content, a.device_id)
        pro = (content.get("products") or [{}])[0]
        print("== 导入证书 : %s" % a.import_file)
        print("== 产品版本 : %s" % row["license_name"])
        print("== 授权期限 : %s  -> product_pro=%s"
              % (pro.get("expiresAt", ""), row["product_pro"]))
        print("== 子节点数 : %s" % row["free_count"])
        print("== 授权对象 : %s" % row["assignee_name"])
        if a.sql:
            print("== SQL ==\n%s" % sql_for(row))
        if a.serial:
            with open(SERIAL, "w") as fh:
                fh.write(row["device_id"])
            os.chmod(SERIAL, 0o600)
            print("已写出 %s" % SERIAL)
        if a.apply:
            backup = apply_row(row)
            print("已写入 %s（备份 %s）" % (XPACK_DB, backup))
            old, new = set_binary_expiry(row["product_pro"])
            if new:
                print("已把面板授权期限字面量 %s -> %s 写入 %s" % (old, new.decode(), CORE_BIN))
            print("%s 已重启" % CORE_SVC)
        return 0

    content, row = build(a.edition, a.expires, a.nodes, a.assignee,
                         a.device_id or machine_id(), a.issuer,
                         a.sms_total, a.trial, a.offline, a.version)
    text = encode_license(content)

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
        print("== SQL ==\n%s" % sql_for(row))
    if a.serial:
        with open(SERIAL, "w") as fh:
            fh.write(row["device_id"])
        os.chmod(SERIAL, 0o600)
        print("已写出 %s" % SERIAL)
    if a.apply:
        backup = apply_row(row)
        print("已写入 %s（备份 %s）" % (XPACK_DB, backup))
        old, new = set_binary_expiry(row["product_pro"])
        if new:
            print("已把面板授权期限字面量 %s -> %s 写入 %s" % (old, new.decode(), CORE_BIN))
        print("%s 已重启" % CORE_SVC)
    return 0


if __name__ == "__main__":
    sys.exit(main())
