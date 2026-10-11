#!/usr/bin/env python3
"""1Panel core (1panel-core) 授权门破解补丁器 —— 「只换授权方」。

思路：官方授权流程照跑，只把授权方从 lxware 换成本站许可中心：
  官方校验链（core/xpack/utils/license_helper.CheckInLocal）
    1) loadRootCertFromStore(host)  从 core_settings 读 LicenseRootCert{HK,CN}
    2) checkRootCertFingerprint     该 PEM 的 sha256 与内置常量比对（P1/P2）
    3) x509 Verify(第 3 段叶子证书, [根证书])
       rsa.VerifyPKCS1v15(叶子公钥, sha256(第 1 段解码字节), 第 2 段签名)
把 (2) 的内置常量换成本站根证书指纹，并由破解脚本把 4 个 core_settings 行
写成本站根证书，官方校验就会**真实通过**：内容解析、字段落库、状态、
节点绑定全部走官方代码，没有任何伪造。

默认补丁表（3 条，全部等长改写，不改段大小、不重定位）：
  P1/P2  内置根证书指纹（HK/CN）      -> 本站签发站根证书指纹
  C7     xpack.initLicense 启动清理   -> 不清掉 sync 字段为 0 的根证书行
         （否则每次重启都会把本站根证书行清回官方，授权失效）

**默认离线**：配合 offline=true 的签名证书，在本地执行真实 RSA 验签及根证书
指纹检查。默认不包含 P3/P4、不读取 REMOTE_BASE 环境变量；旧内核中的地址改写会
恢复官方原值。只有显式 --remote-base URL 才添加 P3/P4，兼容旧线上证书。
不会修改签名载荷或把现存 offline=false 证书强行变成离线证书。

许可证检查（RSA + 根证书指纹）都在 1panel-core 内由官方代码执行，
目标机上不需要任何额外文件。

偏移表的适配范围：按官方 v2.3.2 的构建固化（amd64 / arm64，见 OFFSETS 注释）。
换版本时固化偏移会失效，P1-P4 会按字面量自动重新定位；C7 是代码补丁，amd64 与
arm64 各有一套指令特征（amd64: cmp/jne；arm64: ldr/cbnz），按 Go 符号
xpack.initLicense + 指令特征重新定位，定位不到就拒绝输出破解内核（避免下发坏内核）。

Usage:
  python3 tools/patch_1panel_core.py --verify   [--in BIN]
  python3 tools/patch_1panel_core.py --patch    [--in BIN] [--out BIN]
  python3 tools/patch_1panel_core.py --restore  [--in BIN] [--out BIN]
  python3 tools/patch_1panel_core.py --list
"""
import argparse
import hashlib
import json
import os
import shutil
import ssl
import struct
import sys
import tempfile

# ---------------------------------------------------------------------------
# constants recovered from the binary
# ---------------------------------------------------------------------------
PRODUCT_PRO_TEXT = "2054922799"


DELTA = 0x400000          # file offset -> virtual address for every LOAD segment


def _vaddr(off):
    return off + DELTA


def _nop(n):
    return b"\x90" * n


# ---------------------------------------------------------------------------
# patch table:  name -> (offset, orig_bytes, patched_bytes, comment)
#
# 破解思路 = 「官方授权流程照跑，只把授权方换成许可中心签发站」：
#   官方校验链（license_helper.CheckInLocal）
#     1) loadRootCertFromStore(host)  从 core_settings 读 LicenseRootCert{HK,CN}
#     2) checkRootCertFingerprint     该 PEM 的 sha256 与内置常量比对（P1/P2）
#     3) x509 Verify(第 3 段叶子证书, [根证书])
#        rsa.VerifyPKCS1v15(叶子公钥, sha256(第 1 段解码字节), 第 2 段签名)
#   把 (2) 的内置常量换成本站根证书指纹，并由破解脚本把 4 个 core_settings 行
#   写成本站根证书，官方校验就会**真实通过**：内容解析、字段落库、状态、
#   节点绑定全部走官方代码，不再有任何伪造。
# ---------------------------------------------------------------------------
ROOT_FP_HK_OFF = 0x1568430        # .rodata "cf7b264f...b945"（官方 HK 根证书指纹）
ROOT_FP_CN_OFF = 0x1568470        # .rodata "14b3e497...792c6e"（官方 CN 根证书指纹）
ROOT_FP_HK_ORIG = b"cf7b264f820aba6e8ec1d46cc58af4f53b06e583b9619796855365044475b945"
ROOT_FP_CN_ORIG = b"14b3e497603d26e2c8532cafd1e317120c27548417bed452a9792a0b4d792c6e"

# 站点根证书路径：SIGN_CRT 优先，其次跟着 STATE（Docker/systemd 常把
# 状态目录挂到 /data/state），最后才是仓库内的默认位置。
def _default_cert_path():
    state = (os.environ.get("STATE") or "").strip()
    if state:
        return os.path.join(state, "license.crt")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = (os.path.join(root, "web", "state", "license.crt"),
                  os.path.join(root, "state", "license.crt"))
    return next((p for p in candidates if os.path.isfile(p)), candidates[0])


ROOT_CERT_PATH = os.environ.get("SIGN_CRT") or _default_cert_path()

def root_fingerprint(cert_path=None):
    """本站签发站根证书 DER 的 sha256 十六进制（等价 Go 侧 sha256.Sum256(cert.Raw)）。"""
    try:
        with open(cert_path or ROOT_CERT_PATH) as fh:
            der = ssl.PEM_cert_to_DER_cert(fh.read())
        return hashlib.sha256(der).hexdigest().encode()
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# P3/P4：授权服务器基地址（线上授权的「定期回连」目标）
#
# license_helper.Report / Unbind 里各有一份 33 字节常量，代码把它 memcpy 到
# 33 字节栈缓冲，所以新地址必须正好 33 字符（不足用 '/' 补齐，多余斜杠无影响）。
# 仅显式 --remote-base 启用。默认保持或恢复官方原值。
# ---------------------------------------------------------------------------
LICENSE_BASE_HK_OFF = 0x153FC14
LICENSE_BASE_CN_OFF = 0x153FC35
LICENSE_BASE_HK_ORIG = b"https://license.lxware.hk/api/v1/"
LICENSE_BASE_CN_ORIG = b"https://license.lxware.cn/api/v1/"

# Only a migration signature, never a default remote destination.
LEGACY_LICENSE_BASE = b"https://1p-cert.0rz.li/api/v1////"


def license_base_bytes(base=None):
    """把基地址规整成正好 33 字节（不足补 '/'，超长返回 None）。

    None 或空值表示离线默认；仅显式 --remote-base 提供远端地址。
    """
    if base is None:
        return None
    base = base.strip()
    if not base:
        return None
    if not base.endswith("/"):
        base += "/"
    raw = base.encode()
    if len(raw) > 33:
        return None
    return raw + b"/" * (33 - len(raw))


# 每项 = (名字, 固化的文件偏移, 官方原值, 替换值, 说明, 定位方式)
#
# 定位方式：
#   "literal"      等长字面量（根证书指纹 / 授权服务器地址）。换个 1Panel 版本或
#                  架构时，固化偏移会失效 —— 这时按字面量在二进制里唯一定位。
#   "initLicense"  代码补丁。偏移失效时在 Go 符号 xpack.initLicense 函数体内按
#                  指令特征 `cmp qword [rdx+0x90],0 ; jne +0x14` 重新定位。
PATCHES = [
    ("P1.rootcert.hk_fingerprint",
     ROOT_FP_HK_OFF, ROOT_FP_HK_ORIG, None,
     "checkRootCertFingerprint/loadRootCertFromStore 内置 HK 根证书指纹 -> 本站根证书指纹",
     "literal"),

    ("P2.rootcert.cn_fingerprint",
     ROOT_FP_CN_OFF, ROOT_FP_CN_ORIG, None,
     "checkRootCertFingerprint/loadRootCertFromStore 内置 CN 根证书指纹 -> 本站根证书指纹",
     "literal"),

    ("C7.initLicense.keep_rows",
     0x010866EF, bytes.fromhex("7514"), bytes.fromhex("eb14"),
     "xpack.initLicense: 启动时不再清掉 sync 字段为 0 的根证书行（保住本站根证书）",
     "initLicense"),
]

REMOTE_PATCHES = [
    ("P3.license_base.hk", LICENSE_BASE_HK_OFF, LICENSE_BASE_HK_ORIG, None,
     "Report/Unbind HK 基地址 -> 显式选择的线上兼容地址", "license_base"),
    ("P4.license_base.cn", LICENSE_BASE_CN_OFF, LICENSE_BASE_CN_ORIG, None,
     "Report/Unbind CN 基地址 -> 显式选择的线上兼容地址", "license_base"),
]

# C7 的指令特征：cmp qword ptr [rdx+0x90], 0 ; jne rel8
C7_CTX = bytes.fromhex("4883ba9000000000")     # 48 83 ba 90 00 00 00 00
C7_FUNC_SUFFIX = "core/xpack.initLicense"

# C7 的 amd64 / arm64 固化值（v2.3.2）：
#   两者语义相同 —— 遍历 licenses 行时，sync==0 就删掉（清回官方根证书）。
#   amd64: cmp [rdx+0x90],0 ; jne keep   ->  jmp keep（把 jne 改成 jmp）
#   arm64: ldr x2,[x1,#0x90] ; cbnz x2,keep ->  b keep（把 cbnz 改成 b）
C7_AMD64 = (0x010866EF, bytes.fromhex("7514"), bytes.fromhex("eb14"))
C7_ARM64 = (0xE6B9C8, bytes.fromhex("a20000b5"), bytes.fromhex("05000014"))

# arm64 v2.3.2 的 P1-P4 固化偏移（字面量与 amd64 相同，只是位置不同）。
# 换版本时这些偏移会失效，由 _resolve 按字面量自动重定位。
ARM64_OFFSETS = {
    "P1.rootcert.hk_fingerprint": 0x130EDFB,
    "P2.rootcert.cn_fingerprint": 0x130EE3B,
    "P3.license_base.hk": 0x12E6593,
    "P4.license_base.cn": 0x12E65B4,
}


def detect_machine(data):
    """ELF64 e_machine：62=x86-64，183=AArch64；非 ELF64 返回 None。"""
    if data is None or len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    end = "<" if data[5] == 1 else ">"
    return struct.unpack_from(end + "H", data, 0x12)[0]


def c7_spec(data):
    """C7 补丁的 (offset, orig, patched)，按二进制架构选择。"""
    if detect_machine(data) == 183:
        return C7_ARM64
    return C7_AMD64


def _find_unique(data, needle):
    """在二进制里唯一定位一段字面量；找不到或有第二处命中都返回 None。"""
    first = data.find(needle)
    if first < 0:
        return None
    if data.find(needle, first + 1) >= 0:
        return None
    return first


def _init_license_c7_off(data):
    """在 xpack.initLicense 函数体内按指令特征找 C7 的位置（跨版本/架构）。"""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gosym import read_syms          # noqa: PLC0415
    except Exception:                        # noqa: BLE001
        return None
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(data)
            tmp = fh.name
        _d, syms = read_syms(tmp)
    except (Exception, SystemExit):          # noqa: BLE001
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    machine = detect_machine(data)
    for s in syms:
        if not s["name"].endswith(C7_FUNC_SUFFIX):
            continue
        lo, hi = s["off"], s["off"] + s["size"]
        if machine == 183:
            # arm64: ldr xN,[xM,#0x90] ; cbnz xN,<keep> -> 返回 cbnz 的偏移
            for off in range(lo, hi - 4, 4):
                ldr = struct.unpack_from("<I", data, off)[0]
                if (ldr & 0xFFC00000) != 0xF9400000:
                    continue                      # 不是 ldr(无符号立即数,64位)
                if ((ldr >> 10) & 0xFFF) != 18:
                    continue                      # 偏移不是 18*8=0x90(sync 字段)
                rt = ldr & 0x1F
                cbnz = struct.unpack_from("<I", data, off + 4)[0]
                if (cbnz >> 24) != 0xB5 or (cbnz & 0x1F) != rt:
                    continue                      # 下一条不是同 Rt 的 cbnz
                return off + 4
            return None
        # amd64: 官方形态 75 14 / 已打过形态 eb 14
        for tail in (bytes.fromhex("7514"), bytes.fromhex("eb14")):
            idx = data.find(C7_CTX + tail, lo, hi)
            if idx >= 0:
                return idx + len(C7_CTX)
    return None


# 这些补丁定位不到就不能出破解内核（缺了会掉授权），必须显式 --force 才放行
REQUIRED = ("P1.", "P2.", "C7.")

_MISSING = []


def required_missing():
    return [n for n in _MISSING if n.startswith(REQUIRED)]


def _plausible(cur, orig):
    """偏移处的内容是否仍是「同一类东西」（十六进制指纹 / URL）。

    换过域名或换过签发证书的机器上，字面量既不是官方原值也不是当前环境算出的值，
    这时按形状认位，状态由 locate() 记为 patched(custom)。
    """
    if not cur or len(cur) != len(orig):
        return False
    if all(c in b"0123456789abcdef" for c in orig):
        return all(c in b"0123456789abcdef" for c in cur)
    if orig.startswith(b"http"):
        return cur.startswith(b"http") and all(32 <= c < 127 for c in cur)
    return False


def _resolve(data, name, off, orig, patched, how):
    """返回该补丁在这次二进制里的真实偏移；定位不到返回 None。"""
    if data is None:
        return off
    for cand in (orig, patched):
        if cand and data[off:off + len(cand)] == cand:
            return off
    if how == "literal" and orig:
        alt = _find_unique(data, orig)
        if alt is None and patched:
            alt = _find_unique(data, patched)
        if alt is not None:
            return alt
        # 换过域名/证书：位置没动，只是值变成了第三种
        if _plausible(data[off:off + len(orig)], orig):
            return off
    if how == "initLicense":
        alt = _init_license_c7_off(data)
        if alt is not None:
            return alt
    return None


def license_base_locations(data, remote_base=None):
    """Locate both URL slots, including identical legacy/custom replacements.

    The official HK/CN literals are adjacent. Validate the whole pair rather
    than guessing a slot from an unrelated URL at an outdated fixed offset.
    """
    width = len(LICENSE_BASE_HK_ORIG)
    hk_name, cn_name = "P3.license_base.hk", "P4.license_base.cn"
    off = (ARM64_OFFSETS[hk_name] if detect_machine(data) == 183
           else LICENSE_BASE_HK_OFF)

    def valid_pair(pos):
        hk, cn = data[pos:pos + width], data[pos + width:pos + width * 2]
        return ((hk == LICENSE_BASE_HK_ORIG and cn == LICENSE_BASE_CN_ORIG)
                or (hk == cn and _plausible(hk, LICENSE_BASE_HK_ORIG)
                    and hk.endswith(b"/")))

    if valid_pair(off):
        return [(hk_name, off, LICENSE_BASE_HK_ORIG),
                (cn_name, off + width, LICENSE_BASE_CN_ORIG)]
    pairs = [LICENSE_BASE_HK_ORIG + LICENSE_BASE_CN_ORIG,
             LEGACY_LICENSE_BASE * 2]
    explicit = license_base_bytes(remote_base)
    if explicit:
        pairs.append(explicit * 2)
    candidates = set()
    for pair in pairs:
        found = _find_unique(data, pair)
        if found is not None:
            candidates.add(found)
    # Older builds may have a custom domain and relocated URL literals.
    start = 0
    while True:
        found = data.find(b"http", start)
        if found < 0:
            break
        if valid_pair(found):
            candidates.add(found)
        start = found + 4
    if len(candidates) != 1:
        raise ValueError("无法唯一定位 HK/CN 授权地址；未输出内核")
    off = candidates.pop()
    return [(hk_name, off, LICENSE_BASE_HK_ORIG),
            (cn_name, off + width, LICENSE_BASE_CN_ORIG)]


def restore_license_bases(data, remote_base=None):
    """Restore URL bytes independently of the default three-patch table."""
    out = bytearray(data)
    restored = []
    for name, off, orig in license_base_locations(data, remote_base):
        if out[off:off + len(orig)] != orig:
            out[off:off + len(orig)] = orig
            restored.append({"name": name, "file_offset": hex(off),
                             "original": orig.decode("ascii")})
    return out, restored


# 旧版「状态伪造」补丁：全部删除。
#
# 这些补丁不改变授权来源，只把面板的状态判断短路掉，直接造成
#   * 没导入证书也显示「专业版」
#   * 授权表里的订阅授权 ID / 被授权方 / 版本 是乱码（CheckInLocal 被短路后
#     没有解密，字段被二次加密写库）
# 现在的做法与官方一致：默认只替换内置根证书指纹并保住根证书行，
# 证书校验、绑定、上报、落库全部走官方代码路径。
REMOVED_STATE_FAKES = {
    "C1.checkLicense.return_true":
        "middleware.checkLicense 恒 true：没证书也放行全部 xpack 路由",
    "C2a-d.state_force_bound":
        "强制把许可证状态写成 Bound/productPro",
    "C3a-e.sync_fake":
        "伪造同步结果（跳过远端 licenses/report）",
    "C4.Check.passthrough":
        "middleware.Check 恒走放行分支",
    "C5.EnsureFreeNodeBindAllowed.return_nil":
        "节点绑定校验恒通过",
    "C6.node_bind_free":
        "节点绑定流程跳过授权",
    "C8.NodeCreate.skip_license_bind":
        "创建节点时不调用官方 license bind",
    "C9.BindFree.return_nil":
        "BindFree 恒成功",
    "C10.CheckInLocal.return_nil":
        "本地校验恒成功（乱码根因）",
    "C11a-b.skip_report":
        "跳过远端上报直接落库（绑定丢失根因）",
}

def build_table(data, remote_base=None, cert_path=None, verbose=True):
    _MISSING.clear()
    out = []
    fp = root_fingerprint(cert_path)
    base = license_base_bytes(remote_base)
    if remote_base and base is None:
        raise SystemExit("!! 授权服务器基地址超过 33 字节（最长 33 字符），例如 "
                         "https://你的域名/api/v1/")
    machine = detect_machine(data)
    specs = PATCHES + (REMOTE_PATCHES if base else [])
    remote_locations = ({n: o for n, o, _ in license_base_locations(data, remote_base)}
                        if base and data is not None else {})
    for name, off, orig, patched, comment, how in specs:
        if machine == 183 and name in ARM64_OFFSETS:
            off = ARM64_OFFSETS[name]    # arm64 用自己固化的偏移（换版本再靠字面量重定位）
        if name.startswith(("P3.", "P4.")):
            patched = base
        if name.startswith(("P1.", "P2.")):
            # 内置根证书指纹 -> 本站根证书指纹（等长 64 字符十六进制）
            if fp is None or len(fp) != 64:
                _MISSING.append(name)
                continue                      # 没有签发站私钥材料时跳过，保持官方校验
            patched = fp
        if name.startswith("C7."):
            # C7 的偏移/原值/补丁值随架构不同（amd64 2 字节，arm64 4 字节）
            off, orig, patched = c7_spec(data)
        if orig is not None and len(orig) != len(patched):
            raise SystemExit("patch %s length mismatch %d != %d"
                             % (name, len(orig), len(patched)))
        real = (remote_locations.get(name, off) if how == "license_base"
                else _resolve(data, name, off, orig, patched, how))
        if real is None:
            if verbose:
                print("!! %s: 固化偏移 %#x 与字面量都对不上，这份二进制无法定位该补丁"
                      % (name, off))
            _MISSING.append(name)
            continue
        if real != off and verbose:
            print("   %s: 偏移自动重定位 %#x -> %#x（版本/架构不同）"
                  % (name, off, real))
        out.append((name, real, orig, patched, comment))
    return out


# pristine image, needed by patches whose original bytes are context dependent
#
# 容器部署时 build/ 目录不在镜像里，所以按候选路径依次查找；
# 都找不到也不抛异常（PRISTINE=None），交由调用方自己提供 data。
def load_pristine():
    cands = []
    if os.environ.get("ORIG"):
        cands.append(os.path.join(os.environ["ORIG"], "1panel-core.orig"))
    cands += [
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "build", "orig", "1panel-core.orig"),
        "/opt/1panel/crack/orig/1panel-core.orig",
        "/usr/local/bin/1panel-core",
    ]
    for p in cands:
        if os.path.isfile(p):
            with open(p, "rb") as fh:
                return fh.read()
    return None


PRISTINE = load_pristine()

TABLE = build_table(PRISTINE) if PRISTINE else []


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _render(name, cur):
    """补丁值一律按十六进制打印（P1/P2 是指纹，C7 是指令）。"""
    return cur[:16].hex()


def locate(data):
    """Return per-patch state.

    P1/P2 的替换值是按环境现算的（根证书指纹），所以只要不是官方原值就说明补丁在位：
    状态记 'patched' 或 'patched(custom)'（跟当前环境算出来的值不同，例如换了证书）。
    C7 是定值。
    """
    states = []
    for name, off, orig, patched, _ in TABLE:
        cur = data[off:off + len(patched)]
        if orig is not None and cur == orig:
            st = "original"
        elif cur == patched:
            st = "patched"
        elif orig is not None and (name.startswith("P") or len(orig) == len(cur)):
            st = "patched(custom)"
        else:
            st = "unknown"
        states.append((name, off, st, cur))
    return states


def main():
    global TABLE
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="/usr/local/bin/1panel-core")
    ap.add_argument("--out", dest="dst", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--patch", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--orig", dest="orig", default="build/orig/1panel-core.orig")
    ap.add_argument("--manifest", dest="manifest", default="build/1panel-core.manifest.json")
    ap.add_argument("--remote-base", dest="remote_base", default=None,
                    metavar="URL",
                    help="显式启用旧线上兼容地址（≤33 字节）；默认/空值离线，"
                         "恢复官方 HK/CN 地址，不读取 REMOTE_BASE 环境变量")
    ap.add_argument("--force", action="store_true",
                    help="即使必需补丁（P1/P2/C7）定位不到也照常输出；地址定位和旧伪造检查仍开启")
    args = ap.parse_args()

    def state_fakes(path):
        """Reject known old return stubs instead of preserving forged state."""
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gosym import read_syms
        try:
            image, syms = read_syms(path)
        except (Exception, SystemExit):
            return ["Go authorization symbols unreadable"]
        suffixes = ("license_helper.Report", "license_helper.Unbind",
                    "license_helper.CheckInLocal", "middleware.checkLicense",
                    "license_helper.BindFree", "license_helper.EnsureFreeNodeBindAllowed")
        stubs = (bytes.fromhex("31c031dbc3"), bytes.fromhex("31c031db31c9c3"),
                 bytes.fromhex("b801000000c3"), bytes.fromhex("31c0c3"),
                 bytes.fromhex("000080d2010080d2c0035fd6"),
                 bytes.fromhex("000080d2c0035fd6"),
                 bytes.fromhex("200080d2c0035fd6"))
        return [s["name"] for s in syms if s["name"].endswith(suffixes)
                and image[s["off"]:s["off"] + 24].startswith(stubs)]

    if args.list:
        specs = PATCHES + (REMOTE_PATCHES if license_base_bytes(args.remote_base) else [])
        for name, off, orig, patched, comment, _how in specs:
            n = len(patched) if patched is not None else len(orig or b"")
            print("%-38s file=%#010x len=%2d  %s" % (name, off, n, comment))
        print("   模式: %s" % ("显式线上兼容" if license_base_bytes(args.remote_base)
                              else "离线默认；官方 HK/CN 地址保留/恢复"))
        return 0

    if args.verify:
        data = open(args.src, "rb").read()
        print("binary : %s" % args.src)
        print("sha256 : %s" % sha256(args.src))
        print("size   : %d" % len(data))
        bad = 0
        fakes = state_fakes(args.src)
        if fakes:
            print("!! legacy state-forging stubs: %s; rebuild from official core.orig" % ", ".join(fakes))
            bad += len(fakes)
        try:
            TABLE = build_table(data, remote_base=args.remote_base, verbose=False)
            locations = license_base_locations(data, args.remote_base)
        except ValueError as exc:
            print("!! %s" % exc)
            return 1
        bad += len(required_missing())
        states = locate(data)
        for name, off, st, cur in states:
            mark = {"original": "ORIG", "patched": "PATCHED",
                    "patched(custom)": "PATCHED*", "unknown": "!! UNKNOWN"}[st]
            if st != "patched":
                bad += 1
            print("  %-38s %#010x  %-10s %s" % (name, off, mark, _render(name, cur)))
        base = license_base_bytes(args.remote_base)
        for nm, off, orig in locations:
            cur = data[off:off + len(orig)]
            expected = base or orig
            if cur != expected:
                bad += 1
            print("  地址 %-2s %#010x  %s %s" % (nm.split(".")[-1], off,
                  "OK" if cur == expected else "!! MISMATCH", cur.decode("ascii", "replace")))
        if required_missing():
            print("!! missing required patches: %s" % ", ".join(required_missing()))
        print("\nstate  : %s" % ("all patches present" if bad == 0
                                 else "未打补丁/异常 (%d)" % bad))
        return 0 if bad == 0 else 1

    if args.restore:
        src = args.orig if os.path.exists(args.orig) else args.src
        data = open(src, "rb").read()
        try:
            data, restored_bases = restore_license_bases(data, args.remote_base)
        except ValueError as exc:
            print("!! %s" % exc)
            return 2
        data = bytes(data)
        table = build_table(data)
        for name, off, orig, patched, _ in table:
            if orig is None:
                continue
            if name.startswith("P"):
                # 常量类补丁（根证书指纹 / 授权服务器地址）：只要不是官方原值就还原
                if bytes(data[off:off + len(orig)]) != orig:
                    data = data[:off] + orig + data[off + len(orig):]
            elif bytes(data[off:off + len(patched)]) == patched:
                data = data[:off] + orig + data[off + len(orig):]
        out = args.dst or args.src
        with open(out, "wb") as fh:
            fh.write(data)
        os.chmod(out, 0o755)
        print("restored %s -> %s (sha256 %s)" % (src, out, sha256(out)))
        return 0

    if args.patch:
        src, dst = args.src, args.dst or args.src
        fakes = state_fakes(src)
        if fakes:
            print("!! legacy state-forging stubs: %s; rebuild from official core.orig" % ", ".join(fakes))
            return 2
        data = bytearray(open(src, "rb").read())
        restored_bases = []
        if not license_base_bytes(args.remote_base):
            try:
                data, restored_bases = restore_license_bases(data)
            except ValueError as exc:
                print("!! %s" % exc)
                return 2
        # 按**输入文件**自己定位补丁（换版本/架构时固化偏移会失效）
        try:
            table = build_table(bytes(data), remote_base=args.remote_base)
        except ValueError as exc:
            print("!! %s" % exc)
            return 2
        applied, skipped = [], []
        for name, off, orig, patched, _ in table:
            cur = bytes(data[off:off + len(patched)])
            if cur == patched:
                skipped.append(name)
                continue
            if orig is not None and cur != orig and not (
                    name.startswith(("P1.", "P2.", "P3.", "P4."))
                    and _plausible(cur, orig)):
                print("!! %s: unexpected bytes at %#x: %s" % (name, off, cur.hex()))
                return 2
            data[off:off + len(patched)] = patched
            applied.append(name)

        miss = required_missing()
        if miss and not args.force:
            print("!! 必需补丁定位不到：%s" % ", ".join(miss))
            print("   这份 1Panel 内核（换版本/换架构）暂时不适配，未输出破解内核。")
            print("   确认要继续可加 --force（缺 C7 会掉根证书行，授权会失效）。")
            return 3

        os.makedirs(os.path.dirname(os.path.abspath(args.manifest)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(args.orig)), exist_ok=True)
        if not os.path.exists(args.orig):
            shutil.copy2(src, args.orig)
            print("pristine copy -> %s" % args.orig)

        with open(dst, "wb") as fh:
            fh.write(bytes(data))
        os.chmod(dst, 0o755)

        man = {
            "tool": "patch_1panel_core.py",
            "version": "1panel-core v2.3.2 (sha256 f1265a4fadeaab3d7066dd71e3c6904ac54bb687baab1b205a23c369abb61cac)",
            "source": src,
            "source_sha256": sha256(args.orig),
            "output": dst,
            "output_sha256": sha256(dst),
            "product_pro": PRODUCT_PRO_TEXT,
            "applied": applied,
            "already_patched": skipped,
            "mode": "remote" if license_base_bytes(args.remote_base) else "offline",
            "remote_base": args.remote_base or "",
            "restored_license_bases": restored_bases,
            "patches": [{"name": n, "file_offset": hex(o),
                         "orig": (o2.hex() if o2 else None),
                         "patch": p.hex(), "note": c}
                        for n, o, o2, p, c in table],
        }
        with open(args.manifest, "w") as fh:
            json.dump(man, fh, indent=2, ensure_ascii=False)

        print("applied  : %s" % (", ".join(applied) or "(none)"))
        print("skipped  : %s" % (", ".join(skipped) or "(none)"))
        print("restored : %s" % (", ".join(r["name"] for r in restored_bases) or "(none)"))
        print("output   : %s" % dst)
        print("sha256   : %s" % man["output_sha256"])
        print("manifest : %s" % args.manifest)
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
