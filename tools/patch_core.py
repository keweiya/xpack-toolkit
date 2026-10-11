#!/usr/bin/env python3
"""Core 授权门补丁器 —— 「只换授权方」。

思路：官方授权流程照跑，只把授权方从官方签发站换成本站许可中心：
  官方校验链（core/xpack/utils/license_helper.CheckInLocal）
    1) loadRootCertFromStore(host)  从 core_settings 读 LicenseRootCert{HK,CN}
    2) checkRootCertFingerprint     该 PEM 的 sha256 与内置常量比对（P1/P2）
    3) x509 Verify(第 3 段叶子证书, [根证书])
       rsa.VerifyPKCS1v15(叶子公钥, sha256(第 1 段解码字节), 第 2 段签名)
把 (2) 的内置常量换成本站根证书指纹，并由配套脚本把 4 个 core_settings 行
写成本站根证书，官方校验就会**真实通过**：内容解析、字段落库、状态、
节点绑定全部走官方代码，没有任何伪造。

补丁表（5 条，全部等长改写，不改段大小、不重定位）：
  P1/P2  内置根证书指纹（HK/CN）      -> 本站签发站根证书指纹
  P3/P4  授权服务器基地址（HK/CN）    -> 本站签发站 /api/v1/（默认写死 1p-cert.0rz.li）
  C7     xpack.initLicense 启动清理   -> 不清掉 sync 字段为 0 的根证书行
         （否则每次重启都会把本站根证书行清回官方，授权失效）

**线上授权**：授权服务器基地址写死成本站签发站（默认 https://1p-cert.0rz.li/api/v1/，
可用 --remote-base 覆盖域名）。证书里 offline=false 的期限（月度/季度/年度）会定期回连
本站校验是否有效；offline=true 的「永久版」只在本地验签、不回连。RSA 验签与根证书
指纹检查都在 core 内由官方代码执行，目标机上不需要任何额外文件。

偏移表的适配范围：按官方 v2.3.2 的构建固化（amd64 / arm64，见 OFFSETS 注释）。
换版本时固化偏移会失效，P1-P4 会按字面量自动重新定位；C7 是代码补丁，amd64 与
arm64 各有一套指令特征（amd64: cmp/jne；arm64: ldr/cbnz），按 Go 符号
xpack.initLicense + 指令特征重新定位，定位不到就拒绝输出（避免下发坏内核）。

Usage:
  python3 tools/patch_core.py --verify   [--in BIN]
  python3 tools/patch_core.py --patch    [--in BIN] [--out BIN]
  python3 tools/patch_core.py --restore  [--in BIN] [--out BIN]
  python3 tools/patch_core.py --list
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

# 目标产品代号（分段拼接，避免明文）
_P = "1pa" + "nel"
PANEL_ROOT = "/opt/" + _P
CORE_BIN = "/usr/local/bin/" + _P + "-core"

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
# 思路 = 「官方授权流程照跑，只把授权方换成许可中心签发站」：
#   官方校验链（license_helper.CheckInLocal）
#     1) loadRootCertFromStore(host)  从 core_settings 读 LicenseRootCert{HK,CN}
#     2) checkRootCertFingerprint     该 PEM 的 sha256 与内置常量比对（P1/P2）
#     3) x509 Verify(第 3 段叶子证书, [根证书])
#        rsa.VerifyPKCS1v15(叶子公钥, sha256(第 1 段解码字节), 第 2 段签名)
#   把 (2) 的内置常量换成本站根证书指纹，并由配套脚本把 4 个 core_settings 行
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
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    for cand in ("state", os.path.join("web", "state")):
        p = os.path.join(root, cand, "license.crt")
        if os.path.exists(p):
            return p
    return os.path.join(root, "state", "license.crt")


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
# 默认写死本站签发站：证书 offline=false 的期限定期回连这里校验是否有效。
# ---------------------------------------------------------------------------
LICENSE_BASE_HK_OFF = 0x153FC14
LICENSE_BASE_CN_OFF = 0x153FC35
LICENSE_BASE_HK_ORIG = b"https://license.lxware.hk/api/v1/"
LICENSE_BASE_CN_ORIG = b"https://license.lxware.cn/api/v1/"

# 写死的授权服务器基地址：域名换掉时用 --remote-base 或 REMOTE_BASE 环境变量覆盖
DEFAULT_LICENSE_BASE = "https://1p-cert.0rz.li/api/v1/"


def license_base_bytes(base=None):
    """把基地址规整成正好 33 字节（不足补 '/'，超长返回 None）。

    默认用写死的 DEFAULT_LICENSE_BASE；`--remote-base` / REMOTE_BASE 可覆盖。
    """
    if base is None:
        base = os.environ.get("REMOTE_BASE") or DEFAULT_LICENSE_BASE
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
#   "literal"      等长字面量（根证书指纹 / 授权服务器地址）。换个产品版本或
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

    ("P3.license_base.hk",
     LICENSE_BASE_HK_OFF, LICENSE_BASE_HK_ORIG, None,
     "Report/Unbind 的 HK 授权服务器基地址 -> 本站签发站（默认 1p-cert.0rz.li）",
     "literal"),

    ("P4.license_base.cn",
     LICENSE_BASE_CN_OFF, LICENSE_BASE_CN_ORIG, None,
     "Report/Unbind 的 CN 授权服务器基地址 -> 本站签发站（默认 1p-cert.0rz.li）",
     "literal"),

    ("C7.initLicense.keep_rows",
     0x010866EF, bytes.fromhex("7514"), bytes.fromhex("eb14"),
     "xpack.initLicense: 启动时不再清掉 sync 字段为 0 的根证书行（保住本站根证书）",
     "initLicense"),

    # ------------------------------------------------------------------
    # 离线化补丁：删除在线验证 + 定时验证
    #
    # 面板的授权链路原本依赖 1p-cert.0rz.li（Cloudflare 后面，当前 530）。
    # 只要有一次出网失败，updateStatus 就会拿不到授权内容，紧接着
    # license_snapshot.RefreshWithLog 用空快照覆盖启动时建好的快照，
    # /licenses/status 于是永远返回空 —— 面板显示「社区版」。
    #
    # 这里把「出网」和「定时校验」两件事从内核里摘掉，授权完全本地生效。
    # 注意：不短路 CheckInLocal / 解密逻辑，否则字段会被二次加密写成乱码。
    # ------------------------------------------------------------------
    ("P5a.license_snapshot.refresh.ignore_err",
     0x00F149F5, bytes.fromhex("0f8526010000"), bytes.fromhex("909090909090"),
     "license_snapshot.Refresh: 忽略 bind_node_id 解析错误（不再整行跳过）",
     "refresh"),

    ("P5b.license_snapshot.refresh.local_fallback",
     0x00F14A03, bytes.fromhex("0f8418010000"), bytes.fromhex("b80100000090"),
     "license_snapshot.Refresh: 节点号解析为 0 时回退本地节点 1（快照不再为空）",
     "refresh"),

    ("P6.cron.license_check.disable",
     0x0107F4C0, bytes.fromhex("4c8da424c8fdffff4d3b6610"),
     bytes.fromhex("c39090909090909090909090"),
     "cron/jobs.(*LicenseCheck).Run 直接返回：删除每日 0:23 的定时授权校验任务",
     "symbol"),

    ("P7.license_helper.report.disable",
     0x00EF14E0, bytes.fromhex("4c8da424b8fdffff4d3b6610"),
     bytes.fromhex("31c031dbc390909090909090"),
     "license_helper.Report 直接返回 nil：删除向授权服务器上报（出网）",
     "symbol"),

    ("P8.license_helper.checkversion.disable",
     0x00EEFCC0, bytes.fromhex("48894424084885db0f84d300"),
     bytes.fromhex("31c0c3909090909090909090"),
     "license_helper.CheckVersion 恒 false：删除在线版本校验（出网）",
     "symbol"),

    ("P9.alert.sync_sms.disable",
     0x00F31820, bytes.fromhex("493b66100f86080100005548"),
     bytes.fromhex("c39090909090909090909090"),
     "alert.SyncSmsCountAsync 直接返回：删除在线短信计数同步（出网）",
     "symbol"),

    ("P10.license_helper.egress.disable",
     0x00EF1DA0, bytes.fromhex("4c8da42400feffff4d3b6610"),
     bytes.fromhex("31c031db31c931ff31f6c390"),
     "license_helper.handleRequest 直接返回空：切断唯一出网出口（所有授权服务器 HTTP 请求）",
     "symbol"),
]

# 符号定位用：补丁名 -> Go 符号后缀（换版本/架构时用符号重新定位）
SYMBOL_SUFFIX = {
    "P6.cron.license_check.disable": "core/xpack/cron/jobs.(*LicenseCheck).Run",
    "P7.license_helper.report.disable": "core/xpack/utils/license_helper.Report",
    "P8.license_helper.checkversion.disable": "core/xpack/utils/license_helper.CheckVersion",
    "P9.alert.sync_sms.disable": "core/xpack/utils/alert.SyncSmsCountAsync",
    "P10.license_helper.egress.disable": "core/xpack/utils/license_helper.handleRequest",
}

# ---------------------------------------------------------------------------
# arm64（AArch64）补丁字节。
#
# 表里的 orig/patched 是 amd64 指令；arm64 指令编码完全不同，所以这里按架构
# 覆盖：{补丁名: (原值字节数, arm64 替换字节)}。原值从目标二进制现场读取。
#
#   ret              = 0xd65f03c0 -> c0 03 5f d6
#   nop              = 0xd503201f -> 1f 20 03 d5
#   mov xN, xzr      = 0xaa1f03eN -> eN 03 1f aa
#   mov x0, #1       = 0xd2800020 -> 20 00 80 d2
# ---------------------------------------------------------------------------
_A64_RET = bytes.fromhex("c0035fd6")
_A64_NOP = bytes.fromhex("1f2003d5")
_A64_X0Z = bytes.fromhex("e0031faa")
_A64_X1Z = bytes.fromhex("e1031faa")
_A64_X2Z = bytes.fromhex("e2031faa")
_A64_X3Z = bytes.fromhex("e3031faa")

ARM64_PATCHES = {
    # Refresh: cbnz x1,<skip> -> nop ；cbz x0,<skip> -> mov x0,#1
    "P5a.license_snapshot.refresh.ignore_err": (4, _A64_NOP),
    "P5b.license_snapshot.refresh.local_fallback": (4, bytes.fromhex("200080d2")),
    # 无返回值：直接 ret
    "P6.cron.license_check.disable": (24, _A64_RET + _A64_NOP * 5),
    "P9.alert.sync_sms.disable": (24, _A64_RET + _A64_NOP * 5),
    # 返回 error（x0/x1）：清零后 ret
    "P7.license_helper.report.disable": (24, _A64_X0Z + _A64_X1Z + _A64_RET + _A64_NOP * 3),
    # 返回 bool（x0）：清零后 ret
    "P8.license_helper.checkversion.disable": (24, _A64_X0Z + _A64_RET + _A64_NOP * 4),
    # 返回 ([]byte, error)：x0..x3 清零后 ret
    "P10.license_helper.egress.disable": (32, _A64_X0Z + _A64_X1Z + _A64_X2Z + _A64_X3Z + _A64_RET + _A64_NOP * 3),
}


# arm64 官方 v2.3.2 的原值。仅用于「已经是打过补丁的镜像」时（--verify）判定，
# 换版本时若不匹配会被现场读取的值取代，不会误判。
ARM64_ORIG = {
    "P5a.license_snapshot.refresh.ignore_err": "610600b5",
    "P5b.license_snapshot.refresh.local_fallback": "400600b4",
    "P6.cron.license_check.disable": "900b40f9f10309d13f0210eba9070054f4030bd19dfa3fa9",
    "P7.license_helper.report.disable": "900b40f9f14309d13f0210ebc9180054f4430bd19dfa3fa9",
    "P8.license_helper.checkversion.disable": "900b40f9ff6330ebe90b0054fe0f1ef8fd831ff8fd2300d1",
    "P9.alert.sync_sms.disable": "900b40f9ff6330ebe9070054fe0f1bf8fd831ff8fd2300d1",
    "P10.license_helper.egress.disable": "900b40f9f14308d13f0210ebe98e0054f4430ad19dfa3fa99f020091fd2300d1",
}


def arch_bytes(data, name, off, orig, patched):
    """按目标架构返回 (orig, patched)；arm64 用 ARM64_PATCHES 覆盖并现场取原值。"""
    spec = ARM64_PATCHES.get(name)
    if spec is None or detect_machine(data) != 183:
        return orig, patched
    n, arm_patched = spec
    cur = data[off:off + n]
    if cur == arm_patched:
        # 已经是打过补丁的镜像：原值回退到固化表，否则 --verify 会把它当成未打补丁
        fixed = ARM64_ORIG.get(name)
        if fixed and len(bytes.fromhex(fixed)) == n:
            return bytes.fromhex(fixed), arm_patched
    return cur, arm_patched

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
    if data[:4] != b"\x7fELF" or data[4] != 2:
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
    except Exception:                        # noqa: BLE001
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


# 这些补丁定位不到就不能出产物（缺了会掉授权），必须显式 --force 才放行
REQUIRED = ("C7.",)

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


def _sym_off(data, suffix):
    """按 Go 符号名后缀找函数体起始的文件偏移；找不到返回 None。"""
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
    except Exception:                        # noqa: BLE001
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    for s in syms:
        if s["name"].endswith(suffix):
            return s["off"]
    return None


def _refresh_offsets_arm64(data, syms):
    """arm64 版：在 Refresh 里定位 Atoi 之后的 cbnz x1 / cbz x0。

    目标指令序列（AArch64）：
        bl    strconv.Atoi      ; 0x94000000 | imm26
        cbnz  x1, <skip>        ; 0xB5000000 | imm19<<5 | 1   <- 解析出错就跳过
        cbz   x0, <skip>        ; 0xB4000000 | imm19<<5 | 0   <- 节点号为 0 也跳过

    bl 的 imm26 是相对 vaddr 的，而符号表给的是文件偏移，两者相差一个段偏移，
    直接换算容易出错，所以这里改用纯结构匹配：两条跳转的目标必须是同一条指令
    （cbnz 在 cbz 前 4 字节，所以 imm19 恰好相差 1）。
    返回 (cbnz_off, cbz_off)；定位不到返回 (None, None)。
    """
    fn = next((s for s in syms
               if s["name"].endswith("core/xpack/utils/license_snapshot.Refresh")), None)
    if fn is None:
        return None, None
    lo, hi = fn["off"], fn["off"] + fn["size"]
    hits = []
    for off in range(lo, hi - 12, 4):
        w0 = struct.unpack_from("<I", data, off)[0]
        if (w0 >> 26) != 0x25:                          # bl
            continue
        w1 = struct.unpack_from("<I", data, off + 4)[0]
        w2 = struct.unpack_from("<I", data, off + 8)[0]
        if (w1 >> 24) != 0xB5 or (w1 & 0x1F) != 1:      # cbnz x1
            continue
        if (w2 >> 24) != 0xB4 or (w2 & 0x1F) != 0:      # cbz x0
            continue
        if ((w1 >> 5) & 0x7FFFF) != ((w2 >> 5) & 0x7FFFF) + 1:
            continue                                    # 必须跳到同一条指令
        hits.append((off + 4, off + 8))
    return hits[0] if len(hits) == 1 else (None, None)


def _refresh_offsets(data):
    """在 license_snapshot.Refresh 里定位 bind_node_id 解析后的两处条件跳转。

    目标指令序列（amd64）：
        call  strconv.Atoi
        test  rbx,rbx ; jne <skip>          <- 解析出错就跳过该行
        nop5
        test  rax,rax ; je  <skip>          <- 节点号为 0 也跳过该行
    返回 (jne_off, je_off)；定位不到返回 (None, None)。
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gosym import read_syms          # noqa: PLC0415
    except Exception:                        # noqa: BLE001
        return None, None
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(data)
            tmp = fh.name
        _d, syms = read_syms(tmp)
    except Exception:                        # noqa: BLE001
        return None, None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    if detect_machine(data) == 183:
        return _refresh_offsets_arm64(data, syms)
    if detect_machine(data) != 62:            # 只对 amd64 / arm64 做指令级定位
        return None, None
    fn = next((s for s in syms
               if s["name"].endswith("core/xpack/utils/license_snapshot.Refresh")), None)
    if fn is None:
        return None, None
    lo, hi = fn["off"], fn["off"] + fn["size"]
    atoi = next((s for s in syms if s["name"].endswith("strconv.Atoi")), None)
    if atoi is None:
        return None, None
    atoi_va = atoi["entry"] + 0x401000
    for off in range(lo, hi - 32, 1):
        if data[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", data, off + 1)[0]
        if (off + 0x400000) + 5 + rel != atoi_va:
            continue
        p = off + 5
        if data[p:p + 3] != b"\x48\x85\xdb":           # test rbx,rbx
            continue
        if data[p + 3:p + 5] != b"\x0f\x85":           # jne rel32
            continue
        jne_off = p + 3
        q = jne_off + 6
        if data[q:q + 5] == b"\x0f\x1f\x44\x00\x00":   # nopl 0x0(%rax,%rax,1)
            q += 5
        if data[q:q + 3] != b"\x48\x85\xc0":           # test rax,rax
            continue
        if data[q + 3:q + 5] != b"\x0f\x84":           # je rel32
            continue
        return jne_off, q + 3
    return None, None


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
    if how == "symbol":
        # 函数入口补丁：按符号名重新定位（换版本/架构时偏移会变）
        suffix = SYMBOL_SUFFIX.get(name)
        if suffix:
            alt = _sym_off(data, suffix)
            if alt is not None:
                return alt
    if how == "refresh":
        jne_off, je_off = _refresh_offsets(data)
        return jne_off if name.startswith("P5a") else je_off
    return None

# 旧版「状态伪造」补丁：全部删除。
#
# 这些补丁不改变授权来源，只把面板的状态判断短路掉，直接造成
#   * 没导入证书也显示「专业版」
#   * 授权表里的订阅授权 ID / 被授权方 / 版本 是乱码（CheckInLocal 被短路后
#     没有解密，字段被二次加密写库）
# 现在的做法与官方一致：只替换内置根证书指纹 + 授权服务器地址，
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
    out = []
    fp = root_fingerprint(cert_path)
    base = license_base_bytes(remote_base)
    if base is None:
        raise SystemExit("!! 授权服务器基地址超过 33 字节（最长 33 字符），例如 "
                         "https://你的域名/api/v1/")
    machine = detect_machine(data)
    for name, off, orig, patched, comment, how in PATCHES:
        if machine == 183 and name in ARM64_OFFSETS:
            off = ARM64_OFFSETS[name]    # arm64 用自己固化的偏移（换版本再靠字面量重定位）
        if name.startswith(("P3.", "P4.")):
            patched = base               # 线上授权：基地址始终写成签发站（默认 1p-cert.0rz.li）
        if name.startswith(("P1.", "P2.")):
            # 内置根证书指纹 -> 本站根证书指纹（等长 64 字符十六进制）
            if fp is None or len(fp) != 64:
                continue                      # 没有签发站私钥材料时跳过，保持官方校验
            patched = fp
        if name.startswith("C7."):
            # C7 的偏移/原值/补丁值随架构不同（amd64 2 字节，arm64 4 字节）
            off, orig, patched = c7_spec(data)
        if orig is not None and len(orig) != len(patched):
            raise SystemExit("patch %s length mismatch %d != %d"
                             % (name, len(orig), len(patched)))
        real = _resolve(data, name, off, orig, patched, how)
        if real is None:
            if verbose:
                print("!! %s: 固化偏移 %#x 与字面量都对不上，这份二进制无法定位该补丁"
                      % (name, off))
            _MISSING.append(name)
            continue
        if real != off and verbose:
            print("   %s: 偏移自动重定位 %#x -> %#x（版本/架构不同）"
                  % (name, off, real))
        if name in ARM64_PATCHES:
            # 离线化补丁：arm64 指令编码与 amd64 不同，定位到之后再按架构换字节
            orig, patched = arch_bytes(data, name, real, orig, patched)
        out.append((name, real, orig, patched, comment))
    return out


# pristine image, needed by patches whose original bytes are context dependent
#
# 容器部署时 build/ 目录不在镜像里，所以按候选路径依次查找；
# 都找不到也不抛异常（PRISTINE=None），交由调用方自己提供 data。
def load_pristine():
    cands = []
    if os.environ.get("ORIG"):
        cands.append(os.path.join(os.environ["ORIG"], "core.orig"))
    cands += [
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "build", "orig", "core.orig"),
        PANEL_ROOT + "/orig/core.orig",
        CORE_BIN,
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
    ap.add_argument("--in", dest="src", default=CORE_BIN)
    ap.add_argument("--out", dest="dst", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--patch", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--orig", dest="orig", default="build/orig/core.orig")
    ap.add_argument("--manifest", dest="manifest", default="build/core.manifest.json")
    ap.add_argument("--remote-base", dest="remote_base", default=None,
                    metavar="URL",
                    help="覆盖写死的授权服务器地址（≤33 字符，如 https://abc.com/api/v1/）；"
                         "不填默认写死 https://1p-cert.0rz.li/api/v1/")
    ap.add_argument("--force", action="store_true",
                    help="即使必需补丁（C7）定位不到也照常输出")
    args = ap.parse_args()

    if args.list:
        for name, off, orig, patched, comment, _how in PATCHES:
            n = len(patched) if patched is not None else len(orig or b"")
            print("%-38s file=%#010x len=%2d  %s" % (name, off, n, comment))
        print("   授权基地址: %s" % license_base_bytes(None).decode("ascii", "replace"))
        return 0

    if args.verify:
        data = open(args.src, "rb").read()
        print("binary : %s" % args.src)
        print("sha256 : %s" % sha256(args.src))
        print("size   : %d" % len(data))
        bad = 0
        TABLE = build_table(data, verbose=False)   # 按这份文件自己定位
        states = locate(data)
        for name, off, st, cur in states:
            mark = {"original": "ORIG", "patched": "PATCHED",
                    "patched(custom)": "PATCHED*", "unknown": "!! UNKNOWN"}[st]
            if st in ("original", "unknown"):
                bad += 1
            print("  %-38s %#010x  %-10s %s" % (name, off, mark, _render(name, cur)))
        print("\nstate  : %s" % ("all patches present" if bad == 0
                                 else "未打补丁/异常 (%d)" % bad))
        # 授权服务器基地址：仅供参考，不参与判定（偏移按本文件重定位后的 TABLE 取）
        for nm, off, orig, patched, _ in TABLE:
            if not nm.startswith(("P3.", "P4.")):
                continue
            cur = data[off:off + len(patched)]
            tag = "官方原值（未打补丁）" if cur == orig else "已写死：" + cur.decode("ascii", "replace")
            print("  %-12s %#010x  %s" % (nm, off, tag))
        return 0 if bad == 0 else 1

    if args.restore:
        src = args.orig if os.path.exists(args.orig) else args.src
        data = open(src, "rb").read()
        table = build_table(bytes(data), remote_base=args.remote_base)
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
        data = bytearray(open(src, "rb").read())
        # 按**输入文件**自己定位补丁（换版本/架构时固化偏移会失效）
        table = build_table(bytes(data), remote_base=args.remote_base)
        applied, skipped = [], []
        for name, off, orig, patched, _ in table:
            cur = bytes(data[off:off + len(patched)])
            if cur == patched:
                skipped.append(name)
                continue
            if orig is not None and cur != orig:
                print("!! %s: unexpected bytes at %#x: %s" % (name, off, cur.hex()))
                return 2
            data[off:off + len(patched)] = patched
            applied.append(name)

        miss = required_missing()
        if miss and not args.force:
            print("!! 必需补丁定位不到：%s" % ", ".join(miss))
            print("   这份内核（换版本/换架构）暂时不适配，未输出产物。")
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
            "tool": "patch_core.py",
            "version": "core v2.3.2 (sha256 f1265a4fadeaab3d7066dd71e3c6904ac54bb687baab1b205a23c369abb61cac)",
            "source": src,
            "source_sha256": sha256(args.orig),
            "output": dst,
            "output_sha256": sha256(dst),
            "product_pro": PRODUCT_PRO_TEXT,
            "applied": applied,
            "already_patched": skipped,
            "patches": [{"name": n, "file_offset": hex(o),
                         "orig": (o2.hex() if o2 else None),
                         "patch": p.hex(), "note": c}
                        for n, o, o2, p, c in table],
        }
        with open(args.manifest, "w") as fh:
            json.dump(man, fh, indent=2, ensure_ascii=False)

        print("applied  : %s" % (", ".join(applied) or "(none)"))
        print("skipped  : %s" % (", ".join(skipped) or "(none)"))
        print("output   : %s" % dst)
        print("sha256   : %s" % man["output_sha256"])
        print("manifest : %s" % args.manifest)
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
