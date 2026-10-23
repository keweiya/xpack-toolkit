#!/usr/bin/env python3
"""1Panel agent (1panel-agent) X-Pack unlocker —— 符号 + 代码模式定位（版本解耦）。

Agent 的 X-Pack 开关是一个包级 bool，由 /opt/1panel/conf/panel.json 播种：

    github.com/1Panel-dev/1Panel/agent/xpack/utils/edition -> isXpack（byte，.noptrbss）

三个写入点和七个读取点碰这个字节；`IsXpack()` 是导出访问器。全部改动等长覆盖，
不改变二进制尺寸：

    A1  (*multiNodeHelper).IsXpack          入口 -> return true（符号定位）
    A2  xpack.initXpack     授权分支 guard   -> 去掉 `if !isXpack { 跳过 }`
    A3  xpack.initXpack     日志取值         -> 打印 isXpack=true
    A4  xpack.initXpack     isXpack 写入     -> 恒写 1
    A5  common_xpack.InitLicenseInfo 写入    -> isXpack 恒写 1
    A6  app/service.syncNodeInfo 写入        -> isXpack 恒写 1
    A7  app/service.syncNodeInfo 分支        -> 恒走 InitXpack()，永不 ResetXpack()
    A8  alert_xpack.GetLicenseAlert         入口 -> return nil（不再弹授权告警）

定位策略与内核补丁一致：先用 Go pclntab 的符号名把函数找出来（改名会直接失败，
不会误改），再在函数字节范围内按代码模式唯一定位具体指令。官方发新版后通常不用
重新搜寻偏移，跑一次 `--verify` 即可确认。

Usage:
  python3 tools/patch_agent.py --list
  python3 tools/patch_agent.py --verify [--in BIN]
  python3 tools/patch_agent.py --patch  [--in BIN] [--out BIN]
  python3 tools/patch_agent.py --restore [--in BIN] [--out BIN]
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile

NOP = b"\x90"

# 架构：ELF e_machine -> 名称
ELF_MACHINES = {62: "amd64", 183: "arm64"}

# 必须命中的站点（A7 随版本可选：判断条件可能已经被 A6 的改写覆盖）
REQUIRED_SITES = ("A1.IsXpack.return_true", "A2.initXpack.drop_guard",
                  "A3.initXpack.log_true", "A4.initXpack.store_true",
                  "A5.InitLicenseInfo.store_true", "A6.syncNodeInfo.store_true")
SUF_NODE_INFO = "app/service.syncNodeInfo"

# 入口桩：整函数直接返回常量，覆盖入口即可（长度不超过官方入口指令）。
#   amd64: mov eax,1; nop; nop; ret   / xor eax,eax; xor ebx,ebx; xor ecx,ecx; ret
#   arm64: mov w0,#1; ret; nop       / mov x0..x2,xzr; ret
ENTRY_STUBS = {
    "amd64": [
        ("A1.IsXpack.return_true", ".(*multiNodeHelper).IsXpack",
         bytes.fromhex("b8010000009090c3"),
         "(*multiNodeHelper).IsXpack -> true"),
        ("A8.GetLicenseAlert.return_nil", "alert_xpack.GetLicenseAlert",
         bytes.fromhex("31c031db31c9c3"),
         "alert_xpack.GetLicenseAlert -> nil"),
    ],
    "arm64": [
        ("A1.IsXpack.return_true", ".(*multiNodeHelper).IsXpack",
         bytes.fromhex("20008052c0035fd61f2003d5"),
         "(*multiNodeHelper).IsXpack -> true"),
        ("A8.GetLicenseAlert.return_nil", "alert_xpack.GetLicenseAlert",
         bytes.fromhex("aa1f03e0aa1f03e1aa1f03e2d65f03c0"),
         "alert_xpack.GetLicenseAlert -> nil"),
    ],
}

# 代码模式补丁：(名称, 所在函数符号后缀, 原始字节, 补丁字节, 说明)
# 等长覆盖；arm64 改条件分支只需换一条指令，所以 A2/A7 也放在这里。
PATTERN_SITES = {
    "amd64": [
        ("A3.initXpack.log_true", "xpack.initXpack",
         bytes.fromhex("440fb690980000004c8d1d"),
         bytes.fromhex("41ba0100000090904c8d1d"),
         "日志行读取 isXpack=true"),
        ("A4.initXpack.store_true", "xpack.initXpack",
         bytes.fromhex("0fb692980000008815"),
         bytes.fromhex("ba0100000090908815"),
         "isXpack 全局 <- 1"),
        ("A5.InitLicenseInfo.store_true", "common_xpack.InitLicenseInfo",
         bytes.fromhex("0fb680980000008805"),
         bytes.fromhex("b80100000090908805"),
         "common_xpack.InitLicenseInfo: isXpack 全局 <- 1"),
        ("A6.syncNodeInfo.store_true", "app/service.syncNodeInfo",
         bytes.fromhex("0fb68424080100008805"),
         bytes.fromhex("b8010000009090908805"),
         "app/service.syncNodeInfo: isXpack 全局 <- 1"),
    ],
    "arm64": [],
}

# 需要「先锚定比较指令，再改它后面的条件跳转」的站点：
# 只有 amd64 需要（短/长两种跳转编码 + 位移字节会变），arm64 一条指令即可。
BRANCH_SITES = {
    "amd64": [
        ("A2.initXpack.drop_guard", "xpack.initXpack",
         bytes.fromhex("80ba9800000000"),          # cmpb $0x0, 0x98(%rdx)
         "xpack.initXpack: 永不跳过 X-Pack 初始化块", True),
    ],
    "arm64": [],
}

# syncNodeInfo 的守卫分支形状随版本变过：
#   v2.4.0  cmpb $0x0,0x108(%rsp) + je        —— 直接比较栈上的副本
#   v2.4.1  movzbl 0x108(%rsp),%eax; mov %al,<isXpack>; test %al,%al + je
# 后者判断的正是 A6 改写的那条读指令，改完自然不走 ResetXpack，所以 A7 是
# 「能找到就抹掉、找不到就跳过」的可选站点。
A7_ANCHOR = bytes.fromhex("80bc240801000000")


def _x86_guard_branch(data, start, limit=32, saw_compare=False):
    """从 start 往后找「测试刚写进去的值」的条件跳转，返回 (offset, length)。"""
    pos = start
    end = min(start + limit, len(data) - 2)
    while pos < end:
        opcode = data[pos]
        if opcode in (0x84, 0x85) and (data[pos + 1] >> 6) == 3:
            saw_compare = True
            pos += 2
            continue
        if opcode == 0x80 and ((data[pos + 1] >> 3) & 7) == 7:
            modrm = data[pos + 1]
            mod = modrm >> 6
            size = 2 + (1 if (modrm & 7) == 4 else 0) + (1 if mod == 1 else 4 if mod == 2 else 0) + 1
            saw_compare = True
            pos += size
            continue
        if 0x70 <= opcode <= 0x7F and saw_compare:
            return pos, 2
        if opcode == 0x0F and data[pos + 1] in (0x84, 0x85) and saw_compare:
            return pos, 6
        break
    return None


def _nop_site(data, offset, length, name, note):
    orig = data[offset:offset + length]
    patch = b"\x90" * length
    return (name, offset, orig, patch, state_of(data, offset, patch, orig), note)


def _optional_branch_sites(data, syms, rows):
    """A7：抹掉 syncNodeInfo 里「走 ResetXpack」的那条分支。"""
    try:
        _func(syms, SUF_NODE_INFO)
    except ValueError:
        return []
    note = "syncNodeInfo: 恒调 InitXpack()，永不 ResetXpack()"
    sym = _func(syms, SUF_NODE_INFO)
    hits = _find_all(data, sym["off"], sym["off"] + sym["size"], A7_ANCHOR)
    anchor = hits[0] if len(hits) == 1 else None
    if anchor is not None:
        branch = _x86_guard_branch(data, anchor + len(A7_ANCHOR), saw_compare=True)
        if branch:
            return [_nop_site(data, branch[0], branch[1], "A7.syncNodeInfo.prefer_init", note)]
        return []
    store = next((row for row in rows if row[0] == "A6.syncNodeInfo.store_true"), None)
    if store is None:
        return []
    # 模式里只覆盖到写入指令的 opcode，后面还跟着 disp32，所以从几个可能的起点试一遍
    for delta in range(len(store[3]), len(store[3]) + 8):
        branch = _x86_guard_branch(data, store[1] + delta)
        if branch and branch[0] > store[1]:
            return [_nop_site(data, branch[0], branch[1],
                              "A7.syncNodeInfo.prefer_init", note)]
    return []



# --------------------------------------------------------------------------- #
# arm64：结构化解码定位（不写死偏移，跨版本复用）
#
# isXpack 全局字节的地址每个版本都不同（v2.3.2 是 adrp+2938，v2.4.0 是 adrp+1658），
# 所以不能像 amd64 那样固定字节模式。这里的做法是：
#   1. 从 IsXpack 自己的代码里解出全局地址（adrp + ldrb）；
#   2. 在 initXpack / InitLicenseInfo / syncNodeInfo 里找写这个地址的 strb，
#      再回溯拿到值来源那条 ldrb 的字段偏移；
#   3. 把这些函数里「读同一个字段」的 ldrb 全部换成 mov wN,#1。
# 顺带把授权分支（tbz）也一并消除——因为判断用的就是同一个字段。
# --------------------------------------------------------------------------- #
A64_TARGET_FUNCS = (
    ("xpack.initXpack", ("A3.initXpack.log_true", "A2.initXpack.drop_guard",
                         "A4.initXpack.store_true")),
    ("common_xpack.InitLicenseInfo", ("A5.InitLicenseInfo.store_true",)),
    ("app/service.syncNodeInfo", ("A6.syncNodeInfo.store_true",
                                  "A7.syncNodeInfo.prefer_init")),
)


def _a64_adrp(word, pc):
    """ADRP：返回 (目标页地址, Rd)。"""
    if word & 0x9F000000 != 0x90000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    immediate = (immhi << 2) | immlo
    if immediate & (1 << 20):
        immediate -= 1 << 21
    return ((pc & ~0xFFF) + (immediate << 12)) & 0xFFFFFFFFFFFF, word & 0x1F


def _a64_byte_mem(word):
    """LDRB / STRB (unsigned immediate)：返回 (kind, Rt, Rn, imm)。"""
    if word & 0xFFC00000 == 0x39400000:
        kind = "ldrb"
    elif word & 0xFFC00000 == 0x39000000:
        kind = "strb"
    else:
        return None
    return kind, word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF


def _a64_mov_one(reg):
    """MOV wN, #1（零扩展，等价于编译器生成的 movz）。"""
    return 0xD2800000 | (1 << 5) | (reg & 0x1F)


def _a64_words(data, sym):
    lo, hi = sym["off"], sym["off"] + sym["size"]
    return [(lo + i, struct.unpack_from("<I", data, lo + i)[0])
            for i in range(0, hi - lo - 3, 4)], lo


def _a64_global_byte(data, syms):
    """从 IsXpack 解出 isXpack 全局字节的绝对地址。"""
    sym = _func(syms, ".(*multiNodeHelper).IsXpack")
    words, lo = _a64_words(data, sym)
    page = None
    for off, word in words:
        adrp = _a64_adrp(word, sym["vaddr"] + (off - lo))
        if adrp:
            page = adrp
            continue
        mem = _a64_byte_mem(word)
        if page and mem and mem[0] == "ldrb" and mem[2] == page[1]:
            return (page[0] + mem[3]) & 0xFFFFFFFFFFFF
    raise ValueError("cannot resolve isXpack global byte from IsXpack()"
                     "（文件可能已打过补丁，请用 --orig 指向官方原件）")


def _a64_store_sites(data, syms, suffix, target):
    """函数内写 target 的 strb 站点：(offset, Rt, 值来源 ldrb 的字段偏移)。"""
    sym = _func(syms, suffix)
    words, lo = _a64_words(data, sym)
    pages = {}
    found = []
    for index, (off, word) in enumerate(words):
        adrp = _a64_adrp(word, sym["vaddr"] + (off - lo))
        if adrp:
            pages[adrp[1]] = adrp[0]
            continue
        mem = _a64_byte_mem(word)
        if not mem or mem[0] != "strb":
            continue
        base = pages.get(mem[2])
        if base is None or base + mem[3] != target:
            continue
        # 回溯：谁写了这个值寄存器 —— 拿到 (是否 SP 相对, 立即数) 这个「读法」
        source = None
        for back in range(index - 1, max(index - 9, -1), -1):
            src = _a64_byte_mem(words[back][1])
            if src and src[0] == "ldrb" and src[1] == mem[1]:
                source = (src[2] == 31, src[3])
                break
        found.append((off, mem[1], source))
    return found


def a64_sites(data, syms):
    """arm64 的 8 个站点：2 个入口桩 + 6 处 edition 字段读取。"""
    rows = [_entry(data, syms, name, suffix, stub, note)
            for name, suffix, stub, note in ENTRY_STUBS["arm64"]]
    target = _a64_global_byte(data, syms)

    for suffix, names in A64_TARGET_FUNCS:
        sources = {row[2] for row in _a64_store_sites(data, syms, suffix, target)}
        if len(sources) != 1 or None in sources:
            raise ValueError("cannot derive the edition read pattern in %s: %r"
                             % (suffix, sorted(str(item) for item in sources)))
        is_sp, field = sources.pop()
        sym = _func(syms, suffix)
        words, _lo = _a64_words(data, sym)
        reads = [(off, word) for off, word in words
                 if (lambda m: m and m[0] == "ldrb" and (m[2] == 31) == is_sp
                     and m[3] == field)(_a64_byte_mem(word))]
        # 末尾的名字是可选的：v2.4.1 起 syncNodeInfo 的守卫分支直接判读到的值，
        # 改完 A6 就自然生效，不需要单独的 A7 站点
        if len(reads) not in (len(names), len(names) - 1):
            raise ValueError("expected %d edition reads in %s, got %d"
                             % (len(names), suffix, len(reads)))
        for (off, word), name in zip(reads, names):
            rt = word & 0x1F
            orig = data[off:off + 4]
            patch = struct.pack("<I", _a64_mov_one(rt))
            rows.append((name, off, orig, patch, state_of(data, off, patch, orig),
                         "edition 读取恒为 1（isXpack=true）"))
    rows.sort(key=lambda row: row[1])
    names = [row[0] for row in rows]
    missing = [name for name in REQUIRED_SITES if name not in names]
    if missing or len(names) != len(set(names)):
        raise ValueError("missing required arm64 patch sites %r (found %r)" % (missing, names))
    return rows


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _symbols(data):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gosym import read_syms  # noqa: PLC0415

    tmp = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(data)
            tmp = fh.name
        _image, syms = read_syms(tmp)
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return syms


def _func(syms, suffix):
    matches = [sym for sym in syms if sym["name"].endswith(suffix)]
    if len(matches) != 1:
        raise ValueError("expected exactly one symbol ending with %r, got %d"
                         % (suffix, len(matches)))
    return matches[0]


def _find_all(data, lo, hi, pattern):
    hits = []
    pos = lo
    while True:
        pos = data.find(pattern, pos, hi)
        if pos < 0:
            return hits
        hits.append(pos)
        pos += 1


def _find_one(data, lo, hi, pattern, label):
    hits = _find_all(data, lo, hi, pattern)
    if len(hits) != 1:
        raise ValueError("expected exactly one %s, got %d" % (label, len(hits)))
    return hits[0]


def _site(data, syms, name, suffix, orig, patch, note):
    """在函数字节范围内唯一定位 orig（或已打的 patch），返回补丁站点。"""
    sym = _func(syms, suffix)
    lo, hi = sym["off"], sym["off"] + sym["size"]
    for pattern, state in ((orig, "original"), (patch, "patched")):
        hits = _find_all(data, lo, hi, pattern)
        if len(hits) == 1:
            return (name, hits[0], pattern, patch, state, note)
        if len(hits) > 1:
            raise ValueError("expected exactly one %s in %s, got %d"
                             % (name, suffix, len(hits)))
    raise ValueError("pattern for %s not found in %s (neither original nor patched)"
                     % (name, suffix))


def state_of(data, off, patch, orig=None):
    cur = data[off:off + len(patch)]
    if cur == patch:
        return "patched"
    if orig is not None:
        return "original" if data[off:off + len(orig)] == orig else "unknown"
    return "original"


def _entry(data, syms, name, suffix, stub, note):
    """入口桩：官方入口指令随版本变化，只要不是桩就视为原件。"""
    sym = _func(syms, suffix)
    off = sym["off"]
    if off + len(stub) > len(data):
        raise ValueError("symbol %s truncated" % name)
    return (name, off, data[off:off + len(stub)], stub, state_of(data, off, stub), note)


def _branch(data, syms, name, suffix, anchor, note, allow_long=True):
    """锚定比较指令 → 找后面的条件跳转（或已抹平的 NOP）→ 返回补丁站点。"""
    sym = _func(syms, suffix)
    lo, hi = sym["off"], sym["off"] + sym["size"]
    start = _find_one(data, lo, hi, anchor, "anchor for %s in %s" % (name, suffix))
    lookup = start + len(anchor)
    window = range(lookup, min(lookup + 8, hi))

    # 官方原样：长跳转优先，其次短跳转；已打过补丁：等长 NOP 序列。
    probes = []
    if allow_long:
        probes.append((b"\x0f\x84", 6, "original"))
        probes.append((NOP * 6, 6, "patched"))
    probes.append((b"\x74", 2, "original"))
    probes.append((NOP * 2, 2, "patched"))
    for pattern, length, state in probes:
        for pos in window:
            if data[pos:pos + len(pattern)] == pattern:
                # 短跳转/短 NOP 不能是别的指令的位移字节：要求后一字节非零。
                if length == 2 and data[pos + 2] == 0:
                    continue
                orig = data[pos:pos + length]
                patch = NOP * length
                return (name, pos, orig, patch, state, note)
    raise ValueError("no conditional jump found after anchor for %s" % name)


def machine(data):
    """按 ELF e_machine 判断架构。"""
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    number = struct.unpack_from("<H", data, 18)[0]
    arch = ELF_MACHINES.get(number)
    if arch is None:
        raise ValueError("unsupported ELF machine: %d" % number)
    return arch


def sites(data, syms=None, orig=None):
    """完整站点列表：(name, off, orig, patch, state, note)。

    orig 是「官方原件」：站点定位一律在原件上做（打完补丁的文件里，A1 入口、
    A7 分支这些位置已经看不出原样了），再按同一偏移在 data 里判状态。
    """
    reference = data if orig is None else orig
    arch = machine(reference)
    if syms is None:
        syms = _symbols(reference)
    rows = _locate_sites(reference, arch, syms)
    if orig is None:
        return rows
    return [(name, off, data[off:off + len(patch)], patch,
             state_of(data, off, patch, cur), note)
            for name, off, cur, patch, _state, note in rows]


def _locate_sites(reference, arch, syms):
    if arch == "arm64":
        return a64_sites(reference, syms)
    rows = [_entry(reference, syms, name, suffix, stub, note)
            for name, suffix, stub, note in ENTRY_STUBS[arch]]
    rows.extend(_site(reference, syms, name, suffix, orig, patch, note)
                for name, suffix, orig, patch, note in PATTERN_SITES[arch])
    for name, suffix, anchor, note, allow_long in BRANCH_SITES[arch]:
        rows.append(_branch(reference, syms, name, suffix, anchor, note,
                            allow_long=allow_long))
    rows.extend(_optional_branch_sites(reference, syms, rows))
    rows.sort(key=lambda row: row[1])
    names = [row[0] for row in rows]
    missing = [name for name in REQUIRED_SITES if name not in names]
    if missing or len(names) != len(set(names)):
        raise ValueError("missing required patch sites %r (found %r)" % (missing, names))
    return rows


def locate(data, syms=None, orig=None):
    """与 release.py 约定的接口：(name, file_offset, state, current_bytes)。"""
    return [(name, off, state, cur)
            for name, off, cur, _patch, state, _note in sites(data, syms, orig)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="/usr/local/bin/1panel-agent")
    ap.add_argument("--out", dest="dst", default=None)
    ap.add_argument("--orig", default=None,
                    help="官方原件路径：--patch 时作为原始备份，--verify 时作为解析参考")
    ap.add_argument("--manifest", default="build/1panel-agent.manifest.json")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--patch", action="store_true")
    ap.add_argument("--restore", action="store_true")
    args = ap.parse_args()

    if args.list:
        for arch in ("amd64", "arm64"):
            print("[%s] 入口桩（Go 符号定位，等长覆盖）:" % arch)
            for name, sym, stub, note in ENTRY_STUBS[arch]:
                print("  %-34s symbol=…%-30s patch=%s  %s"
                      % (name, sym, stub.hex(), note))
            print("[%s] 代码模式（函数内唯一定位）:" % arch)
            for name, sym, orig, patch, note in PATTERN_SITES[arch]:
                print("  %-34s %s -> %s  %s" % (name, orig.hex(), patch.hex(), note))
            for name, sym, anchor, note, _long in BRANCH_SITES[arch]:
                print("  %-34s anchor=%s -> 抹掉授权分支跳转  %s"
                      % (name, anchor.hex(), note))
            print()
        return 0

    if args.verify:
        data = open(args.src, "rb").read()
        print("binary : %s" % args.src)
        print("sha256 : %s" % sha256(args.src))
        print("size   : %d" % len(data))
        reference = None
        if args.orig:
            if not os.path.exists(args.orig):
                print("!! missing pristine reference: %s" % args.orig)
                return 2
            reference = open(args.orig, "rb").read()
            print("reference: %s" % args.orig)
        try:
            rows = sites(data, orig=reference)
        except (ValueError, OSError) as exc:
            print("!! %s" % exc)
            return 1
        bad = 0
        for name, off, cur, _patch, state, _note in rows:
            if state != "patched":
                bad += 1
            print("  %-34s off=%#010x  %-9s %s" % (name, off, state, cur[:16].hex()))
        print("\nstate  : %s" % ("all patches present" if bad == 0
                                 else "patches missing (%d)" % bad))
        return 0 if bad == 0 else 1

    if args.restore:
        if not os.path.exists(args.orig):
            print("!! missing pristine copy: %s" % args.orig)
            return 2
        out = args.dst or args.src
        shutil.copy2(args.orig, out)
        os.chmod(out, 0o755)
        print("restored %s -> %s (sha256 %s)" % (args.orig, out, sha256(out)))
        return 0

    if args.patch:
        src, dst = args.src, args.dst or args.src
        args.orig = args.orig or "build/orig/1panel-agent.orig"
        data = bytearray(open(src, "rb").read())
        try:
            rows = sites(bytes(data))
        except (ValueError, OSError) as exc:
            print("!! %s" % exc)
            return 2

        applied, skipped = [], []
        for name, off, cur, patch, state, _note in rows:
            if state == "patched":
                skipped.append(name)
                continue
            if state != "original":
                print("!! %s: unexpected bytes at %#x: %s" % (name, off, cur.hex()))
                return 2
            data[off:off + len(patch)] = patch
            applied.append(name)

        if not applied and skipped:
            print("already patched: %s" % ", ".join(skipped))
            print("output   : %s (unchanged)" % dst)
            return 0

        os.makedirs(os.path.dirname(os.path.abspath(args.orig)), exist_ok=True)
        if not os.path.exists(args.orig):
            shutil.copy2(src, args.orig)
            print("pristine copy -> %s" % args.orig)
        open(dst, "wb").write(bytes(data))
        os.chmod(dst, 0o755)

        man = {
            "tool": "patch_agent.py",
            "version": "1panel-agent (symbol+pattern located)",
            "source": src,
            "source_sha256": sha256(args.orig),
            "output": dst,
            "output_sha256": sha256(dst),
            "applied": applied,
            "already_patched": skipped,
            "patches": [{"name": name, "file_offset": hex(off), "orig": cur.hex(),
                         "patch": patch.hex(), "note": note}
                        for name, off, cur, patch, _state, note in rows],
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
