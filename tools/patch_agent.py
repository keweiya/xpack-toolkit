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
import sys
import tempfile

NOP = b"\x90"

# 入口桩：整函数直接返回常量，覆盖入口即可（长度与官方入口指令一致）。
ENTRY_STUBS = [
    ("A1.IsXpack.return_true", ".(*multiNodeHelper).IsXpack",
     bytes.fromhex("b8010000009090c3"),
     "(*multiNodeHelper).IsXpack -> true"),
    ("A8.GetLicenseAlert.return_nil", "alert_xpack.GetLicenseAlert",
     bytes.fromhex("31c031db31c9c3"),
     "alert_xpack.GetLicenseAlert -> nil"),
]

# 代码模式补丁：(名称, 所在函数符号后缀, 原始字节, 补丁字节, 说明)
PATTERN_SITES = [
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
]

# 分支补丁：先锚定比较指令，再改它后面的条件跳转。
A2_NAME = "A2.initXpack.drop_guard"
A2_FUNC = "xpack.initXpack"
A2_ANCHOR = bytes.fromhex("80ba9800000000")      # cmpb $0x0, 0x98(%rdx)
A2_NOTE = "xpack.initXpack: 永不跳过 X-Pack 初始化块"

A7_NAME = "A7.syncNodeInfo.prefer_init"
A7_FUNC = "app/service.syncNodeInfo"
A7_ANCHOR = bytes.fromhex("80bc240801000000")    # cmpb $0x0, 0x108(%rsp)
A7_NOTE = "syncNodeInfo: 恒调 InitXpack()，永不 ResetXpack()"


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


def sites(data, syms=None):
    """完整站点列表：(name, off, orig, patch, state, note)，共 8 条。"""
    if syms is None:
        syms = _symbols(data)
    rows = [_entry(data, syms, name, suffix, stub, note)
            for name, suffix, stub, note in ENTRY_STUBS]
    rows.append(_branch(data, syms, A2_NAME, A2_FUNC, A2_ANCHOR, A2_NOTE))
    rows.extend(_site(data, syms, name, suffix, orig, patch, note)
                for name, suffix, orig, patch, note in PATTERN_SITES)
    rows.append(_branch(data, syms, A7_NAME, A7_FUNC, A7_ANCHOR, A7_NOTE,
                        allow_long=False))
    rows.sort(key=lambda row: row[1])
    names = [row[0] for row in rows]
    if len(names) != 8 or len(set(names)) != 8:
        raise ValueError("expected eight unique patch sites, got %r" % (names,))
    return rows


def locate(data, syms=None):
    """与 release.py 约定的接口：(name, file_offset, state, current_bytes)。"""
    return [(name, off, state, cur) for name, off, cur, _patch, state, _note in sites(data, syms)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="/usr/local/bin/1panel-agent")
    ap.add_argument("--out", dest="dst", default=None)
    ap.add_argument("--orig", default="build/orig/1panel-agent.orig")
    ap.add_argument("--manifest", default="build/1panel-agent.manifest.json")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--patch", action="store_true")
    ap.add_argument("--restore", action="store_true")
    args = ap.parse_args()

    if args.list:
        print("入口桩（Go 符号定位，等长覆盖）:")
        for name, sym, stub, note in ENTRY_STUBS:
            print("  %-34s symbol=…%-30s patch=%s  %s" % (name, sym, stub.hex(), note))
        print("代码模式（函数内唯一定位）:")
        print("  %-34s anchor=%s -> 抹掉授权分支跳转" % (A2_NAME, A2_ANCHOR.hex()))
        for name, sym, orig, patch, note in PATTERN_SITES:
            print("  %-34s %s  %s" % (name, orig.hex(), note))
        print("  %-34s anchor=%s -> 恒走 InitXpack()" % (A7_NAME, A7_ANCHOR.hex()))
        return 0

    if args.verify:
        data = open(args.src, "rb").read()
        print("binary : %s" % args.src)
        print("sha256 : %s" % sha256(args.src))
        print("size   : %d" % len(data))
        try:
            rows = sites(data)
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
