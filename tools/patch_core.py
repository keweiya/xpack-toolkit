#!/usr/bin/env python3
"""1Panel core (1panel-core) X-Pack 授权内核破解补丁器 —— 移除全部内核授权检查。

目标：内网本地使用的破解内核。内核启动后**不再执行任何授权校验**，不需要
宿主机额外签发/生成授权证书，也不需要把面板根证书换成第三方根证书。

实现方式：直接把授权门函数在入口处改写为「恒成功」的返回桩，等价于把下面这些
校验全部短路（与官方逻辑无关，官方代码不再被走到）：

    C1  middleware.checkLicense              授权中间件：放行（不 abort）
    C2  middleware.checkLicenseSyncFresh     同步新鲜度：恒 true + nil err
    C3  license_helper.CheckInLocal          本地签名/根证书校验：恒 nil err
    C4  license_helper.checkRootCertFingerprint  内置根指纹比对：恒 nil err
    C5  license_helper.EnsureFreeNodeBindAllowed 节点额度校验：恒 nil err
    C6  xpack/helper.(*licenseHelper).BindFree    免费节点绑定：恒 nil err
    C7  license_helper.Report                远端上报：恒 nil err（不回连）
    C8  license_helper.Unbind                远端解绑：恒 nil err（不回连）

所有目标函数都按 Go 符号名（pclntab）唯一定位，因此换 1Panel 版本 / 架构时
无需维护固化偏移；定位不到就拒绝输出破解内核，避免下发坏内核。

返回桩（等长/不等长均只覆盖函数入口，后续死代码不影响执行）：
    amd64  void     c3
    amd64  err      31 c0 31 db c3            （RAX:RBX = nil error 接口）
    amd64  bool_err b8 01 00 00 00 31 db 31 c9 c3 （AL=1, RBX:RCX = nil error）
    arm64  同语义的 movz/mov + ret 序列。

Usage:
  python3 tools/patch_core.py --list
  python3 tools/patch_core.py --patch  [--in BIN] [--out BIN]
  python3 tools/patch_core.py --verify [--in BIN]
  python3 tools/patch_core.py --restore [--in BIN] [--out BIN]
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import sys

# ---------------------------------------------------------------------------
# 目标函数：name -> (Go 符号后缀, 返回类型, 说明)
# ---------------------------------------------------------------------------
TARGETS = [
    ("C1.middleware.checkLicense.passthrough",
     "router/middleware.checkLicense", "void",
     "授权中间件直接放行，不再 abort 未授权请求"),

    ("C2.checkLicenseSyncFresh.return_true",
     "router/middleware.checkLicenseSyncFresh", "bool_err",
     "同步新鲜度恒为 true + nil err，避免触发远端重校验"),

    ("C3.CheckInLocal.return_ok",
     "utils/license_helper.CheckInLocal", "err",
     "本地签名/根证书校验恒成功（不再校验签名与内置根指纹）"),

    ("C4.checkRootCertFingerprint.return_ok",
     "utils/license_helper.checkRootCertFingerprint", "err",
     "内置根证书指纹比对恒通过"),

    ("C5.EnsureFreeNodeBindAllowed.return_ok",
     "utils/license_helper.EnsureFreeNodeBindAllowed", "err",
     "节点绑定额度校验恒通过（不受节点数限制）"),

    ("C6.BindFree.return_ok",
     "xpack/helper.(*licenseHelper).BindFree", "err",
     "免费节点绑定恒成功"),

    ("C7.Report.skip",
     "utils/license_helper.Report", "err",
     "跳过授权上报，不回连授权服务器"),

    ("C8.Unbind.skip",
     "utils/license_helper.Unbind", "err",
     "跳过远端解绑，不回连授权服务器"),
]

# 返回桩，按 (架构, 返回类型) 索引。所有 stub 都覆盖函数入口即可。
STUBS = {
    "amd64": {
        "void": b"\xc3",
        "err": b"\x31\xc0\x31\xdb\xc3",                       # xor eax,eax; xor ebx,ebx; ret
        "bool_err": b"\xb8\x01\x00\x00\x00\x31\xdb\x31\xc9\xc3",  # mov eax,1; xor ebx,ebx; xor ecx,ecx; ret
    },
    "arm64": {
        "void": bytes.fromhex("c0035fd6"),
        "err": bytes.fromhex("000080d2010080d2c0035fd6"),     # mov x0,#0; mov x1,#0; ret
        "bool_err": bytes.fromhex("200080d2010080d2020080d2c0035fd6"),  # mov x0,#1; mov x1,#0; mov x2,#0; ret
    },
}


def detect_machine(data):
    """ELF64 e_machine：62=x86-64，183=AArch64；非 ELF64 返回 None。"""
    if data is None or len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    end = "<" if data[5] == 1 else ">"
    return struct.unpack_from(end + "H", data, 0x12)[0]


def _suffix_unique(syms, suffix):
    matches = [s for s in syms if s["name"].endswith(suffix)]
    if len(matches) != 1:
        raise ValueError("expected exactly one symbol ending with %r, got %d"
                         % (suffix, len(matches)))
    return matches[0]


def locate(data):
    """按 Go 符号名定位每个目标函数，返回 [(name, off, orig_prologue, stub, note), ...]。

    ``orig_prologue`` 为函数入口处与 stub 等长的原始字节（用于 verify/restore）。
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gosym import read_syms  # noqa: PLC0415

    machine = detect_machine(data)
    arch = {62: "amd64", 183: "arm64"}.get(machine)
    if arch is None:
        raise ValueError("unsupported ELF machine: %s" % machine)

    tmp = None
    try:
        import tempfile
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

    stubs = STUBS[arch]
    out = []
    for name, suffix, kind, note in TARGETS:
        sym = _suffix_unique(syms, suffix)
        stub = stubs[kind]
        off = sym["off"]
        if off + len(stub) > len(data):
            raise ValueError("symbol %s truncated" % name)
        out.append((name, off, data[off:off + len(stub)], stub, note))
    return out


def build_table(data):
    return locate(data)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="src", default="/usr/local/bin/1panel-core")
    ap.add_argument("--out", dest="dst", default=None)
    ap.add_argument("--orig", dest="orig", default="build/orig/1panel-core.orig")
    ap.add_argument("--manifest", dest="manifest",
                    default="build/1panel-core.manifest.json")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--patch", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="即使有目标函数定位不到也照常输出（会导致授权检查残留）")
    args = ap.parse_args()

    if args.list:
        machine = "amd64"  # 仅用于展示说明
        for name, suffix, kind, note in TARGETS:
            stub = STUBS["amd64"][kind]
            print("%-42s kind=%-8s %s" % (name, kind, note))
        print("定位方式: 按 Go 符号名（pclntab），amd64 / arm64 通用")
        return 0

    if args.verify:
        data = open(args.src, "rb").read()
        print("binary : %s" % args.src)
        print("sha256 : %s" % sha256(args.src))
        print("size   : %d" % len(data))
        bad = 0
        try:
            rows = locate(data)
        except (ValueError, OSError) as exc:
            print("!! %s" % exc)
            return 1
        for name, off, orig, stub, _note in rows:
            cur = data[off:off + len(stub)]
            if cur == stub:
                state = "PATCHED"
            elif cur == orig:
                state = "ORIG"
                bad += 1
            else:
                state = "!! UNKNOWN"
                bad += 1
            print("  %-42s off=%#010x  %-10s %s" % (name, off, state, cur.hex()))
        print("\nstate  : %s" % ("all checks removed" if bad == 0
                                 else "checks remain (%d)" % bad))
        return 0 if bad == 0 else 1

    if args.restore:
        src = args.orig if os.path.exists(args.orig) else args.src
        data = open(src, "rb").read()
        out = args.dst or args.src
        with open(out, "wb") as fh:
            fh.write(data)
        os.chmod(out, 0o755)
        print("restored %s -> %s (sha256 %s)" % (src, out, sha256(out)))
        return 0

    if args.patch:
        src, dst = args.src, args.dst or args.src
        data = bytearray(open(src, "rb").read())
        try:
            rows = locate(bytes(data))
        except (ValueError, OSError) as exc:
            print("!! %s" % exc)
            return 2

        applied, skipped = [], []
        for name, off, orig, stub, _note in rows:
            cur = bytes(data[off:off + len(stub)])
            if cur == stub:
                skipped.append(name)
                continue
            if cur != orig:
                print("!! %s: unexpected bytes at %#x: %s" % (name, off, cur.hex()))
                return 2
            data[off:off + len(stub)] = stub
            applied.append(name)

        if not applied and skipped:
            print("already patched: %s" % ", ".join(skipped))
            print("output   : %s (unchanged)" % dst)
            return 0

        os.makedirs(os.path.dirname(os.path.abspath(args.orig)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(args.manifest)), exist_ok=True)
        if not os.path.exists(args.orig):
            shutil.copy2(src, args.orig)
            print("pristine copy -> %s" % args.orig)

        with open(dst, "wb") as fh:
            fh.write(bytes(data))
        os.chmod(dst, 0o755)

        man = {
            "tool": "patch_core.py",
            "version": "1panel-core (remove-all-checks, symbol-located)",
            "source": src,
            "source_sha256": sha256(args.orig),
            "output": dst,
            "output_sha256": sha256(dst),
            "applied": applied,
            "already_patched": skipped,
            "mode": "offline",
            "remote_base": "",
            "patches": [{"name": n, "file_offset": hex(o), "stub": s.hex(), "note": c}
                        for n, o, _orig, s, c in rows],
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
