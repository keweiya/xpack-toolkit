#!/usr/bin/env python3
"""1Panel v2.3.2 agent (1panel-agent) X-Pack unlocker.

The agent gates every X-Pack subsystem on one package-level bool that is
seeded from /opt/1panel/conf/panel.json:

    github.com/1Panel-dev/1Panel/agent/xpack/utils/edition  -> isXpack  (byte, .noptrbss @ 0x51c94c0)

Three writers and seven readers touch that byte; `IsXpack()` is the exported
accessor.  All edits below are length preserving.

    A1  (*multiNodeHelper).IsXpack        -> return true
    A2  xpack.initXpack      guard        -> drop `if !isXpack { skip }`
    A3  xpack.initXpack      log value    -> print isXpack=true
    A4  xpack.initXpack      store        -> isXpack = true
    A5  common_xpack.InitLicenseInfo store -> isXpack = true
    A6  app/service.syncNodeInfo store   -> isXpack = true
    A7  app/service.syncNodeInfo branch  -> always InitXpack(), never ResetXpack()
    A8  alert_xpack.GetLicenseAlert       -> return nil (no license nag)

Usage:
  python3 tools/patch_1panel_agent.py --list
  python3 tools/patch_1panel_agent.py --verify [--in BIN]
  python3 tools/patch_1panel_agent.py --patch  [--in BIN] [--out BIN]
  python3 tools/patch_1panel_agent.py --restore [--in BIN] [--out BIN]
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

NOP = b"\x90"

PATCHES = [
    ("A1.IsXpack.return_true", 0x00FCBD20,
     bytes.fromhex("0fb60599d7df03c3"),
     bytes.fromhex("b8010000009090c3"),
     "(*multiNodeHelper).IsXpack -> true"),

    ("A2.initXpack.drop_guard", 0x02414B80,
     bytes.fromhex("0f8415010000"),
     NOP * 6,
     "xpack.initXpack: never skip the publish block"),

    ("A3.initXpack.log_true", 0x02414B25,
     bytes.fromhex("440fb690980000004c8d1d"),
     bytes.fromhex("41ba0100000090904c8d1d"),
     "log line reads isXpack=true"),

    ("A4.initXpack.store_true", 0x02414C25,
     bytes.fromhex("0fb692980000008815"),
     bytes.fromhex("ba0100000090908815"),
     "isXpack global <- 1"),

    ("A5.InitLicenseInfo.store_true", 0x00F5E419,
     bytes.fromhex("0fb680980000008805"),
     bytes.fromhex("b80100000090908805"),
     "common_xpack.InitLicenseInfo: isXpack global <- 1"),

    ("A6.syncNodeInfo.store_true", 0x023D54C7,
     bytes.fromhex("0fb68424080100008805"),
     bytes.fromhex("b8010000009090908805"),
     "app/service.syncNodeInfo: isXpack global <- 1"),

    ("A7.syncNodeInfo.prefer_init", 0x023D54DD,
     bytes.fromhex("7410"),
     NOP * 2,
     "syncNodeInfo: call InitXpack(), never ResetXpack()"),

    ("A8.GetLicenseAlert.return_nil", 0x00F92E40,
     bytes.fromhex("493b6610763d55"),
     bytes.fromhex("31c031db31c9c3"),
     "alert_xpack.GetLicenseAlert -> nil"),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def locate(data):
    out = []
    for name, off, orig, pat, _ in PATCHES:
        cur = data[off:off + len(pat)]
        out.append((name, off, "original" if cur == orig else
                    ("patched" if cur == pat else "unknown"), cur))
    return out


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
        for n, o, orig, pat, c in PATCHES:
            print("%-34s file=%#010x len=%2d  %s" % (n, o, len(pat), c))
        return 0

    if args.verify:
        data = open(args.src, "rb").read()
        print("binary : %s" % args.src)
        print("sha256 : %s" % sha256(args.src))
        print("size   : %d" % len(data))
        bad = 0
        for n, o, st, cur in locate(data):
            if st == "unknown":
                bad += 1
            print("  %-34s %#010x  %-9s %s" % (n, o, st, cur[:16].hex()))
        allp = all(s == "patched" for _, _, s, _ in locate(data))
        print("\nstate  : %s" % ("all patches present" if allp else
                                 ("unknown sites: %d" % bad if bad else "unpatched")))
        return 0 if bad == 0 else 1

    if args.restore:
        src = args.orig if os.path.exists(args.orig) else args.src
        data = open(src, "rb").read()
        for n, o, orig, pat, _ in PATCHES:
            if data[o:o + len(orig)] == pat:
                data = data[:o] + orig + data[o + len(orig):]
        out = args.dst or args.src
        open(out, "wb").write(data)
        os.chmod(out, 0o755)
        print("restored %s -> %s (sha256 %s)" % (src, out, sha256(out)))
        return 0

    if args.patch:
        src, dst = args.src, args.dst or args.src
        data = bytearray(open(src, "rb").read())
        applied, skipped = [], []
        for n, o, orig, pat, _ in PATCHES:
            cur = bytes(data[o:o + len(pat)])
            if cur == pat:
                skipped.append(n)
                continue
            if cur != orig:
                print("!! %s: unexpected bytes at %#x: %s" % (n, o, cur.hex()))
                return 2
            data[o:o + len(pat)] = pat
            applied.append(n)

        os.makedirs(os.path.dirname(os.path.abspath(args.orig)), exist_ok=True)
        if not os.path.exists(args.orig):
            shutil.copy2(src, args.orig)
            print("pristine copy -> %s" % args.orig)
        open(dst, "wb").write(bytes(data))
        os.chmod(dst, 0o755)

        man = {
            "tool": "patch_1panel_agent.py",
            "version": "1panel-agent v2.3.2 (from 1panel-v2.3.2-linux-amd64.tar.gz)",
            "source": src,
            "source_sha256": sha256(args.orig),
            "output": dst,
            "output_sha256": sha256(dst),
            "isxpack_global": "0x51c94c0",
            "applied": applied,
            "already_patched": skipped,
            "patches": [{"name": n, "file_offset": hex(o), "orig": or_.hex(),
                         "patch": p.hex(), "note": c} for n, o, or_, p, c in PATCHES],
        }
        json.dump(man, open(args.manifest, "w"), indent=2, ensure_ascii=False)
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
