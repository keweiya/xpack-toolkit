#!/usr/bin/env python3
"""dpanel Pro Edition license unlocker.

Target: https://github.com/donknap/dpanel  (Pro Edition binaries `dpanel-pe-*`)

The PE build is stripped and garble-obfuscated: package names are random, only
identifier suffixes survive. All patch sites are therefore located by pclntab
function suffix plus instruction-pattern matching inside the function body --
never by hardcoded file offsets.

Gate chain (reverse engineered on v1.11.1 / linux amd64):

    Process (gin middleware)
      -> os.ReadFile(dpanel.lic) / os.ReadFile(w7_opensoftware.enc)
      -> base64 -> AES -> json.Unmarshal into a local LicenseInfo copy
      -> OpenSoftwareLicenseInit -> OpenSoftwareLicenseVerify (remote check)
      -> zuakDQ4 (expiry window check) -> c.Set("license", info) -> c.Next()

Patch set:

  1. OpenSoftwareLicenseVerify  : allocate LicenseInfo{Valid:true}, return (ptr, nil)
  2. OpenSoftwareLicenseInit    : thin passthrough to (1)
  3. Process                    : drop the "license file unreadable" abort jump
  4. Process                    : on decrypt failure jump straight to the Init call
  5. zuakDQ4                    : neutralize the three expiry comparisons

Usage:
    python3 tools/dpanel_unlock.py BINARY [-o OUT] [--dry-run]
    python3 tools/dpanel_unlock.py --download v1.11.1 -o dpanel-pe-unlocked
"""

import argparse
import hashlib
import os
import struct
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gopclntab import Elf, load_functions  # noqa: E402

VERIFY_SUFFIX = "OpenSoftwareLicenseVerify"
INIT_SUFFIX = "OpenSoftwareLicenseInit"
PROCESS_SUFFIX = "Process"
EXPIRY_SUFFIX = "zuakDQ4"          # randomised name in 1.11.1; may change
NEWOBJECT_NAME = "runtime.newobject"

RELEASE_URL = "https://github.com/donknap/dpanel/releases/download/{ver}/dpanel-pe-{plat}"


class PatchError(RuntimeError):
    pass


def resolve(functions, suffix, required=True, min_size=0):
    hits = [(n, m) for n, m in functions.items()
            if (n == suffix or n.endswith("." + suffix)) and m[1] >= min_size]
    # prefer the plain function over closures / -fm wrappers, then the largest body
    hits.sort(key=lambda kv: (kv[0].count("."), -kv[1][1], kv[1][0]))
    if not hits:
        if required:
            raise PatchError(f"symbol not found: *.{suffix}")
        return None
    return hits[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def call_target(data, off, va):
    """Resolve the target vaddr of `e8 rel32` located at file offset `off`
    whose instruction address is `va`."""
    if data[off] != 0xE8:
        raise PatchError(f"not a call at {off:#x}")
    return va + 5 + struct.unpack_from("<i", data, off + 1)[0]


def find_license_type(data, process_va, process_off, process_size, newobject_va):
    """Locate the `lea rax,[LicenseInfo]; call runtime.newobject` pair in Process."""
    end = process_off + process_size
    for off in range(process_off, end - 12):
        if data[off] == 0x48 and data[off + 1] == 0x8D and (data[off + 2] & 0xC7) == 0x05:
            va = process_va + (off - process_off)
            tgt = va + 7 + struct.unpack_from("<i", data, off + 3)[0]
            if data[off + 7] == 0xE8 and call_target(data, off + 7, va + 7) == newobject_va:
                return tgt, off
    raise PatchError("LicenseInfo `lea + call newobject` pair not found in Process")


def find_process(data, elf, funcs, init_va):
    """The license middleware is the `.Process` body that calls Init."""
    cands = [(n, m) for n, m in funcs.items()
             if n.endswith("." + PROCESS_SUFFIX) and m[1] >= 0x400]
    cands.sort(key=lambda kv: -kv[1][1])
    for name, (va, size) in cands:
        off = elf.va2off(va)
        for i in range(off, off + size - 5):
            if data[i] == 0xE8:
                tgt = va + (i - off) + 5 + struct.unpack_from("<i", data, i + 1)[0]
                if tgt == init_va:
                    return va, size, name
    raise PatchError("no `.Process` body calls OpenSoftwareLicenseInit")


def patch_amd64(data, funcs):
    """Return (new_bytes, report list). data is a bytearray of the whole file."""
    elf = Elf(bytes(data))
    edits = []
    report = []

    newobject_va, _ = resolve(funcs, NEWOBJECT_NAME)[1]
    verify_va, verify_size = resolve(funcs, VERIFY_SUFFIX)[1]
    init_va, init_size = resolve(funcs, INIT_SUFFIX)[1]
    # several middleware types expose a `Process` method; the license gate is the
    # one whose body actually calls OpenSoftwareLicenseInit
    process_va, process_size, process_name = find_process(data, elf, funcs, init_va)
    expiry = resolve(funcs, EXPIRY_SUFFIX, required=False)

    process_off = elf.va2off(process_va)
    verify_off = elf.va2off(verify_va)
    init_off = elf.va2off(init_va)

    license_type, tlea_off = find_license_type(
        data, process_va, process_off, process_size, newobject_va)
    report.append(f"LicenseInfo type      {license_type:#x}")
    report.append(f"runtime.newobject     {newobject_va:#x}")
    report.append(f"Verify                {verify_va:#x} (size {verify_size:#x})")
    report.append(f"Init                  {init_va:#x} (size {init_size:#x})")
    report.append(f"Process               {process_va:#x} (size {process_size:#x}) {process_name}")
    if expiry:
        report.append(f"expiry check          {expiry[1][0]:#x} (size {expiry[1][1]:#x})")

    # ---- 1. Verify: return a freshly allocated LicenseInfo{Valid:true}
    stub = bytearray()
    stub += b"\x48\x83\xec\x08"                                  # sub rsp,8
    at = verify_va + len(stub)
    stub += b"\x48\x8d\x05" + struct.pack("<i", license_type - (at + 7))
    at = verify_va + len(stub)
    stub += b"\xe8" + struct.pack("<i", newobject_va - (at + 5))
    stub += b"\xc6\x00\x01"                                      # mov byte [rax],1
    stub += b"\x31\xdb"                                          # xor ebx,ebx
    stub += b"\x31\xc9"                                          # xor ecx,ecx
    stub += b"\x48\x83\xc4\x08"                                  # add rsp,8
    stub += b"\xc3"                                              # ret
    if len(stub) > verify_size:
        raise PatchError("Verify too small for stub")
    edits.append((verify_off, bytes(stub), "Verify -> LicenseInfo{Valid:true}"))

    # ---- 2. Init: passthrough to Verify (ignores all arguments)
    stub = bytearray()
    stub += b"\x48\x83\xec\x08"
    at = init_va + len(stub)
    stub += b"\xe8" + struct.pack("<i", verify_va - (at + 5))
    stub += b"\x48\x83\xc4\x08\xc3"
    if len(stub) > init_size:
        raise PatchError("Init too small for stub")
    edits.append((init_off, bytes(stub), "Init -> passthrough to Verify"))

    # ---- 3. Process: the "both license files unreadable" abort jump
    #        pattern: 48 85 d2 0f 85 <rel32>
    sig = b"\x48\x85\xd2\x0f\x85"
    pos = data.find(sig, process_off, process_off + process_size)
    if pos < 0:
        raise PatchError("Process: license-file abort jump not found")
    edits.append((pos + 3, b"\x90" * 6, "Process: skip license-file abort jump"))

    # ---- 4. Process: on decrypt failure, jump to the `call Init` site
    #        find `call Init`, back up over `xor ecx,ecx`
    init_call = None
    for off in range(process_off, process_off + process_size - 5):
        va = process_va + (off - process_off)
        if data[off] == 0xE8 and call_target(data, off, va) == init_va:
            init_call = off
            break
    if init_call is None:
        raise PatchError("Process: `call Init` not found")
    if data[init_call - 2:init_call] != b"\x31\xc9":
        raise PatchError("Process: unexpected prologue before `call Init`")
    resume_va_tgt = process_va + (init_call - process_off) - 2

    sig2 = b"\x48\x85\xdb\x75\x0a\x48\x83\xb8\xc8\x00\x00\x00\x00\x75\x16"
    pos = data.find(sig2, process_off, process_off + process_size)
    if pos < 0:
        raise PatchError("Process: decrypt-failure branch not found")
    src_va = process_va + (pos + 3 - process_off)   # the jcc itself is at pos+3
    rel = resume_va_tgt - (src_va + 5)
    edits.append((pos + 3, b"\xe9" + struct.pack("<i", rel),
                  "Process: decrypt failure -> call Init"))

    # ---- 5. zuakDQ4: force the success branch over expiry comparisons
    if expiry:
        exp_va, exp_size = expiry[1]
        exp_off = elf.va2off(exp_va)
        sites = []
        off = exp_off
        while off < exp_off + exp_size - 4:
            if data[off:off + 3] == b"\x48\x85\xc0":
                jcc = data[off + 3]
                if jcc == 0x7C:      # jl  -> never take the failure branch
                    sites.append((off + 3, b"\x90\x90", "zuakDQ4: drop jl failure"))
                elif jcc == 0x7D:    # jge -> always continue on success path
                    sites.append((off + 3, b"\xeb" + data[off + 4:off + 5],
                                  "zuakDQ4: force jge success"))
                off += 3
                continue
            off += 1
        if len(sites) < 2:
            raise PatchError(f"zuakDQ4: expected >=2 expiry checks, found {len(sites)}")
        edits.extend(sites)

    # apply
    for off, blob, label in edits:
        data[off:off + len(blob)] = blob
        report.append(f"patched {label:<42} @ {off:#x}  {blob.hex(' ')}")
    return data, report


def download(version, plat, dest):
    url = RELEASE_URL.format(ver=version, plat=plat)
    print(f"[*] downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "xpack-toolkit"})
    with urllib.request.urlopen(req) as r, open(dest, "wb") as f:
        f.write(r.read())
    os.chmod(dest, 0o755)
    print(f"[*] saved {dest}")


def main():
    ap = argparse.ArgumentParser(description="dpanel PE license unlocker")
    ap.add_argument("binary", nargs="?")
    ap.add_argument("-o", "--output")
    ap.add_argument("--download", metavar="VERSION",
                    help="fetch dpanel-pe release instead of using a local file")
    ap.add_argument("--plat", default="gnu-amd64")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    src = args.binary
    if args.download:
        src = args.output or f"dpanel-pe-{args.download}-{args.plat}"
        download(args.download, args.plat, src)

    if not src:
        ap.error("provide BINARY or --download VERSION")
    if not args.output:
        root, ext = os.path.splitext(src)
        args.output = f"{root}-unlocked{ext or ''}"

    raw = open(src, "rb").read()
    funcs, meta = load_functions(raw)
    print(f"[*] {src}: {len(raw)} bytes, magic={meta['magic']:#x}, "
          f"{meta['nfunc']} functions")

    if raw[:4] != b"\x7fELF":
        raise SystemExit("not an ELF binary")
    if raw[4] != 2:
        raise SystemExit("only 64-bit ELF is supported")
    if raw[5] != 1:
        raise SystemExit("only little-endian ELF is supported")
    machine = struct.unpack_from("<H", raw, 0x12)[0]
    if machine != 0x3E:
        raise SystemExit(f"unsupported machine {machine:#x} (only x86-64 implemented)")

    data, report = patch_amd64(bytearray(raw), funcs)
    print("\n".join(report))

    if args.dry_run:
        print("[*] dry run, nothing written")
        return
    with open(args.output, "wb") as f:
        f.write(data)
    os.chmod(args.output, 0o755)
    print(f"\n[+] wrote {args.output}")
    print(f"[+] sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
