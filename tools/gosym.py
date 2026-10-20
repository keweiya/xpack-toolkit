#!/usr/bin/env python3
"""Minimal Go pclntab reader: function name -> file offset / vaddr / size.

Works on stripped Go binaries because the runtime pclntab (with func names) is
always shipped. No external deps, pure stdlib.

Mapping used (verified against this binary's ELF section table):
    file_offset = .text.sh_offset + functab_entryoff
    vaddr       = .text.sh_addr   + functab_entryoff
Go 1.26 stores pcHeader.textStart as 0 here, so the .text section header is the
authoritative base instead.

Usage:
    python3 gosym.py BINARY [regex-filter]
"""
import re
import struct
import sys


def parse_elf(data):
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise SystemExit("expected an ELF64 file")
    end = "<" if data[5] == 1 else ">"

    def u(fmt, off):
        return struct.unpack_from(end + fmt, data, off)[0]

    e_phoff, e_shoff = u("Q", 0x20), u("Q", 0x28)
    e_phentsize, e_phnum = u("H", 0x36), u("H", 0x38)
    e_shentsize, e_shnum = u("H", 0x3A), u("H", 0x3C)
    e_shstrndx = u("H", 0x3E)

    def section(i):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack_from(end + "IIQQQQ", data, o)
        return {"name_off": name, "type": typ, "addr": addr, "off": off, "size": size}

    sections = [section(i) for i in range(e_shnum)]
    shstr = sections[e_shstrndx]

    def sname(n):
        s = shstr["off"] + n
        return data[s:data.index(b"\x00", s)].decode()

    by_name = {}
    for s in sections:
        s["name"] = sname(s["name_off"])
        by_name.setdefault(s["name"], s)

    phdrs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        typ = u("I", o)
        if typ != 1:  # PT_LOAD
            continue
        phdrs.append(
            {
                "off": u("Q", o + 0x08),
                "vaddr": u("Q", o + 0x10),
                "filesz": u("Q", o + 0x20),
            }
        )
    return end, by_name, phdrs


def vaddr_to_off(phdrs, vaddr):
    for p in phdrs:
        if p["vaddr"] <= vaddr < p["vaddr"] + p["filesz"]:
            return p["off"] + (vaddr - p["vaddr"])
    return None


def find_pclntab(data):
    """Return the offset of a *validated* pcHeader.

    A magic can appear by chance inside code/data, so every candidate is
    checked against the header invariants (plausible nfunc, in-file offsets).
    """
    for magic in (b"\xf1\xff\xff\xff", b"\xf0\xff\xff\xff"):
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            start = idx + 1
            try:
                nfunc = struct.unpack_from("<Q", data, idx + 8)[0]
                funcname_off = struct.unpack_from("<Q", data, idx + 32)[0]
                pctab_off = struct.unpack_from("<Q", data, idx + 56)[0]
                pcln_off = struct.unpack_from("<Q", data, idx + 64)[0]
            except struct.error:
                continue
            if 0 < nfunc < 3_000_000 and idx + max(funcname_off, pctab_off, pcln_off) < len(data):
                return idx
    raise SystemExit("pclntab magic not found")


def read_syms(path):
    with open(path, "rb") as fh:
        data = fh.read()
    end, sections, phdrs = parse_elf(data)
    text = sections.get(".text")
    base = find_pclntab(data)

    def u32(o):
        return struct.unpack_from(end + "I", data, o)[0]

    nfunc = struct.unpack_from(end + "Q", data, base + 8)[0]
    funcname_off = struct.unpack_from(end + "Q", data, base + 32)[0]
    pcln_off = struct.unpack_from(end + "Q", data, base + 64)[0]

    funcname = base + funcname_off
    functab = base + pcln_off

    syms = []
    for i in range(nfunc):
        entry_off = u32(functab + i * 8)
        func_off = u32(functab + i * 8 + 4)
        name_off = struct.unpack_from(end + "i", data, functab + func_off + 4)[0]
        nstart = funcname + name_off
        nend = data.index(b"\x00", nstart)
        name = data[nstart:nend].decode("utf-8", "replace")
        if text:
            foff = text["off"] + entry_off
            vaddr = text["addr"] + entry_off
        else:
            vaddr = entry_off
            foff = vaddr_to_off(phdrs, vaddr)
        syms.append({"name": name, "entry": entry_off, "vaddr": vaddr, "off": foff})
    syms.sort(key=lambda r: r["entry"])
    for i, s in enumerate(syms):
        nxt = syms[i + 1]["entry"] if i + 1 < len(syms) else s["entry"] + 1
        s["size"] = nxt - s["entry"]
    return data, syms


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    pat = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None
    _, syms = read_syms(sys.argv[1])
    for s in syms:
        if pat and not pat.search(s["name"]):
            continue
        print(f"0x{s['vaddr']:08x}  off=0x{s['off']:08x}  size=0x{s['size']:<6x}  {s['name']}")


if __name__ == "__main__":
    main()
