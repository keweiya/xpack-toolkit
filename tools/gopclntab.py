#!/usr/bin/env python3
"""Minimal Go pclntab reader that tolerates tampered / obfuscated binaries.

Works on stripped + garble-obfuscated Go binaries where:
  - the ELF symbol table is gone,
  - the pclntab magic is not the stock 0xFFFFFFF1,
  - sections are still intact (`.gopclntab` / `.text`).

Function names may be rewritten by garble, but suffixes of stdlib-style
identifiers are usually preserved, so callers should resolve by suffix.
"""

import struct


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.data = data
        self.is64 = data[4] == 2
        if not self.is64:
            raise ValueError("only ELF64 is supported")
        self.endian = "<" if data[5] == 1 else ">"
        e = self.endian
        self.e_type = struct.unpack_from(e + "H", data, 0x10)[0]
        e_shoff = struct.unpack_from(e + "Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from(e + "H", data, 0x3A)[0]
        e_shnum = struct.unpack_from(e + "H", data, 0x3C)[0]
        self.sections = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            name, typ, flags, addr, off, size = struct.unpack_from(e + "IIQQQQ", data, base)
            sh_name_off = name
            self.sections.append(
                {
                    "name_off": sh_name_off,
                    "type": typ,
                    "flags": flags,
                    "addr": addr,
                    "offset": off,
                    "size": size,
                }
            )
        shstr = self.sections[struct.unpack_from(e + "H", data, 0x3E)[0]]
        for s in self.sections:
            start = shstr["offset"] + s["name_off"]
            end = data.index(b"\x00", start)
            s["name"] = data[start:end].decode("latin1")

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def va2off(self, va):
        for s in self.sections:
            if s["type"] != 8 and s["addr"] <= va < s["addr"] + s["size"]:
                return s["offset"] + (va - s["addr"])
        raise ValueError(f"vaddr {va:#x} not mapped")


def _read_cstr(data, off):
    end = data.index(b"\x00", off)
    return data[off:end].decode("latin1", "replace")


def load_functions(data: bytes):
    """Return {name: (entry_vaddr, size)} and extra metadata."""
    elf = Elf(data)
    sec = elf.section(".gopclntab") or elf.section(".data.rel.ro.gopclntab")
    if sec is None:
        raise ValueError(".gopclntab section missing (binary may be packed)")
    base = sec["offset"]
    blob = data[base:base + sec["size"]]
    e = elf.endian

    magic = struct.unpack_from(e + "I", blob, 0)[0]
    ptr_size = blob[7]
    if ptr_size != 8:
        raise ValueError(f"unexpected pointer size {ptr_size}")

    nfunc = struct.unpack_from(e + "Q", blob, 8)[0]
    text_start = struct.unpack_from(e + "Q", blob, 24)[0]
    funcname_off = struct.unpack_from(e + "Q", blob, 32)[0]
    pcln_off = struct.unpack_from(e + "Q", blob, 64)[0]

    funcname_tab = base + funcname_off
    ftab = base + pcln_off
    entries = []
    for i in range(nfunc):
        entry_off, func_off = struct.unpack_from(e + "Ii", blob, (ftab + i * 8) - base)
        entries.append((entry_off, func_off))
    funcs = {}
    order = sorted(entries)
    for idx, (entry_off, func_off) in enumerate(order):
        p = ftab + func_off + 4  # _func header: entryOff uint32, then nameOff int32
        name_off = struct.unpack_from(e + "i", data, p)[0]
        name = _read_cstr(data, funcname_tab + name_off)
        nxt = order[idx + 1][0] if idx + 1 < len(order) else entry_off + 1
        funcs[name] = (text_start + entry_off, nxt - entry_off)
    return funcs, {"magic": magic, "text_start": text_start, "nfunc": nfunc}


def find(functions, suffix, exact=False):
    """Resolve a function by exact name or by dotted suffix (garble-safe)."""
    hits = []
    for name, meta in functions.items():
        if exact:
            if name == suffix:
                hits.append((name, meta))
        elif name == suffix or name.endswith("." + suffix):
            hits.append((name, meta))
    hits.sort(key=lambda x: x[1][0])
    return hits


if __name__ == "__main__":
    import sys

    path = sys.argv[1]
    pattern = sys.argv[2] if len(sys.argv) > 2 else ""
    data = open(path, "rb").read()
    funcs, meta = load_functions(data)
    print(f"# magic={meta['magic']:#x} textStart={meta['text_start']:#x} nfunc={meta['nfunc']}")
    for name, (addr, size) in sorted(funcs.items(), key=lambda kv: kv[1][0]):
        if pattern.lower() in name.lower():
            print(f"{addr:#x} {size:#6x} {name}")
