#!/usr/bin/env python3
"""tools/patch_agent.py 的双架构补丁测试（amd64 / arm64）。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import patch_agent as agent  # noqa: E402

RELEASE = ROOT / "build/release-v2.4.0"


def asset(arch):
    return RELEASE / "agent-linux-{}.orig".format(arch)


class MachineTest(unittest.TestCase):
    def test_detects_both_architectures(self):
        for arch, number in (("amd64", 62), ("arm64", 183)):
            header = b"\x7fELF\x02\x01\x01" + b"\x00" * 11 + number.to_bytes(2, "little")
            self.assertEqual(agent.machine(header + b"\x00" * 8), arch)

    def test_rejects_non_elf_and_unknown_machine(self):
        for blob in (b"", b"#!/bin/sh\necho hi\n", b"\x7fELF\x02\x01\x01" + b"\x00" * 11 + (40).to_bytes(2, "little")):
            with self.assertRaises(ValueError):
                agent.machine(blob)

    def test_each_architecture_has_eight_sites(self):
        for arch in ("amd64", "arm64"):
            names = [row[0] for row in agent.ENTRY_STUBS[arch]]
            names += [row[0] for row in agent.PATTERN_SITES[arch]]
            names += [row[0] for row in agent.BRANCH_SITES[arch]]
            self.assertEqual(len(names), 8, arch)
            self.assertEqual(len(set(names)), 8, arch)


@unittest.skipUnless(asset("amd64").is_file() and asset("arm64").is_file(),
                     "official agents not present in build/release-v2.4.0")
class RoundTripTest(unittest.TestCase):
    def check(self, arch):
        data = asset(arch).read_bytes()
        rows = agent.sites(data)
        self.assertEqual([row[4] for row in rows], ["original"] * 8)
        patched = bytearray(data)
        for _name, off, _orig, patch, _state, _note in rows:
            patched[off:off + len(patch)] = patch
        patched = bytes(patched)
        self.assertEqual(len(patched), len(data), "补丁必须等长")
        again = agent.sites(patched)
        self.assertEqual([row[4] for row in again], ["patched"] * 8)
        changed = [i for i in range(len(data)) if data[i] != patched[i]]
        limit = sum(len(row[3]) for row in rows)
        self.assertLessEqual(len(changed), limit)
        # 改动必须全部落在站点范围内
        ranges = [(row[1], row[1] + len(row[3])) for row in rows]
        for index in changed:
            self.assertTrue(any(lo <= index < hi for lo, hi in ranges), hex(index))

    def test_amd64_round_trip(self):
        self.check("amd64")

    def test_arm64_round_trip(self):
        self.check("arm64")

    def test_cli_verifies_patched_copy(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "agent"
            subprocess.run([sys.executable, str(ROOT / "tools/patch_agent.py"), "--patch",
                            "--in", str(asset("arm64")), "--out", str(out),
                            "--manifest", str(Path(tmp) / "m.json")],
                           check=True, capture_output=True)
            listing = subprocess.run([sys.executable, str(ROOT / "tools/patch_agent.py"),
                                      "--verify", "--in", str(out)],
                                     check=True, capture_output=True, text=True).stdout
            self.assertIn("all patches present", listing)


if __name__ == "__main__":
    unittest.main()
