"""Remove-all-checks kernel patch regressions (offline, no live installation)."""

import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("patch_core", ROOT / "tools/patch_core.py")
patch_core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patch_core)

ORIG = ROOT / "build/orig/core-linux-amd64.orig"


class StubTests(unittest.TestCase):
    def test_amd64_stubs(self):
        self.assertEqual(patch_core.STUBS["amd64"]["void"], b"\xc3")
        self.assertEqual(patch_core.STUBS["amd64"]["err"], b"\x31\xc0\x31\xdb\xc3")
        self.assertEqual(patch_core.STUBS["amd64"]["bool_err"],
                         b"\xb8\x01\x00\x00\x00\x31\xdb\x31\xc9\xc3")

    def test_arm64_stubs(self):
        self.assertEqual(patch_core.STUBS["arm64"]["void"], bytes.fromhex("c0035fd6"))
        self.assertEqual(patch_core.STUBS["arm64"]["err"],
                         bytes.fromhex("000080d2010080d2c0035fd6"))
        self.assertEqual(patch_core.STUBS["arm64"]["bool_err"],
                         bytes.fromhex("200080d2010080d2020080d2c0035fd6"))

    def test_targets_are_eight_and_unique(self):
        names = [row[0] for row in patch_core.TARGETS]
        suffixes = [row[1] for row in patch_core.TARGETS]
        kinds = [row[2] for row in patch_core.TARGETS]
        self.assertEqual(len(names), 8)
        self.assertEqual(len(set(names)), 8)
        self.assertEqual(len(set(suffixes)), 8)
        self.assertTrue(all(kind in patch_core.STUBS["amd64"] for kind in kinds))

    def test_detect_machine(self):
        amd64 = (b"\x7fELF\x02\x01" + b"\x00" * 10
                 + (2).to_bytes(2, "little") + (62).to_bytes(2, "little"))
        arm64 = (b"\x7fELF\x02\x01" + b"\x00" * 10
                 + (2).to_bytes(2, "little") + (183).to_bytes(2, "little"))
        self.assertEqual(patch_core.detect_machine(amd64), 62)
        self.assertEqual(patch_core.detect_machine(arm64), 183)
        self.assertIsNone(patch_core.detect_machine(b"not an elf"))


@unittest.skipUnless(ORIG.is_file(), "official core binary not present")
class RealBinaryTests(unittest.TestCase):
    def test_patch_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            patched = directory / "core"
            manifest = directory / "manifest.json"
            shutil.copy2(ORIG, directory / "orig")
            proc = subprocess.run(
                ["python3", str(ROOT / "tools/patch_core.py"), "--patch",
                 "--in", str(ORIG), "--out", str(patched), "--orig", str(directory / "orig"),
                 "--manifest", str(manifest)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            proc = subprocess.run(
                ["python3", str(ROOT / "tools/patch_core.py"), "--verify", "--in", str(patched)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("all checks removed", proc.stdout)
            self.assertEqual(patched.stat().st_size, ORIG.stat().st_size)
            self.assertNotEqual(hashlib.sha256(patched.read_bytes()).hexdigest(),
                                hashlib.sha256(ORIG.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
