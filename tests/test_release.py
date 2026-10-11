"""Public release regressions; all GitHub operations use subprocess fixtures."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("xpack_release", ROOT / "tools/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class ReleaseTests(unittest.TestCase):
    def test_versions_and_arches(self):
        self.assertEqual(release.normalize_version("2.3.2"), "v2.3.2")
        self.assertEqual(release.normalize_version("v2.3.2"), "v2.3.2")
        self.assertEqual(release.parse_arches("amd64,arm64"), ("amd64", "arm64"))
        for version in ("latest", "v2.3", "../../v2.3.2", "v2.3.2/x"):
            with self.assertRaises(argparse.ArgumentTypeError):
                release.normalize_version(version)
        for arches in ("armv7", "ppc64le", "s390x", "riscv64", "amd64,amd64", "amd64,", ""):
            with self.assertRaises(argparse.ArgumentTypeError):
                release.parse_arches(arches)

    def test_checksum_markers_and_strict_rejection(self):
        filename = "1panel-v2.3.2-linux-amd64.tar.gz"
        digest = "ABCDEF0123456789" * 4
        for marker in ("", "*", "./", "*./"):
            self.assertEqual(release.checksum_for(digest + "  " + marker + filename, filename), digest.lower())
        bad = ("", "x" * 64 + "  " + filename, digest + "  " + filename + " extra",
               digest + "  " + filename + "\n" + digest + "  *./" + filename,
               "bad  " + filename + "\n" + digest + "  " + filename)
        for text in bad:
            with self.assertRaises(release.ReleaseError):
                release.checksum_for(text, filename)

    def test_cache_reuse_and_mismatch_preserve_user_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            package = cache / "sample.tar.gz"
            package.write_bytes(b"official sample")
            expected = hashlib.sha256(package.read_bytes()).hexdigest()
            with mock.patch.object(release.urllib.request, "urlopen") as network:
                result = release.cached_package("https://example.invalid", package.name, expected, cache)
                self.assertEqual(result, package)
                network.assert_not_called()
                with self.assertRaises(release.ReleaseError):
                    release.cached_package("https://example.invalid", package.name, "0" * 64, cache)
                self.assertEqual(package.read_bytes(), b"official sample")
                network.assert_not_called()

    def test_public_runtime_exact_whitelist_and_no_private_key(self):
        files = release.public_runtime()
        self.assertEqual(tuple(files), release.RUNTIME_FILES)
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.tar.gz"
            second = Path(temporary) / "second.tar.gz"
            info = release.build_runtime(first, files)
            release.build_runtime(second, files)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(info["size"], first.stat().st_size)
            self.assertEqual(info["sha256"], release.sha256(first))
            with tarfile.open(first, "r:gz") as archive:
                self.assertEqual(tuple(archive.getnames()), release.RUNTIME_FILES)
                for member in archive.getmembers():
                    self.assertTrue(member.isfile())
                    self.assertIsNone(release.PRIVATE_PEM.search(archive.extractfile(member).read()))
            damaged = dict(files)
            damaged["tools/aes128.py"] = b"-----BEGIN RSA PRIVATE KEY-----\nfixture\n"
            with self.assertRaises(release.ReleaseError):
                release.build_runtime(second, damaged)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(data)
            (root / "tools/gosym.py").write_bytes(b"-----BEGIN PRIVATE KEY-----\nfixture\n")
            with mock.patch.object(release, "ROOT", root), self.assertRaises(release.ReleaseError):
                release.public_runtime()

    @staticmethod
    def core_archive(path, names, arch="amd64"):
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 18, release.ELF_MACHINES[arch])
        with tarfile.open(path, "w:gz") as archive:
            for name in names:
                member = tarfile.TarInfo(name)
                member.size = len(header)
                archive.addfile(member, io.BytesIO(header))

    def test_archive_traversal_duplicate_and_wrong_arch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "official.tar.gz"
            for names in (("../1panel-core",), ("/1panel-core",), ("a/1panel-core", "b/1panel-core")):
                self.core_archive(archive, names)
                with self.assertRaises(release.ReleaseError):
                    release.extract_core(archive, root / "core", "amd64")
            self.core_archive(archive, ("package/1panel-core",), "arm64")
            with self.assertRaises(release.ReleaseError):
                release.extract_core(archive, root / "core", "amd64")
            self.core_archive(archive, ("package/1panel-core",))
            release.extract_core(archive, root / "core", "amd64")
            self.assertEqual((root / "core").stat().st_size, 20)

    def test_gh_existing_and_confirmed_404(self):
        with mock.patch.object(release.subprocess, "run", return_value=completed(stdout='{"tagName":"core-v2.3.2"}')) as run:
            self.assertTrue(release.github_release_exists("core-v2.3.2", "owner/repo"))
            self.assertEqual(run.call_count, 1)
        responses = [completed(1, stderr="release not found"),
                     completed(1, "HTTP/2.0 404 Not Found\r\n\r\n{}"), completed(stdout="{}")]
        with mock.patch.object(release.subprocess, "run", side_effect=responses) as run:
            self.assertFalse(release.github_release_exists("core-v2.3.2", "owner/repo"))
            self.assertEqual(run.call_args_list[-1].args[0], ["gh", "api", "repos/owner/repo"])

    def test_gh_other_errors_are_not_release_absence(self):
        for status in ("401", "403", "429", "500", ""):
            responses = [completed(1, stderr="view failure"),
                         completed(1, "HTTP/2.0 " + status + " error", "probe failure")]
            with mock.patch.object(release.subprocess, "run", side_effect=responses), self.assertRaises(release.ReleaseError):
                release.github_release_exists("core-v2.3.2", "owner/repo")
        responses = [completed(1), completed(1, "HTTP/2.0 404 Not Found"), completed(1, stderr="repository inaccessible")]
        with mock.patch.object(release.subprocess, "run", side_effect=responses), self.assertRaises(release.ReleaseError):
            release.github_release_exists("core-v2.3.2", "owner/repo")

    def test_publish_delete_then_one_create_and_preserve_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"platforms": {"linux-amd64": {}}}))
            assets = [manifest, root / "runtime.tar.gz", root / "core-linux-amd64", root / "core-linux-amd64.orig"]
            with mock.patch.object(release.shutil, "which", return_value="/fixture/gh"), \
                    mock.patch.object(release, "github_release_exists", return_value=True), \
                    mock.patch.object(release, "command", return_value=completed()) as run:
                release.publish_release("v2.3.2", "owner/repo", assets)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(len(commands), 2)
            self.assertEqual(commands[0], ["gh", "release", "delete", "core-v2.3.2", "--repo", "owner/repo", "--yes"])
            self.assertNotIn("--cleanup-tag", commands[0])
            self.assertEqual(commands[1][:4], ["gh", "release", "create", "core-v2.3.2"])
            self.assertEqual(commands[1][-len(assets):], [str(path) for path in assets])
            self.assertNotIn("--clobber", commands[1])
            self.assertIn("--latest", commands[1])
            self.assertIn("linux-amd64", commands[1][commands[1].index("--notes") + 1])
            self.assertNotIn("arm64", commands[1][commands[1].index("--notes") + 1])

    def test_publish_only_after_successful_build(self):
        with mock.patch.object(release, "build_release", side_effect=release.ReleaseError("second arch failed")), \
                mock.patch.object(release, "publish_release") as publish, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(release.main(["--version", "v2.3.2", "--publish", "--repo", "owner/repo"]), 1)
            publish.assert_not_called()
        order = []
        with mock.patch.object(release, "build_release", side_effect=lambda args: order.append("all-built") or []), \
                mock.patch.object(release, "publish_release", side_effect=lambda *args: order.append("publish")):
            self.assertEqual(release.main(["--version", "v2.3.2", "--publish", "--repo", "owner/repo"]), 0)
        self.assertEqual(order, ["all-built", "publish"])

    def test_platforms_have_independent_workdirs_and_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            assets.mkdir()
            workdirs = []

            def extract(package, destination, arch):
                workdirs.append(destination.parent)
                destination.write_bytes((arch + " original").encode())

            def patcher(args, **kwargs):
                if "--patch" in args:
                    original = Path(args[args.index("--in") + 1])
                    patched = Path(args[args.index("--out") + 1])
                    patched.write_bytes(original.read_bytes().replace(b"original", b"patched!"))
                    manifest = Path(args[args.index("--manifest") + 1])
                    manifest.write_text(json.dumps({"patches": [{"name": name} for name in release.PATCH_NAMES],
                                                   "applied": list(release.PATCH_NAMES), "already_patched": [],
                                                   "mode": "offline", "remote_base": "",
                                                   "source_sha256": release.sha256(original),
                                                   "output_sha256": release.sha256(patched)}))

            with mock.patch.object(release, "extract_core", side_effect=extract), \
                    mock.patch.object(release, "command", side_effect=patcher):
                platforms = {arch: release.build_platform("v2.3.2", arch, root / "package", root / arch, assets)
                             for arch in release.SUPPORTED_ARCHES}
            self.assertNotEqual(workdirs[0], workdirs[1])
            self.assertEqual({path.name for path in assets.iterdir()}, {
                "core-linux-amd64", "core-linux-amd64.orig", "core-linux-arm64", "core-linux-arm64.orig"})
            for arch, metadata in platforms.items():
                self.assertEqual(metadata["core_asset"], "core-linux-" + arch)
                self.assertEqual(metadata["orig_asset"], "core-linux-" + arch + ".orig")
                self.assertEqual(metadata["patches"], 3)


if __name__ == "__main__":
    unittest.main()
