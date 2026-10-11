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
AGENT_SPEC = importlib.util.spec_from_file_location("xpack_release_agent_test", ROOT / "tools/patch_agent.py")
agent = importlib.util.module_from_spec(AGENT_SPEC)
AGENT_SPEC.loader.exec_module(agent)


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
    def elf_header(arch):
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 18, release.ELF_MACHINES[arch])
        return bytes(header)

    @classmethod
    def original_agent(cls, arch="amd64"):
        if arch == "arm64":
            return cls.elf_header(arch) + b"official arm64 agent"
        data = bytearray(max(offset + len(original) for _, offset, original, _, _ in agent.PATCHES))
        data[:20] = cls.elf_header(arch)
        for _, offset, original, _, _ in agent.PATCHES:
            data[offset:offset + len(original)] = original
        return bytes(data)

    @classmethod
    def core_archive(cls, path, names, arch="amd64"):
        header = cls.elf_header(arch)
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

    def test_agent_archive_traversal_duplicate_and_wrong_arch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "official.tar.gz"
            destination = root / "agent"
            for names in (("../1panel-agent",), ("/1panel-agent",),
                          ("package/../1panel-agent",), ("a/1panel-agent", "b/1panel-agent"),
                          ("package/1panel-core",)):
                self.core_archive(archive, names)
                with self.assertRaises(release.ReleaseError):
                    release.extract_agent(archive, destination, "amd64")
            self.core_archive(archive, ("package/1panel-agent",), "arm64")
            with self.assertRaises(release.ReleaseError):
                release.extract_agent(archive, destination, "amd64")
            for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE):
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo("package/1panel-agent")
                    member.type = kind
                    member.linkname = "1panel-core"
                    stream.addfile(member)
                with self.assertRaises(release.ReleaseError):
                    release.extract_agent(archive, destination, "amd64")
            for header in (b"", b"not an ELF", b"\x7fELF\x01\x01" + b"\0" * 14,
                           b"\x7fELF\x02\x02" + b"\0" * 14):
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo("package/1panel-agent")
                    member.size = len(header)
                    stream.addfile(member, io.BytesIO(header))
                with self.assertRaises(release.ReleaseError):
                    release.extract_agent(archive, destination, "amd64")
            self.core_archive(archive, ("package/1panel-agent",), "arm64")
            release.extract_agent(archive, destination, "arm64")
            self.assertEqual(destination.read_bytes(), self.elf_header("arm64"))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)

    def test_amd64_agent_requires_all_eight_original_sites(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "agent"
            original = self.original_agent()
            path.write_bytes(original)
            release.verify_agent_original(path, "amd64")
            for name, offset, before, after, _ in agent.PATCHES:
                for state, replacement in (("patched", after), ("unknown", b"\xff" * len(before))):
                    with self.subTest(site=name, state=state):
                        modified = bytearray(original)
                        modified[offset:offset + len(before)] = replacement
                        path.write_bytes(modified)
                        with self.assertRaisesRegex(release.ReleaseError, name + ":" + state):
                            release.verify_agent_original(path, "amd64")
            path.write_bytes(self.original_agent("arm64"))
            with mock.patch.object(release.importlib.util, "spec_from_file_location") as load:
                release.verify_agent_original(path, "arm64")
                load.assert_not_called()

    def test_stage_package_rehashes_and_preserves_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cached = root / "official.tar.gz"
            cached.write_bytes(b"official cache bytes")
            expected = release.sha256(cached)
            staged = root / "staged.tar.gz"
            self.assertEqual(release.stage_package(cached, staged, expected), staged)
            self.assertEqual(staged.read_bytes(), cached.read_bytes())
            with self.assertRaises(release.ReleaseError):
                release.stage_package(cached, staged, "0" * 64)
            self.assertEqual(cached.read_bytes(), b"official cache bytes")
            link = root / "symlink.tar.gz"
            link.symlink_to(cached)
            with self.assertRaises(release.ReleaseError):
                release.stage_package(link, staged, expected)

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
            manifest.write_text(json.dumps({"platforms": {"linux-amd64": {}, "linux-arm64": {}}}))
            assets = [manifest, root / "runtime.tar.gz"]
            for arch in release.SUPPORTED_ARCHES:
                assets.extend(root / name for name in ("core-linux-" + arch,
                              "core-linux-" + arch + ".orig", "agent-linux-" + arch + ".orig"))
            self.assertEqual(len(assets), 8)
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
            self.assertIn("linux-arm64", commands[1][commands[1].index("--notes") + 1])

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

    def test_release_outputs_all_eight_assets_and_stages_official_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            checksums = []
            originals = {}
            for arch in release.SUPPORTED_ARCHES:
                filename = "1panel-v2.3.2-linux-" + arch + ".tar.gz"
                path = cache / filename
                path.write_bytes(("official archive " + arch).encode())
                checksums.append(release.sha256(path) + "  " + filename)
                originals[arch] = path
            args = argparse.Namespace(version="v2.3.2", arches=release.SUPPORTED_ARCHES,
                                      cache_dir=cache, output=root / "output")
            stages = []

            def platform(version, arch, package, work, assets):
                self.assertNotEqual(package, originals[arch])
                self.assertEqual(package.read_bytes(), originals[arch].read_bytes())
                self.assertEqual(package.parent, work.parent)
                stages.append(package)
                core = "core-linux-" + arch
                agent_orig = "agent-linux-" + arch + ".orig"
                for name in (core, core + ".orig", agent_orig):
                    (assets / name).write_bytes(name.encode())
                return {"core_asset": core, "orig_asset": core + ".orig",
                        "agent_orig_asset": agent_orig, "agent_orig_sha256": release.sha256(assets / agent_orig),
                        "agent_orig_size": (assets / agent_orig).stat().st_size}

            with mock.patch.object(release, "official_checksums", return_value=("https://example.invalid", "\n".join(checksums))), \
                    mock.patch.object(release, "build_platform", side_effect=platform), \
                    mock.patch.object(release.urllib.request, "urlopen") as network:
                assets = release.build_release(args)
                network.assert_not_called()
            self.assertEqual(len(assets), 8)
            self.assertEqual({path.name for path in assets}, {
                "manifest.json", "runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig",
                "core-linux-arm64", "core-linux-arm64.orig", "agent-linux-amd64.orig", "agent-linux-arm64.orig"})
            manifest = json.loads((args.output / "manifest.json").read_text())
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(set(manifest["platforms"]), {"linux-amd64", "linux-arm64"})
            self.assertTrue(all(path.is_file() for path in assets))
            self.assertTrue(all(not path.exists() for path in stages))
            with mock.patch.object(release, "official_checksums", return_value=("https://example.invalid", "\n".join(checksums))), \
                    mock.patch.object(release, "cached_package", return_value=originals["arm64"]), \
                    mock.patch.object(release, "build_platform") as build:
                with self.assertRaisesRegex(release.ReleaseError, "staged official package SHA-256 mismatch"):
                    release.build_release(args)
                build.assert_not_called()
            self.assertEqual(json.loads((args.output / "manifest.json").read_text()), manifest)

    def test_platforms_have_independent_workdirs_and_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            assets.mkdir()
            workdirs = []
            extract_core = release.extract_core
            for arch in release.SUPPORTED_ARCHES:
                with tarfile.open(root / (arch + ".tar.gz"), "w:gz") as archive:
                    binaries = {"1panel-core": self.elf_header(arch) + (arch + " original").encode(),
                                "1panel-agent": self.original_agent(arch)}
                    for name, data in binaries.items():
                        member = tarfile.TarInfo("package/" + name)
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))

            def extract(package, destination, arch):
                workdirs.append(destination.parent)
                extract_core(package, destination, arch)

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
                platforms = {arch: release.build_platform("v2.3.2", arch, root / (arch + ".tar.gz"), root / arch, assets)
                             for arch in release.SUPPORTED_ARCHES}
            self.assertNotEqual(workdirs[0], workdirs[1])
            self.assertEqual({path.name for path in assets.iterdir()}, {
                "core-linux-amd64", "core-linux-amd64.orig", "core-linux-arm64", "core-linux-arm64.orig",
                "agent-linux-amd64.orig", "agent-linux-arm64.orig"})
            for arch, metadata in platforms.items():
                self.assertEqual(metadata["core_asset"], "core-linux-" + arch)
                self.assertEqual(metadata["orig_asset"], "core-linux-" + arch + ".orig")
                self.assertEqual(metadata["agent_orig_asset"], "agent-linux-" + arch + ".orig")
                self.assertEqual(metadata["agent_orig_sha256"], release.sha256(assets / metadata["agent_orig_asset"]))
                self.assertEqual(metadata["agent_orig_size"], (assets / metadata["agent_orig_asset"]).stat().st_size)
                self.assertEqual((assets / metadata["agent_orig_asset"]).read_bytes(), self.original_agent(arch))
                self.assertEqual(metadata["patches"], 8)


if __name__ == "__main__":
    unittest.main()
