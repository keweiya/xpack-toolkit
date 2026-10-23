#!/usr/bin/env python3
"""Internal multi-platform release builder; the user entry point is unlock.sh."""

import argparse
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_ARCHES = ("amd64", "arm64")
ELF_MACHINES = {"amd64": 62, "arm64": 183}
ROOT_FINGERPRINT = "cb8cc410354dbbda7b542c952a8c8ffb47a0f3d886c7e7273c89cb7a44156030"
RUNTIME_FILES = (
    "tools/gen_license.py",
    "tools/patch_core.py",
    "tools/patch_agent.py",
    "tools/cert_store.py",
    "tools/aes128.py",
    "tools/gosym.py",
    "tools/official_rootcert.json",
    "state/license.crt",
)
PATCH_NAMES = {
    "C1.middleware.checkLicense.passthrough",
    "C2.checkLicenseSyncFresh.return_true",
    "C3.CheckInLocal.return_ok",
    "C4.checkRootCertFingerprint.return_ok",
    "C5.EnsureFreeNodeBindAllowed.return_ok",
    "C6.BindFree.return_ok",
    "C7.Report.skip",
    "C8.Unbind.skip",
}
PRIVATE_PEM = re.compile(br"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


class ReleaseError(Exception):
    """A failed build must leave the existing GitHub release untouched."""


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_version(value):
    version = value if value.startswith("v") else "v" + value
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", version):
        raise argparse.ArgumentTypeError("version must be vMAJOR.MINOR.PATCH")
    return version


def parse_arches(value):
    arches = tuple(part.strip() for part in value.split(","))
    if not arches or len(set(arches)) != len(arches):
        raise argparse.ArgumentTypeError("arches must be a unique comma-separated list")
    unsupported = [arch for arch in arches if arch not in SUPPORTED_ARCHES]
    if unsupported:
        raise argparse.ArgumentTypeError(
            "C7 adaptation is verified only for amd64,arm64; unsupported: "
            + ",".join(unsupported))
    return arches


def checksum_for(text, filename):
    """Accept sha256sum's text/binary markers, rejecting duplicate target entries."""
    matches = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[1]
        if name.startswith("*"):
            name = name[1:]
        if name.startswith("./"):
            name = name[2:]
        if name == filename:
            matches.append(parts)
    if (len(matches) != 1 or len(matches[0]) != 2
            or not re.fullmatch(r"[0-9a-fA-F]{64}", matches[0][0])):
        raise ReleaseError("official checksums require one valid SHA-256 for " + filename)
    return matches[0][0].lower()


def official_checksums(version):
    base = "https://resource.fit2cloud.com/1panel/package/v2/stable/{}/release".format(version)
    request = urllib.request.Request(base + "/checksums.txt", headers={"User-Agent": "xpack-release/2"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ReleaseError("official checksums exceed the size limit")
        return base, data.decode("utf-8", errors="strict")
    except (urllib.error.URLError, UnicodeError, OSError) as exc:
        raise ReleaseError("failed to retrieve official checksums: {}".format(exc)) from exc


def cached_package(base, filename, expected, cache_dir):
    cache_dir.mkdir(parents=True, exist_ok=True)
    destination = cache_dir / filename
    if destination.is_symlink():
        raise ReleaseError("package cache entry must be a regular file: " + str(destination))
    if destination.exists():
        if not destination.is_file() or sha256(destination) != expected:
            raise ReleaseError("cached official package SHA-256 mismatch; cache preserved: " + str(destination))
        print("Reusing verified official package: " + str(destination), flush=True)
        return destination
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=filename + ".", suffix=".part", dir=cache_dir, delete=False) as target:
            temporary = Path(target.name)
            request = urllib.request.Request(base + "/" + filename, headers={"User-Agent": "xpack-release/2"})
            with urllib.request.urlopen(request, timeout=120) as response:
                shutil.copyfileobj(response, target, length=1024 * 1024)
        if sha256(temporary) != expected:
            raise ReleaseError("downloaded official package SHA-256 mismatch: " + filename)
        # Never replace an entry another process supplied during the download.
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if destination.is_symlink() or not destination.is_file() or sha256(destination) != expected:
                raise ReleaseError("conflicting cache entry preserved: " + str(destination))
        return destination
    except (urllib.error.URLError, OSError) as exc:
        raise ReleaseError("official package download failed: {}".format(exc)) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def stage_package(package, destination, expected):
    """Extract only from a private copy rehashed against current official checksums."""
    if package.is_symlink() or not package.is_file():
        raise ReleaseError("official package must be a regular file: " + str(package))
    shutil.copyfile(package, destination)
    if sha256(destination) != expected:
        raise ReleaseError("staged official package SHA-256 mismatch: " + package.name)
    return destination


def extract_binary(package, destination, arch, binary):
    """Copy only a unique regular binary member; never extract archive paths."""
    with tarfile.open(package, "r:gz") as archive:
        candidates = [member for member in archive.getmembers()
                      if PurePosixPath(member.name).name == binary]
        if len(candidates) != 1 or not candidates[0].isfile():
            raise ReleaseError("official archive requires one regular " + binary)
        member = candidates[0]
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts or member.size <= 0:
            raise ReleaseError("invalid " + binary + " archive member")
        with archive.extractfile(member) as source, destination.open("wb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
    with destination.open("rb") as source:
        header = source.read(20)
    if (len(header) != 20 or header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", header, 18)[0] != ELF_MACHINES[arch]):
        raise ReleaseError("official " + binary + " ELF architecture mismatch: " + arch)
    destination.chmod(0o755)


def extract_core(package, destination, arch):
    extract_binary(package, destination, arch, "1panel-core")


def extract_agent(package, destination, arch):
    extract_binary(package, destination, arch, "1panel-agent")


def verify_agent_original(path, arch):
    if arch not in SUPPORTED_ARCHES:
        return
    spec = importlib.util.spec_from_file_location("xpack_release_agent", ROOT / "tools/patch_agent.py")
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    try:
        sites = agent.locate(path.read_bytes())
    except (ValueError, OSError, struct.error, IndexError) as exc:
        raise ReleaseError("official {} agent patch sites are not locatable: {}".format(arch, exc)) from exc
    names = {name for name, _, _, _ in sites}
    required = set(agent.REQUIRED_SITES)
    if not required <= names or len(names) != len(sites) or len(sites) < len(required):
        raise ReleaseError("official {} agent is missing required patch sites: {}".format(
            arch, ", ".join(sorted(required - names)) or "duplicated sites"))
    bad = [name + ":" + state for name, _, state, _ in sites if state != "original"]
    if bad:
        raise ReleaseError("official {} agent is not pristine: {}".format(arch, ", ".join(bad)))


def command(args, *, env=None, capture=False):
    try:
        result = subprocess.run(args, cwd=ROOT, env=env, text=True,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.PIPE if capture else None)
    except OSError as exc:
        raise ReleaseError("command failed: {}: {}".format(args[0], exc)) from exc
    if result.returncode:
        detail = ((result.stderr or "") + (result.stdout or "")).strip() if capture else ""
        raise ReleaseError("command exited {}: {} {}".format(result.returncode, args[0], detail))
    return result


def public_runtime():
    files = {}
    for name in RUNTIME_FILES:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ReleaseError("missing regular public runtime file: " + name)
        data = path.read_bytes()
        if not data or PRIVATE_PEM.search(data):
            raise ReleaseError("empty file or private key material in public runtime: " + name)
        files[name] = data
    certificate = files["state/license.crt"].decode("ascii")
    if (certificate.count("-----BEGIN CERTIFICATE-----") != 1
            or certificate.count("-----END CERTIFICATE-----") != 1):
        raise ReleaseError("public root must contain exactly one certificate")
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
    if fingerprint != ROOT_FINGERPRINT:
        raise ReleaseError("public cb8c root certificate changed")
    return files


def build_runtime(destination, files):
    # Stable public-only archive: no source directory walk, keys, caches or helpers.
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name in RUNTIME_FILES:
                    info = tarfile.TarInfo(name)
                    info.size = len(files[name])
                    info.mode = 0o644
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(files[name]))
    verify_runtime(destination, files)
    return {"asset": "runtime.tar.gz", "sha256": sha256(destination),
            "size": destination.stat().st_size}


def verify_runtime(path, files):
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if tuple(member.name for member in members) != RUNTIME_FILES:
            raise ReleaseError("runtime must contain exactly the eight whitelisted files")
        for member in members:
            if not member.isfile():
                raise ReleaseError("non-regular runtime member: " + member.name)
            data = archive.extractfile(member).read()
            if data != files[member.name] or PRIVATE_PEM.search(data):
                raise ReleaseError("runtime file mismatch or private key material: " + member.name)


def build_platform(version, arch, package, work, assets):
    work.mkdir()
    original = work / "core.orig"
    agent_original = work / "agent.orig"
    patched = work / "core"
    patch_manifest = work / "patches.json"
    extract_core(package, original, arch)
    extract_agent(package, agent_original, arch)
    verify_agent_original(agent_original, arch)
    environment = os.environ.copy()
    environment["SIGN_CRT"] = str(ROOT / "state/license.crt")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in ("ORIG", "STATE", "REMOTE_BASE"):
        environment.pop(name, None)
    command([sys.executable, str(ROOT / "tools/patch_core.py"), "--in", str(original),
             "--out", str(patched), "--patch", "--orig", str(original),
             "--manifest", str(patch_manifest)], env=environment)
    command([sys.executable, str(ROOT / "tools/patch_core.py"), "--in", str(patched),
             "--verify"], env=environment)
    details = json.loads(patch_manifest.read_text(encoding="utf-8"))
    patches = details.get("patches")
    if (not isinstance(patches, list) or len(patches) != len(PATCH_NAMES)
            or {item.get("name") for item in patches} != PATCH_NAMES
            or set(details.get("applied", [])) != PATCH_NAMES
            or details.get("already_patched") != []
            or details.get("mode") != "offline" or details.get("remote_base") != ""
            or details.get("source_sha256") != sha256(original)
            or details.get("output_sha256") != sha256(patched)
            or patched.stat().st_size != original.stat().st_size):
        raise ReleaseError("unexpected fresh offline patch manifest for " + arch)
    # Agent 也在构建期打好补丁随 Release 发布，装机器只做校验 + 替换，
    # 不需要在目标机上再跑一遍补丁流程。
    agent_patched = work / "agent"
    agent_manifest = work / "agent-patches.json"
    command([sys.executable, str(ROOT / "tools/patch_agent.py"), "--patch",
             "--in", str(agent_original), "--out", str(agent_patched),
             "--orig", str(agent_original), "--manifest", str(agent_manifest)])
    command([sys.executable, str(ROOT / "tools/patch_agent.py"), "--verify",
             "--in", str(agent_patched), "--orig", str(agent_original)])
    agent_details = json.loads(agent_manifest.read_text(encoding="utf-8"))
    agent_patches = agent_details.get("applied") or []
    recorded = {item.get("name") for item in agent_details.get("patches") or []}
    if (not agent_patches or set(agent_patches) != recorded
            or agent_details.get("already_patched") != []
            or agent_patched.stat().st_size != agent_original.stat().st_size):
        raise ReleaseError("unexpected agent patch manifest for " + arch)
    core_asset = "core-linux-" + arch
    orig_asset = core_asset + ".orig"
    agent_asset = "agent-linux-" + arch
    agent_orig_asset = agent_asset + ".orig"
    shutil.copyfile(patched, assets / core_asset)
    shutil.copyfile(original, assets / orig_asset)
    shutil.copyfile(agent_patched, assets / agent_asset)
    shutil.copyfile(agent_original, assets / agent_orig_asset)
    for name in (core_asset, orig_asset, agent_asset, agent_orig_asset):
        (assets / name).chmod(0o755)
    return {"arch": arch, "os": "linux", "size": patched.stat().st_size,
            "sha256": sha256(patched), "orig_sha256": sha256(original),
            "core_asset": core_asset, "orig_asset": orig_asset, "patches": len(patches),
            "agent_asset": agent_asset, "agent_sha256": sha256(agent_patched),
            "agent_size": agent_patched.stat().st_size, "agent_patches": len(agent_patches),
            "agent_orig_asset": agent_orig_asset, "agent_orig_sha256": sha256(agent_original),
            "agent_orig_size": agent_original.stat().st_size}


def source_commit():
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                text=True, capture_output=True)
    except OSError:
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None


def build_release(args):
    files = public_runtime()
    base, checksums = official_checksums(args.version)
    # Validate every requested entry before downloading or building any platform.
    expected = {arch: checksum_for(checksums, "1panel-{}-linux-{}.tar.gz".format(args.version, arch))
                for arch in args.arches}
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ReleaseError("output must be a real directory")
    with tempfile.TemporaryDirectory(prefix=".xpack-{}-".format(args.version), dir=output.parent) as temporary:
        stage = Path(temporary)
        assets = stage / "assets"
        assets.mkdir()
        manifest = {
            "schema_version": 2, "name": "xpack-toolkit", "version": args.version,
            "mode": "offline", "remote_base": "", "root_fingerprint": ROOT_FINGERPRINT,
            "built_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "platforms": {},
        }
        commit = source_commit()
        if commit:
            manifest["source_commit"] = commit
        for arch in args.arches:
            print("Building {} / linux-{}".format(args.version, arch), flush=True)
            filename = "1panel-{}-linux-{}.tar.gz".format(args.version, arch)
            package = cached_package(base, filename, expected[arch], args.cache_dir)
            package = stage_package(package, stage / filename, expected[arch])
            manifest["platforms"]["linux-" + arch] = build_platform(
                args.version, arch, package, stage / arch, assets)
        manifest["runtime"] = build_runtime(assets / "runtime.tar.gz", files)
        (assets / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        output.mkdir(exist_ok=True)
        names = ["manifest.json", "runtime.tar.gz"]
        for arch in args.arches:
            names.extend(["core-linux-" + arch, "core-linux-" + arch + ".orig",
                          "agent-linux-" + arch, "agent-linux-" + arch + ".orig"])
        # Replace only our named assets after the entire release has built successfully.
        for name in names:
            target = output / name
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise ReleaseError("output asset must be a regular file: " + str(target))
        for name in names:
            os.replace(assets / name, output / name)
    print("Built core-{}: {}".format(args.version, output), flush=True)
    return [output / name for name in names]


def github_release_exists(tag, repo):
    result = subprocess.run(["gh", "release", "view", tag, "--repo", repo, "--json", "tagName"],
                            cwd=ROOT, text=True, capture_output=True)
    if result.returncode == 0:
        if json.loads(result.stdout).get("tagName") != tag:
            raise ReleaseError("gh returned an unexpected release tag")
        return True
    # gh view often omits HTTP status; confirm a real 404 via REST, then ensure
    # the repository itself is readable (an auth/repository 404 is not absence).
    endpoint = "repos/{}/releases/tags/{}".format(repo, urllib.parse.quote(tag, safe=""))
    probe = subprocess.run(["gh", "api", "--include", endpoint], cwd=ROOT, text=True, capture_output=True)
    status = re.search(r"(?m)^HTTP/[0-9.]+\s+([0-9]{3})\b", probe.stdout)
    if probe.returncode != 0 and status and status.group(1) == "404":
        command(["gh", "api", "repos/" + repo], capture=True)
        return False
    raise ReleaseError("gh release view failed; release absence was not confirmed: "
                       + (result.stderr + probe.stderr).strip())


def release_repo(repo):
    if repo:
        return repo
    remote = command(["git", "remote", "get-url", "origin"], capture=True).stdout.strip()
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+/[^/]+?)(?:\.git)?/?", remote)
    if not match:
        raise ReleaseError("use --repo OWNER/REPO when origin is not a GitHub URL")
    return match.group(1)


def publish_release(version, repo, assets):
    if not shutil.which("gh"):
        raise ReleaseError("publishing requires GitHub CLI gh")
    repo = release_repo(repo)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ReleaseError("--publish requires a GitHub OWNER/REPO")
    manifest_asset = next(path for path in assets if path.name == "manifest.json")
    manifest = json.loads(manifest_asset.read_text(encoding="utf-8"))
    platforms = ", ".join(manifest["platforms"])
    tag = "core-" + version
    if github_release_exists(tag, repo):
        # Keep the git tag; no matrix job can race a second deletion.
        command(["gh", "release", "delete", tag, "--repo", repo, "--yes"])
    command(["gh", "release", "create", tag, "--repo", repo, "--title", "xpack-toolkit " + version,
             "--notes", "Offline release; verified platforms: {} (see manifest.json). ".format(platforms)
             + "Remove-all-checks kernel; license is auto-generated and imported locally (no signing key).",
             "--latest"] + [str(path) for path in assets])
    print("Published https://github.com/{}/releases/tag/{}".format(repo, tag), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, type=normalize_version)
    parser.add_argument("--arches", type=parse_arches, default=SUPPORTED_ARCHES,
                        help="verified platforms (default: amd64,arm64)")
    parser.add_argument("--output", type=Path, help="default: build/release-VERSION")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "build/dl",
                        help="reuse official tarballs only after current official SHA verification")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--build-only", action="store_true", help="build without publishing (default)")
    modes.add_argument("--publish", action="store_true", help="build all platforms, then replace one release")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""),
                        help="GitHub OWNER/REPO (default: GITHUB_REPOSITORY, then origin)")
    args = parser.parse_args(argv)
    args.output = (args.output or ROOT / "build" / ("release-" + args.version)).absolute()
    args.cache_dir = args.cache_dir.absolute()
    try:
        assets = build_release(args)
        if args.publish:
            publish_release(args.version, args.repo, assets)
        return 0
    except (ReleaseError, OSError, ValueError, tarfile.TarError) as exc:
        print("release error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
