#!/usr/bin/env python3
"""发布前自检：manifest 与资产一致 + 内核/Agent 补丁可复现。

在 build-only 之后、publish 之前跑；任何一项失败都以非 0 退出，发布流程随即中止。

检查内容：
    1. manifest.json 记录的大小 / sha256 与磁盘上的资产一致
    2. patch_core.py --verify 在破解内核上全部 PATCHED（8/8）
    3. agent 原件能被 patch_agent.py 完整改写并复验（8/8）
    4. 内核体积不变（等长覆盖，避免破坏 ELF 布局）

用法：
    python3 tools/verify_release.py --release build/release-v2.4.0
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PATCHES = 8
# Agent 的 X-Pack 开关改写只在 amd64 上验证过；arm64 保留官方 Agent（unlock.sh 也这么装）。
AGENT_PATCH_PLATFORMS = ("linux-amd64",)


class VerifyError(Exception):
    """自检失败；不允许继续发布。"""


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command):
    result = subprocess.run([sys.executable] + [str(part) for part in command],
                            text=True, capture_output=True)
    if result.returncode != 0:
        raise VerifyError("command failed ({}): {}\n{}{}".format(
            result.returncode, command[0], result.stdout, result.stderr))
    return result.stdout


def check_platform(release, platform, info):
    core = release / info["core_asset"]
    original = release / info["orig_asset"]
    agent = release / info["agent_orig_asset"]
    for path in (core, original, agent):
        if not path.is_file():
            raise VerifyError("missing asset: " + str(path))
    if sha256(core) != info["sha256"]:
        raise VerifyError("core sha256 mismatch: " + str(core))
    if sha256(original) != info["orig_sha256"]:
        raise VerifyError("orig sha256 mismatch: " + str(original))
    if sha256(agent) != info["agent_orig_sha256"]:
        raise VerifyError("agent sha256 mismatch: " + str(agent))
    if core.stat().st_size != original.stat().st_size:
        raise VerifyError("patched core changed size (not an equal-length patch): " + str(core))

    listing = run([ROOT / "tools/patch_core.py", "--in", core, "--verify"])
    patched = listing.count("PATCHED")
    if patched != EXPECTED_PATCHES or "ORIG" in listing or "UNKNOWN" in listing:
        raise VerifyError("core patches incomplete for {}:\n{}".format(platform, listing))

    if platform not in AGENT_PATCH_PLATFORMS:
        return patched, "跳过（该平台保留官方 Agent）"
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "agent"
        run([ROOT / "tools/patch_agent.py", "--in", agent, "--out", target, "--patch"])
        listing = run([ROOT / "tools/patch_agent.py", "--in", target, "--verify"])
        if "all patches present" not in listing:
            raise VerifyError("agent patches incomplete for {}:\n{}".format(platform, listing))
        if target.stat().st_size != agent.stat().st_size:
            raise VerifyError("patched agent changed size: " + str(target))
    return patched, "8/8"


def verify(release):
    manifest_path = release / "manifest.json"
    if not manifest_path.is_file():
        raise VerifyError("missing manifest: " + str(manifest_path))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 2 or manifest.get("name") != "xpack-toolkit":
        raise VerifyError("unexpected manifest schema: {} {}".format(
            manifest.get("schema_version"), manifest.get("name")))
    runtime = release / "runtime.tar.gz"
    if not runtime.is_file() or sha256(runtime) != (manifest.get("runtime") or {}).get("sha256"):
        raise VerifyError("runtime.tar.gz does not match manifest")
    platforms = manifest.get("platforms") or {}
    if not platforms:
        raise VerifyError("manifest lists no platforms")
    print("release  : {}".format(release))
    print("version  : {}".format(manifest.get("version")))
    for platform, info in sorted(platforms.items()):
        count, agent_state = check_platform(release, platform, info)
        print("  [ok] {:<13} core {}  {} 内核补丁  agent {}".format(
            platform, info["sha256"][:16], count, agent_state))
    print("自检通过：{} 个平台".format(len(platforms)))
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verify(args.release.resolve())
        return 0
    except (VerifyError, OSError, ValueError, KeyError) as exc:
        print("verify error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
