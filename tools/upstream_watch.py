#!/usr/bin/env python3
"""检测上游 1Panel 是否发布新稳定版，决定是否触发自动破解发布。

上游版本号来源（无需 token，比 GitHub API 更稳）：
    https://resource.fit2cloud.com/1panel/package/v2/stable/latest   ->  "v2.4.0"

判定规则：
    update  ：上游版本 > 本仓库已发布的最新 core-vX.Y.Z，且两架构官方包都已就绪
    pending ：上游版本更新，但官方包/校验文件还没传全（下一轮再试，不报错）
    current ：本仓库已是最新（或更新的）版本

用法：
    python3 tools/upstream_watch.py --repo keweiya/xpack-toolkit
    python3 tools/upstream_watch.py --repo ... --github-output   # 写 $GITHUB_OUTPUT

输出（stdout，key=value）：
    upstream=v2.4.0
    published=v2.4.0
    status=update|pending|current
    version=v2.4.0          # 需要构建的版本（status=update 时有意义）
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_INDEX = "https://resource.fit2cloud.com/1panel/package/v2/stable/latest"
PACKAGE_BASE = "https://resource.fit2cloud.com/1panel/package/v2/stable/{}/release"
ARCHES = ("amd64", "arm64")
TAG_PREFIX = "core-"
VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


class WatchError(Exception):
    """检测失败必须以非 0 退出，避免静默漏掉新版。"""


def fetch(url, timeout=30, limit=1 << 20):
    request = urllib.request.Request(url, headers={"User-Agent": "xpack-watch/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(limit + 1)


def version_key(text):
    match = re.match(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)$", text.strip())
    if not match:
        raise ValueError("not a version: " + text)
    return tuple(int(part) for part in match.groups())


def latest_official():
    text = fetch(VERSION_INDEX).decode("utf-8", "strict").strip()
    if not VERSION_RE.match(text):
        raise WatchError("unexpected upstream version pointer: {!r}".format(text[:80]))
    return text


def packages_ready(version):
    """官方是否已把两架构的包和校验文件传全。"""
    base = PACKAGE_BASE.format(version)
    try:
        checksums = fetch(base + "/checksums.txt").decode("utf-8", "strict")
    except (urllib.error.URLError, OSError, UnicodeError):
        return False
    for arch in ARCHES:
        name = "1panel-{}-linux-{}.tar.gz".format(version, arch)
        if not any(line.rstrip().endswith(" " + name) for line in checksums.splitlines()):
            return False
    return True


def published_versions(repo):
    if not repo:
        return []
    try:
        output = subprocess.run(["gh", "release", "list", "--repo", repo, "--limit", "100",
                                 "--json", "tagName,isDraft,isPrerelease"],
                                text=True, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise WatchError("cannot list releases for {}: {}".format(repo, exc)) from exc
    versions = []
    for item in json.loads(output):
        tag = item.get("tagName") or ""
        if item.get("isDraft") or item.get("isPrerelease") or not tag.startswith(TAG_PREFIX):
            continue
        version = tag[len(TAG_PREFIX):]
        if VERSION_RE.match(version):
            versions.append(version)
    return sorted(versions, key=version_key)


def decide(repo, forced_version=None):
    upstream = forced_version or latest_official()
    published = published_versions(repo)
    latest_published = published[-1] if published else ""
    if forced_version:
        status = "current" if forced_version in published else "update"
    elif latest_published and version_key(upstream) <= version_key(latest_published):
        status = "current"
    elif not packages_ready(upstream):
        status = "pending"
    else:
        status = "update"
    return {
        "upstream": upstream,
        "published": latest_published,
        "status": status,
        "version": upstream if status == "update" else "",
        "published_all": ",".join(published),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""),
                        help="OWNER/REPO（默认取 GITHUB_REPOSITORY）")
    parser.add_argument("--version", help="强制指定版本，跳过上游指针判断")
    parser.add_argument("--github-output", nargs="?", const=os.environ.get("GITHUB_OUTPUT", ""),
                        help="把结果写成 GitHub Actions outputs")
    args = parser.parse_args(argv)
    if args.version and not VERSION_RE.match(args.version):
        print("watch error: version must look like v2.4.0", file=sys.stderr)
        return 2
    try:
        result = decide(args.repo, args.version)
    except (WatchError, ValueError, urllib.error.URLError, OSError) as exc:
        print("watch error: {}".format(exc), file=sys.stderr)
        return 1

    for key in ("upstream", "published", "status", "version", "published_all"):
        print("{}={}".format(key, result[key]))
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as handle:
            for key in ("upstream", "published", "status", "version"):
                handle.write("{}={}\n".format(key, result[key]))
    if result["status"] == "pending":
        print("上游 {} 的官方包尚未传全，本轮跳过。".format(result["upstream"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
