"""Installer flow regressions (unlock.sh syntax + release selection logic)."""

import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNLOCK = ROOT / "unlock.sh"


def version_key(value):
    return tuple(map(int, value.lstrip("v").split(".")))


def select_release(releases_json):
    """Mirror of the selection logic embedded in unlock.sh."""
    def version(value):
        return tuple(map(int, value.lstrip("v").split(".")))
    releases = []
    for release in releases_json:
        tag = release.get("tag_name", "")
        if (release.get("draft") or release.get("prerelease")
                or not re.fullmatch(r"core-v\d+\.\d+\.\d+", tag)):
            continue
        releases.append((version(tag[5:]), release))
    if not releases:
        raise SystemExit("No stable project release is published")
    return max(releases, key=lambda item: item[0])[1]["tag_name"]


class UnlockFlowTests(unittest.TestCase):
    def test_bash_syntax(self):
        result = subprocess.run(["bash", "-n", str(UNLOCK)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_version_comparison_newer(self):
        self.assertGreater(version_key("v2.3.2"), version_key("v2.2.0"))
        self.assertEqual(version_key("v2.3.2"), version_key("2.3.2"))

    def test_select_release_ignores_prerelease_and_draft(self):
        data = [
            {"tag_name": "core-v2.3.1", "draft": False, "prerelease": False,
             "assets": [{"name": "manifest.json", "browser_download_url": "u"}]},
            {"tag_name": "core-v2.3.2", "draft": False, "prerelease": False,
             "assets": [{"name": "manifest.json", "browser_download_url": "u"}]},
            {"tag_name": "core-v2.4.0-rc1", "draft": False, "prerelease": True,
             "assets": [{"name": "manifest.json", "browser_download_url": "u"}]},
            {"tag_name": "core-v2.5.0", "draft": True, "prerelease": False,
             "assets": [{"name": "manifest.json", "browser_download_url": "u"}]},
        ]
        self.assertEqual(select_release(data), "core-v2.3.2")

    def test_select_release_rejects_garbage(self):
        self.assertEqual(select_release([
            {"tag_name": "core-v2.3.2", "draft": False, "prerelease": False,
             "assets": [{"name": "manifest.json", "browser_download_url": "u"}]},
            {"tag_name": "not-a-release", "draft": False, "prerelease": False,
             "assets": [{"name": "manifest.json", "browser_download_url": "u"}]},
        ]), "core-v2.3.2")


def extract_tool_files(script):
    match = re.search(r'TOOL_FILES="([^"]+)"', script)
    if not match:
        raise AssertionError("TOOL_FILES declaration not found in unlock.sh")
    return match.group(1).split()


class RuntimeToolFilesTests(unittest.TestCase):
    """工具脚本现在从 main 分支下载，不再打进 runtime.tar.gz。"""

    def test_tool_files_exist_in_repo(self):
        for name in extract_tool_files(UNLOCK.read_text()):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_tool_files_drop_legacy_cert_store(self):
        # 遗留的 cert_store.py / official_rootcert.json 已不再随安装流程下载。
        files = set(extract_tool_files(UNLOCK.read_text()))
        self.assertNotIn("tools/cert_store.py", files)
        self.assertNotIn("tools/official_rootcert.json", files)


def extract_heredoc(script, marker):
    """Extract the first ``<<'PY' ... PY`` heredoc whose body contains marker."""
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY", script, flags=re.S)
    for block in blocks:
        if marker in block:
            return block
    raise AssertionError("heredoc not found: " + marker)


class RouteAndAssetsTests(unittest.TestCase):
    """下载线路只探测一次；Agent 只替换不打补丁；替换前有版本门禁。"""

    @classmethod
    def setUpClass(cls):
        cls.script = UNLOCK.read_text()

    def test_no_mirror_switches_left(self):
        for flag in ("--use-mirror", "--mirror", "--no-mirror", "--direct", "GH_MIRRORS"):
            self.assertNotIn(flag, self.script, flag)
        self.assertNotIn("rank_mirrors", self.script)
        self.assertNotIn("configure_mirrors", self.script)

    def test_single_probe_decides_the_route(self):
        self.assertIn('GH_MIRROR="${GH_MIRROR:-https://ghfast.top/}"', self.script)
        self.assertIn("probe_route", self.script)
        self.assertIn('if [ "$STATUS" = 200 ]', self.script)
        # 探测只跑一次，结果对整个流程生效
        self.assertEqual(self.script.count("ROUTE_READY=1"), 1)
        self.assertEqual(self.script.count("ROUTE_READY=0"), 1)
        self.assertEqual(self.script.count("probe_route"), 2)   # 定义 + fetch 里调用
        self.assertIn('ROUTES=("$MIRROR_PREFIX$URL" "$URL")', self.script)
        # api.github.com 不套镜像（网关会 403）
        self.assertNotIn("https://api.github.com/*)", self.script)

    def test_bootstrap_prefix_wins_over_probe(self):
        self.assertIn("BOOTSTRAP_PREFIX", self.script)
        detect = self.script.index("detect_bootstrap_route\n")
        self.assertLess(detect, self.script.index("probe_route() {"))
        # 探测前先看启动前缀
        probe = self.script.index("probe_route() {")
        body = self.script[probe:probe + 1200]
        self.assertLess(body.index("BOOTSTRAP_PREFIX"), body.index("GH_MIRROR_FORCE"))

    def test_bootstrap_prefix_parser(self):
        import subprocess
        fn = re.search(r"^mirror_prefix_from_url\(\) \{.*?^\}", self.script, flags=re.S | re.M).group(0)
        cases = {
            "https://ghfast.top/https://raw.githubusercontent.com/a/b/main/unlock.sh": "https://ghfast.top/",
            "https://raw.githubusercontent.com/a/b/main/unlock.sh": "",
            "https://gh-proxy.com/https://github.com/a/b/releases/download/x/y": "https://gh-proxy.com/",
        }
        for url, expected in cases.items():
            result = subprocess.run(["bash", "-c", fn + '\nmirror_prefix_from_url "$1"', "_", url],
                                    capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), expected, url)

    def test_agent_is_replaced_not_patched(self):
        self.assertNotIn("agent.orig.url", self.script)
        self.assertNotIn("--patch --in \"$RUN/agent.orig\"", self.script)
        self.assertIn("Verified patched agent sha256 + arch", self.script)
        self.assertIn("No downloadable $PLATFORM agent", self.script)

    def test_version_gate_runs_before_replacement(self):
        gate = self.script.index("Version mismatch (installed")
        replace = self.script.index('install -m 0755 "$RUN/core" "$CORE_BIN"')
        self.assertLess(gate, replace)


class ReleaseSelectionTests(unittest.TestCase):
    """select_release 支持 API 与 atom 两种来源，资产 URL 都要能拼出来。"""

    @classmethod
    def setUpClass(cls):
        cls.code = extract_heredoc(UNLOCK.read_text(), "releases.atom")

    def run_parser(self, run, platform, source):
        return subprocess.run([sys.executable, "-c", self.code, str(run), platform,
                               "keweiya/xpack-toolkit", source],
                              capture_output=True, text=True)

    def test_atom_source_picks_highest_and_builds_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "releases.atom").write_text(
                "<feed><entry><title>core-v2.4.0</title></entry>"
                "<entry><title>core-v2.4.1</title></entry></feed>")
            result = self.run_parser(run, "linux-arm64", "atom")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((run / "selected.version").read_text(), "v2.4.1")
            self.assertIn("core-linux-arm64", (run / "core.url").read_text())
            self.assertIn("agent-linux-arm64", (run / "agent.url").read_text())
            self.assertIn("core-v2.4.1", (run / "manifest.url").read_text())

    def test_api_source_uses_published_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "releases.json").write_text(json.dumps([{
                "tag_name": "core-v2.4.1", "draft": False, "prerelease": False,
                "assets": [{"name": n, "browser_download_url": "https://x/" + n}
                           for n in ("manifest.json", "core-linux-amd64",
                                     "core-linux-amd64.orig", "agent-linux-amd64")]}]))
            result = self.run_parser(run, "linux-amd64", "api")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((run / "core.url").read_text(), "https://x/core-linux-amd64")
            self.assertEqual((run / "agent.url").read_text(), "https://x/agent-linux-amd64")


class VersionGateTests(unittest.TestCase):
    """升级后数据库版本还没迁移完时，门禁要认 1pctl 里的包版本。"""

    @classmethod
    def setUpClass(cls):
        cls.script = UNLOCK.read_text()
        cls.fn = re.search(r"^ctl_version\(\) \{.*?^\}", cls.script, flags=re.S | re.M).group(0)

    def test_reads_original_version_from_1pctl(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctl = Path(tmp) / "1pctl"
            ctl.write_text('#!/bin/bash\nBASE_DIR=/opt/1panel\nORIGINAL_VERSION=v2.4.1\n')
            result = subprocess.run(["bash", "-c", self.fn + '\nPANEL_CTL="$1"; ctl_version', "_", str(ctl)],
                                    capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), "v2.4.1")

    def test_missing_1pctl_yields_empty(self):
        result = subprocess.run(["bash", "-c", self.fn + '\nPANEL_CTL=/nonexistent; ctl_version'],
                                capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "")

    def test_gate_consults_1pctl_before_waiting(self):
        gate = self.script.index("Version check passed on the installed 1pctl")
        wait = self.script.index("wait_for_version \"$RELEASE_VERSION\"")
        self.assertLess(gate, wait)


class ScriptStartupTests(unittest.TestCase):
    """脚本头部必须能把 set -u 下的变量都准备好，且不因缺变量崩在启动阶段。"""

    def test_platform_and_ctl_variables_defined(self):
        script = UNLOCK.read_text()
        for line in ('[ "$(id -u)" -eq 0 ] || die "Run as root"',
                     'PLATFORM="linux-$ARCH"',
                     'PANEL_CTL="${PANEL_CTL:-/usr/local/bin/1pctl}"'):
            self.assertIn(line, script)

    @unittest.skipUnless(os.geteuid() == 0, "需要在 root 下执行脚本")
    def test_fake_env_fails_on_version_detection_not_unbound_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            environment = os.environ.copy()
            environment.update({
                "PANEL_ROOT": tmp, "CORE_BIN": tmp + "/core", "AGENT_BIN": tmp + "/agent",
                "BACKUP": tmp + "/backup", "UNLOCK_WORK": tmp + "/unlock",
                "PANEL_CTL": tmp + "/1pctl",
            })
            run = subprocess.run(["bash", str(UNLOCK), "install", "--no-progress"],
                                 capture_output=True, text=True, env=environment, timeout=180)
            self.assertEqual(run.returncode, 1)
            self.assertNotIn("unbound variable", run.stderr)
            self.assertIn("Installed panel version was not detected", run.stderr)


if __name__ == "__main__":
    unittest.main()
