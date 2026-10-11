"""Installer flow regressions (unlock.sh syntax + release selection logic)."""

import json
import re
from pathlib import Path
import subprocess
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


class RuntimeWhitelistTests(unittest.TestCase):
    def test_whitelist_matches_repo_files(self):
        whitelist = {"tools/gen_license.py", "tools/patch_core.py", "tools/patch_agent.py",
                     "tools/cert_store.py", "tools/aes128.py", "tools/gosym.py",
                     "tools/official_rootcert.json", "state/license.crt"}
        for name in whitelist:
            self.assertTrue((ROOT / name).is_file(), name)


def extract_heredoc(script, marker):
    """Extract the first ``<<'PY' ... PY`` heredoc whose body contains marker."""
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY", script, flags=re.S)
    for block in blocks:
        if marker in block:
            return block
    raise AssertionError("heredoc not found: " + marker)


class MirrorConfigTests(unittest.TestCase):
    """The mirror-prefix validator embedded in unlock.sh (unchanged download routing)."""

    @classmethod
    def setUpClass(cls):
        cls.code = extract_heredoc(UNLOCK.read_text(), "GitHub mirror prefix")

    def run_parser(self, preferred, configured):
        return subprocess.run(
            ["python3", "-c", self.code, preferred, configured],
            capture_output=True, text=True)

    def test_direct_and_auto(self):
        self.assertEqual(self.run_parser("direct", "https://a.test/").returncode, 0)
        self.assertEqual(self.run_parser("auto", "https://a.test/ https://b.test/").returncode, 0)
        out = self.run_parser("auto", " https://a.test/ , https://b.test/ ").stdout
        self.assertEqual(out.splitlines(), ["https://a.test/", "https://b.test/"])

    def test_invalid_prefixes_rejected(self):
        for prefix in ("ftp://m.test/", "https://user:pass@m.test/",
                       "https://m.test/?x=1", "https://m.test/#f", "https://m.test:bad/"):
            result = self.run_parser("", prefix)
            self.assertNotEqual(result.returncode, 0, prefix)
            self.assertIn("Invalid GitHub mirror", result.stderr)


if __name__ == "__main__":
    unittest.main()
