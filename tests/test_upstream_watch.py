#!/usr/bin/env python3
"""tools/upstream_watch.py 的判定逻辑测试（不联网、不调 gh）。"""
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import upstream_watch as watch  # noqa: E402


class VersionKeyTest(unittest.TestCase):
    def test_orders_by_number_not_text(self):
        self.assertGreater(watch.version_key("v2.10.0"), watch.version_key("v2.9.9"))

    def test_accepts_bare_version(self):
        self.assertEqual(watch.version_key("2.4.0"), watch.version_key("v2.4.0"))

    def test_rejects_non_version(self):
        for value in ("latest", "v2.4", "2.4.0.1", ""):
            with self.assertRaises(ValueError):
                watch.version_key(value)


class DecideTest(unittest.TestCase):
    def decide(self, upstream="v2.5.0", published=("v2.4.0",), ready=True, forced=None):
        with mock.patch.object(watch, "latest_official", return_value=upstream), \
             mock.patch.object(watch, "published_versions", return_value=list(published)), \
             mock.patch.object(watch, "packages_ready", return_value=ready):
            return watch.decide("owner/repo", forced)

    def test_new_upstream_triggers_update(self):
        result = self.decide()
        self.assertEqual(result["status"], "update")
        self.assertEqual(result["version"], "v2.5.0")
        self.assertEqual(result["published"], "v2.4.0")

    def test_same_upstream_is_current(self):
        result = self.decide(upstream="v2.4.0")
        self.assertEqual(result["status"], "current")
        self.assertEqual(result["version"], "")

    def test_older_upstream_is_current(self):
        result = self.decide(upstream="v2.3.2", published=("v2.4.0",))
        self.assertEqual(result["status"], "current")

    def test_missing_packages_are_pending(self):
        result = self.decide(ready=False)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["version"], "")

    def test_first_release_without_history(self):
        result = self.decide(upstream="v2.0.0", published=())
        self.assertEqual(result["status"], "update")

    def test_forced_version_already_published(self):
        result = self.decide(upstream="v9.9.9", forced="v2.4.0")
        self.assertEqual(result["status"], "current")

    def test_forced_new_version_skips_package_probe(self):
        result = self.decide(upstream="v9.9.9", ready=False, forced="v9.9.9")
        self.assertEqual(result["status"], "update")
        self.assertEqual(result["version"], "v9.9.9")


class PublishedVersionsTest(unittest.TestCase):
    def test_filters_drafts_and_foreign_tags(self):
        payload = ('[{"tagName":"core-v2.4.0","isDraft":false,"isPrerelease":false},'
                   '{"tagName":"core-v2.5.0","isDraft":true,"isPrerelease":false},'
                   '{"tagName":"core-v2.6.0-rc1","isDraft":false,"isPrerelease":true},'
                   '{"tagName":"v1.0.0","isDraft":false,"isPrerelease":false},'
                   '{"tagName":"core-v2.3.2","isDraft":false,"isPrerelease":false}]')
        completed = mock.Mock(stdout=payload, returncode=0)
        with mock.patch.object(watch.subprocess, "run", return_value=completed):
            self.assertEqual(watch.published_versions("o/r"), ["v2.3.2", "v2.4.0"])

    def test_empty_repo_returns_nothing(self):
        self.assertEqual(watch.published_versions(""), [])


if __name__ == "__main__":
    unittest.main()
