"""Public download routing tests using temporary, offline curl fixtures only.

Run: python3 -m unittest discover -s tests -p test_download_mirrors.py -v
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_unlock import API_URL, Fixture, INITIAL_CORE


BUILTINS = ("https://ghfast.top/", "https://gh-proxy.com/", "https://ghproxy.net/")


class DownloadMirrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="public-download-mirrors-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)
        self.f.env["GH_MIRRORS"] = " ".join(BUILTINS)
        self.f.mirror_urls(BUILTINS)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("CURL_MISTAKE", self.f.log())
        self.assert_clean_parts()

    def assert_clean_parts(self):
        self.assertEqual(list(self.f.base.rglob("*.part.*")), [])

    def direct_urls(self, agent=False):
        names = ["manifest.json", "runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig"]
        if agent:
            names.append("agent-linux-amd64.orig")
        return [API_URL] + [self.f.asset_url(name) for name in names]

    def fetch_only(self, url=API_URL, destination=None, **env):
        # Execute the actual installer preamble and fetch function, without services.
        program = self.f.script.read_text().split('\nWORK=""', 1)[0]
        program += '\nfetch "$TEST_FETCH_URL" "$TEST_FETCH_DEST"\n'
        destination = destination or self.f.temporary / "releases.json"
        return subprocess.run(["bash", "-c", program], cwd=self.f.base,
                              env={**self.f.env, "TEST_FETCH_URL": url,
                                   "TEST_FETCH_DEST": str(destination), **env},
                              capture_output=True, text=True, timeout=120)

    def test_direct_success_uses_no_mirrors_and_bounded_atomic_downloads(self):
        self.f.guard_first_api()
        self.ok(self.f.run())
        self.assertEqual(self.f.urls(), self.direct_urls())
        for call in self.f.curl_trace():
            args = call["args"]
            for option, value in (("--connect-timeout", "10"), ("--max-time", "180"),
                                  ("--retry", "1"), ("--retry-max-time", "20")):
                self.assertEqual(args[args.index(option) + 1], value)
            destination = Path(args[args.index("-o") + 1])
            self.assertIn(".part.", destination.name)
            self.assertTrue(destination.resolve().is_relative_to(self.f.base))
            self.assertNotIn("--proxy", args)
            self.assertNotIn("--user", args)
            self.assertNotIn("Authorization", " ".join(args))
        self.assertIn("first-api-readonly", self.f.log())

    def test_api_http_failure_then_html_gateway_then_valid_mirror(self):
        self.f.guard_first_api()
        self.f.curl_failures([API_URL])
        self.f.curl_responses({BUILTINS[0] + API_URL: "<html>gateway unavailable</html>"})
        self.ok(self.f.run())
        self.assertEqual(self.f.urls(), [API_URL, BUILTINS[0] + API_URL,
                                       BUILTINS[1] + API_URL] + self.direct_urls()[1:])
        self.assertEqual(self.f.log().count("first-api-readonly"), 3)

    def test_unset_mirrors_uses_default_builtins_in_documented_order(self):
        self.f.env.pop("GH_MIRRORS")
        self.f.curl_failures([API_URL] + [prefix + API_URL for prefix in BUILTINS[:2]])
        self.ok(self.fetch_only())
        self.assertEqual(self.f.urls(), [API_URL] + [prefix + API_URL for prefix in BUILTINS])

    def test_explicit_gh_proxy_is_preferred_before_direct_and_remaining_mirrors(self):
        preferred = "https://preferred.test/gateway/"
        self.f.mirror_urls([preferred])
        self.f.env["GH_PROXY"] = preferred.rstrip("/")
        self.ok(self.fetch_only())
        self.assertEqual(self.f.urls(), [preferred + API_URL])
        self.f.events.unlink()
        self.f.curl_failures([preferred + API_URL, API_URL])
        self.ok(self.fetch_only())
        self.assertEqual(self.f.urls(), [preferred + API_URL, API_URL, BUILTINS[0] + API_URL])

    def test_custom_http_prefixes_whitespace_commas_and_duplicates_normalize(self):
        prefixes = ("http://mirror.test/route/", "https://another.test/")
        self.f.env["GH_MIRRORS"] = "  http://mirror.test/route,\nhttp://mirror.test/route/\t https://another.test/// "
        self.f.mirror_urls(prefixes)
        self.f.curl_failures([API_URL, prefixes[0] + API_URL])
        self.ok(self.fetch_only())
        self.assertEqual(self.f.urls(), [API_URL] + [prefix + API_URL for prefix in prefixes])
        args = self.f.curl_trace()[1]["args"]
        self.assertIn("http", args[args.index("--proto") + 1])

    def test_direct_override_and_explicit_empty_mirror_list_disable_fallback(self):
        for overrides in ({"GH_PROXY": "direct"}, {"GH_MIRRORS": ""}):
            with self.subTest(**overrides):
                self.f.events.unlink(missing_ok=True)
                self.f.curl_failures([API_URL])
                result = self.fetch_only(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.f.urls(), [API_URL])
                self.assert_clean_parts()

    def test_xpack_http_proxy_is_explicit_and_standard_proxy_environment_is_preserved(self):
        standard = {"http_proxy": "http://user:private@standard.test:8080",
                    "https_proxy": "http://user:private@standard.test:8443"}
        self.ok(self.fetch_only(**standard))
        self.assertNotIn("--proxy", self.f.curl_trace()[-1]["args"])
        self.assertEqual(self.f.curl_trace()[-1]["proxy_env"], standard)
        proxy = "http://proxy-user:proxy-secret@explicit.test:8080"
        result = self.fetch_only(XPACK_HTTP_PROXY=proxy, **standard)
        self.ok(result)
        args = self.f.curl_trace()[-1]["args"]
        self.assertEqual(args[args.index("--proxy") + 1], proxy)
        self.assertEqual(self.f.curl_trace()[-1]["proxy_env"], standard)
        self.assertNotIn("private", result.stdout + result.stderr)
        self.assertNotIn("proxy-secret", result.stdout + result.stderr)

    def test_api_invalid_json_http_200_is_retried_before_persistent_writes(self):
        for invalid in ("{invalid json", '{"message":"rate limited"}',
                        '[{"tag_name":123,"assets":[]}]'):
            with self.subTest(invalid=invalid):
                self.f.events.unlink(missing_ok=True)
                self.f.guard_first_api()
                self.f.curl_responses({API_URL: invalid})
                self.ok(self.fetch_only())
                self.assertEqual(self.f.urls(), [API_URL, BUILTINS[0] + API_URL])
                self.assertFalse(self.f.work.exists())
                self.assertFalse(self.f.backup.exists())

    def test_manifest_html_or_wrong_release_version_retries_valid_mirror(self):
        variants = {"html": "<html>download page</html>"}
        for key, value in (("version", "v9.9.9"), ("root_fingerprint", "0" * 64),
                           ("schema_version", 1), ("name", "different-project"),
                           ("mode", "online"), ("remote_base", "https://remote.test/")):
            variants[key] = json.dumps(dict(self.f.man, **{key: value}))
        for key, value in (("os", "darwin"), ("arch", "arm64"), ("patches", 4),
                           ("core_asset", "core"), ("orig_asset", "core.orig"),
                           ("sha256", "invalid hash"), ("orig_size", True)):
            wrong = json.loads(json.dumps(self.f.man))
            wrong["platforms"]["linux-amd64"][key] = value
            variants["platform-" + key] = json.dumps(wrong)
        for key, value in (("asset", "runtime.zip"), ("sha256", "invalid hash"), ("size", 0)):
            wrong = json.loads(json.dumps(self.f.man))
            wrong["runtime"][key] = value
            variants["runtime-" + key] = json.dumps(wrong)
        destination = self.f.temporary / "manifest.json"
        (self.f.temporary / "release.tag").write_text("core-" + self.f.man["version"])
        url = self.f.asset_url("manifest.json")
        for variant, invalid in variants.items():
            with self.subTest(variant=variant):
                self.f.events.unlink(missing_ok=True)
                self.f.curl_responses({url: invalid})
                self.ok(self.fetch_only(url, destination))
                self.assertEqual(self.f.urls(), [url, BUILTINS[0] + url])
                self.assertEqual(json.loads(destination.read_text()), self.f.man)
                self.assertNotIn("code ", self.f.log())
                self.assertFalse(self.f.work.exists())

    def test_runtime_core_original_and_agent_checksum_retry_without_publishing_bad_candidate(self):
        for asset in ("runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig",
                      "agent-linux-amd64.orig"):
            with self.subTest(asset=asset):
                self.f.events.unlink(missing_ok=True)
                self.f.agent.write_bytes(b"installed agent sentinel")
                url = self.f.asset_url(asset)
                valid = (self.f.assets / asset).read_bytes()
                bad = valid[:-1] + bytes([valid[-1] ^ 1])
                self.f.curl_responses({url: bad, BUILTINS[0] + url: bad})
                self.ok(self.f.run())
                direct = self.direct_urls(agent=True)
                index = direct.index(url)
                self.assertEqual(self.f.urls(), direct[:index + 1] +
                                 [BUILTINS[0] + url, BUILTINS[1] + url] + direct[index + 1:])
                run = self.f.last_license().parent
                destination = {"runtime.tar.gz": "runtime.tar.gz", "core-linux-amd64": "core",
                               "core-linux-amd64.orig": "core.orig",
                               "agent-linux-amd64.orig": "agent.orig"}[asset]
                self.assertEqual((run / destination).read_bytes(), (self.f.assets / asset).read_bytes())

    def test_all_mirror_failures_leave_machine_data_and_existing_target_unchanged(self):
        destination = self.f.temporary / "releases.json"
        old = b"previous verified target"
        destination.write_bytes(old)
        self.f.curl_failures([API_URL] + [prefix + API_URL for prefix in BUILTINS])
        result = self.fetch_only(destination=destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(destination.read_bytes(), old)
        self.assertEqual(self.f.urls(), [API_URL] + [prefix + API_URL for prefix in BUILTINS])
        self.assert_clean_parts()
        self.f.events.unlink()
        self.f.curl_failures([])
        self.f.curl_responses({route: "<html>invalid HTTP 200 candidate</html>" for route in
                              [API_URL] + [prefix + API_URL for prefix in BUILTINS]})
        result = self.fetch_only(destination=destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(destination.read_bytes(), old)
        self.assert_clean_parts()
        self.f.events.unlink()
        url = self.f.asset_url("core-linux-amd64")
        self.f.curl_responses({route: b"corrupt core" for route in
                              [url] + [prefix + url for prefix in BUILTINS]})
        snapshot = self.f.machine_snapshot()
        result = self.f.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.machine_snapshot(), snapshot)
        self.assertEqual(self.f.core.read_bytes(), INITIAL_CORE)
        self.assertNotIn("systemctl stop", self.f.log())
        self.assertNotIn("apply 17", self.f.log())
        self.assertEqual(list(self.f.work.glob("run.*/core")), [])
        self.assert_clean_parts()

    def test_cached_verify_restore_and_local_artifacts_use_no_http(self):
        self.ok(self.f.run(ARTIFACT_DIR=str(self.f.assets), FAIL_CURL="1"))
        self.assertEqual(self.f.urls(), [])
        self.ok(self.f.run("verify", FAIL_CURL="1"))
        self.ok(self.f.run("restore", FAIL_CURL="1"))
        self.assertEqual(self.f.urls(), [])

    def test_invalid_mirror_configuration_exits_early_without_network_or_data_changes(self):
        invalid = ("ftp://mirror.test/", "https://user:secret@mirror.test/",
                   "https://mirror.test/?token=secret", "https://mirror.test/#fragment",
                   "https://mirror.test:bad/", "https://", "https://mirror.test/\x01")
        snapshot = self.f.machine_snapshot()
        for prefix in invalid:
            for variable in ("GH_MIRRORS", "GH_PROXY"):
                with self.subTest(prefix=prefix, variable=variable):
                    self.f.events.unlink(missing_ok=True)
                    result = self.f.run(**{variable: prefix})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.f.urls(), [])
                    self.assertEqual(self.f.machine_snapshot(), snapshot)
                    self.assertFalse(self.f.work.exists())
                    self.assertFalse(self.f.backup.exists())
                    self.assertNotIn("secret", result.stdout + result.stderr)
                    self.assert_clean_parts()

    def test_only_official_github_origins_are_mirrored_and_original_scheme_is_preserved(self):
        urls = ("https://raw.githubusercontent.com/fixture/xpack/main/file.bin",
                "https://github.com/fixture/xpack/file.bin", "http://github.com/fixture/xpack/file.bin",
                "https://downloads.fixture.test/file.bin", "https://github.com.evil.test/file.bin")
        destination = self.f.temporary / "opaque.bin"
        for url in urls:
            with self.subTest(url=url):
                self.f.events.unlink(missing_ok=True)
                response = self.f.downloads / "opaque-response"
                response.write_bytes(b"public fixture file")
                mapping = json.loads(Path(self.f.env["CURL_MAP"]).read_text())
                mapping.update({url: str(response), BUILTINS[0] + url: str(response)})
                Path(self.f.env["CURL_MAP"]).write_text(json.dumps(mapping))
                self.f.curl_failures([url])
                result = self.fetch_only(url, destination)
                mirrored = url.startswith(("https://raw.githubusercontent.com/", "https://github.com/"))
                self.assertEqual(result.returncode == 0, mirrored, result.stdout + result.stderr)
                self.assertEqual(self.f.urls(), [url, BUILTINS[0] + url] if mirrored else [url])
                self.assert_clean_parts()


if __name__ == "__main__":
    unittest.main()
