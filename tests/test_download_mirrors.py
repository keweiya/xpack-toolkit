"""Opt-in public download routing, using temporary offline curl and TTY fixtures.

Run: python3 -m unittest discover -s tests -p test_download_mirrors.py -v
"""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import termios
import threading
import time
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
        self.f.probe_responses(dict(zip(BUILTINS, ("0.100", "0.200", "0.300"))))

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("CURL_MISTAKE", self.f.log())
        self.assert_clean_parts()

    def assert_clean_parts(self):
        self.assertEqual(list(self.f.base.rglob("*.part.*")), [])
        self.assertEqual(list(self.f.temporary.glob("xpack-mirror-probe-*")), [])

    def clear_trace(self):
        self.f.events.unlink(missing_ok=True)
        Path(self.f.env["CURL_TRACE"]).unlink(missing_ok=True)

    def probes(self):
        return [call for call in self.f.curl_trace() if call["probe"]]

    def direct_urls(self, agent=False):
        names = ["manifest.json", "runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig"]
        if agent:
            names.append("agent-linux-amd64.orig")
        return [API_URL] + [self.f.asset_url(name) for name in names]

    def preamble(self, url=API_URL, destination=None):
        program = self.f.script.read_text().split('\nWORK=""', 1)[0]
        program += '\nfetch "$TEST_FETCH_URL" "$TEST_FETCH_DEST"\nprintf "PIPE_BODY_INTACT\\n"\n'
        return program, {"TEST_FETCH_URL": url,
                         "TEST_FETCH_DEST": str(destination or self.f.temporary / "releases.json")}

    def fetch_only(self, url=API_URL, destination=None, options=(), **env):
        # Run the real parser and fetch with the shell program delivered on stdin.
        program, extra = self.preamble(url, destination)
        return subprocess.run(["bash", "-s", "--", *options], input=program, cwd=self.f.base,
                              env={**self.f.env, **extra, **env}, capture_output=True,
                              text=True, start_new_session=True, timeout=30)

    def tty_run(self, answer=None, program=None, options=(), expect_prompt=True, **env):
        program, extra = self.preamble() if program is None else (program, {})
        master, slave = pty.openpty()
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        process = subprocess.Popen(["bash", "-s", "--", *options], cwd=self.f.base,
                                   env={**self.f.env, **extra, **env}, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   pass_fds=(slave,), preexec_fn=controlling_terminal)
        captured = []
        def communicate():
            captured.append(process.communicate(input=program))
        writer = threading.Thread(target=communicate, daemon=True)
        writer.start()
        terminal = b""
        deadline = time.monotonic() + 5
        prompted = False
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    terminal += os.read(master, 65536)
                if b"[y/N]" in terminal:
                    prompted = True
                    if answer is not None:
                        os.write(master, answer.encode())
                    break
                if process.poll() is not None:
                    break
            if expect_prompt and not prompted:
                self.fail("Expected controlling-terminal prompt: " + terminal.decode(errors="replace"))
            if not expect_prompt and prompted:
                self.fail("Offline or explicit mode unexpectedly prompted")
            writer.join(timeout=30)
            if writer.is_alive():
                self.fail("TTY fixture exceeded bounded completion time")
            stdout, stderr = captured[0]
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), terminal.decode(errors="replace")
        finally:
            if process.poll() is None:
                process.kill()
                writer.join(timeout=5)
            os.close(master)
            os.close(slave)

    def test_default_no_tty_is_direct_and_candidates_do_not_opt_in(self):
        self.f.guard_first_api()
        result = self.f.run(piped=True)
        self.ok(result)
        self.assertEqual(self.f.download_urls(), self.direct_urls())
        self.assertEqual(self.probes(), [])
        self.assertNotIn("[y/N]", result.stdout + result.stderr)
        self.assertIn("first-api-readonly", self.f.log())
        for call in self.f.curl_trace():
            args = call["args"]
            for option, value in (("--connect-timeout", "10"), ("--max-time", "1800"),
                                  ("--retry", "1"), ("--retry-max-time", "20"),
                                  ("--speed-limit", "1024"), ("--speed-time", "30")):
                self.assertEqual(args[args.index(option) + 1], value)
            destination = Path(args[args.index("-o") + 1])
            self.assertIn(".part.", destination.name)
            self.assertTrue(destination.resolve().is_relative_to(self.f.base))
            self.assertNotIn("--proxy", args)
            self.assertNotIn("--user", args)
            self.assertNotIn("Authorization", " ".join(args))

    def test_default_direct_failure_has_no_hidden_fallback(self):
        self.f.curl_failures([API_URL])
        result = self.fetch_only()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.urls(), [API_URL])
        self.assertEqual(self.probes(), [])
        self.assert_clean_parts()

    def test_env_direct_and_cli_opt_out_exclusively_use_direct(self):
        for options, environment in (((), {"GH_PROXY": "direct"}),
                                     (("--no-mirror",), {"GH_PROXY": "auto"}),
                                     (("--direct",), {"GH_PROXY": BUILTINS[0]}),
                                     (("--use-mirror", "--direct"), {"GH_PROXY": "auto"})):
            with self.subTest(options=options, environment=environment):
                self.clear_trace()
                self.f.curl_failures([API_URL])
                result = self.fetch_only(options=options, **environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.f.download_urls(), [API_URL])
                self.assertEqual(self.probes(), [])

    def test_custom_gh_proxy_normalizes_and_is_exclusive_even_on_failure(self):
        preferred = "https://preferred.test/gateway/"
        self.f.mirror_urls([preferred])
        self.ok(self.fetch_only(GH_PROXY=preferred.rstrip("/")))
        self.assertEqual(self.f.download_urls(), [preferred + API_URL])
        self.assertEqual(self.probes(), [])
        self.clear_trace()
        self.f.curl_failures([preferred + API_URL])
        result = self.fetch_only(GH_PROXY=preferred)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.download_urls(), [preferred + API_URL])

    def test_cli_custom_url_overrides_env_and_does_not_probe_candidates(self):
        custom = "http://mirror.test/route/"
        self.f.mirror_urls([custom])
        for options in (("--mirror", custom.rstrip("/")), ("--mirror=" + custom + "//",),
                        ("--direct", "--mirror=" + custom)):
            with self.subTest(options=options):
                self.clear_trace()
                self.ok(self.f.run_cli(*options, GH_PROXY=BUILTINS[1], GH_MIRRORS="ftp://unused.test/"))
                self.assertEqual(self.f.download_urls(), [custom + url for url in self.direct_urls()])
                self.assertEqual(self.probes(), [])
                args = self.f.curl_trace()[0]["args"]
                self.assertIn("http", args[args.index("--proto") + 1])

    def test_cli_auto_flags_override_direct_environment(self):
        for options in (("--use-mirror",), ("--mirror", "auto"), ("--mirror=auto",),
                        ("--direct", "--use-mirror")):
            with self.subTest(options=options):
                self.clear_trace()
                self.ok(self.fetch_only(options=options, GH_PROXY="direct"))
                self.assertEqual(len(self.probes()), 3)
                self.assertEqual(self.f.download_urls(), [BUILTINS[0] + API_URL])

    def test_missing_invalid_cli_arguments_exit_before_network(self):
        for options in (("--mirror",), ("--mirror=",), ("--http-proxy",),
                        ("--http-proxy=",), ("--unknown",), ("--mirror", "ftp://bad.test/")):
            with self.subTest(options=options):
                self.clear_trace()
                shutil.rmtree(self.f.work, ignore_errors=True)
                shutil.rmtree(self.f.backup, ignore_errors=True)
                snapshot = self.f.machine_snapshot()
                result = self.f.run_cli(*options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.f.urls(), [])
                self.assertEqual(self.f.machine_snapshot(), snapshot)
                self.assertFalse(self.f.work.exists())

    def test_xpack_http_proxy_and_cli_override_preserve_standard_proxy_environment(self):
        standard = {"http_proxy": "http://user:private@standard.test:8080",
                    "https_proxy": "http://user:private@standard.test:8443"}
        self.ok(self.fetch_only(**standard))
        self.assertNotIn("--proxy", self.f.curl_trace()[-1]["args"])
        self.assertEqual(self.f.curl_trace()[-1]["proxy_env"], standard)
        proxy = "http://proxy-user:proxy-secret@explicit.test:8080"
        for options in ((), ("--http-proxy", proxy), ("--http-proxy=" + proxy,)):
            with self.subTest(options=options):
                self.clear_trace()
                result = self.fetch_only(options=options, XPACK_HTTP_PROXY=proxy if not options else "http://old.test:8080",
                                         GH_PROXY="auto", **standard)
                self.ok(result)
                for call in self.f.curl_trace():
                    args = call["args"]
                    self.assertEqual(args[args.index("--proxy") + 1], proxy)
                    self.assertEqual(call["proxy_env"], standard)
                self.assertNotIn("private", result.stdout + result.stderr)
                self.assertNotIn("proxy-secret", result.stdout + result.stderr)

    def test_auto_ranks_ttfb_and_uses_fastest_for_api_again_and_every_asset_including_agent(self):
        self.f.agent.write_bytes(b"installed agent sentinel")
        self.f.guard_first_api()
        self.f.probe_responses({BUILTINS[0]: "0.800", BUILTINS[1]: "0.040", BUILTINS[2]: "0.300"})
        result = self.f.run(GH_PROXY="auto")
        self.ok(result)
        self.assertEqual({call["args"][-1] for call in self.probes()}, {prefix + API_URL for prefix in BUILTINS})
        self.assertEqual(self.f.download_urls(), [BUILTINS[1] + url for url in self.direct_urls(agent=True)])
        self.assertIn("40.0 ms", result.stderr)
        self.assertIn(BUILTINS[1], result.stdout)
        self.assertEqual(self.f.log().count("first-api-readonly"), 4)
        self.assertEqual(list(self.f.temporary.iterdir()), [])
        for call in self.probes():
            args = call["args"]
            self.assertIn("--tlsv1.2", args)
            self.assertEqual(args[args.index("--write-out") + 1], "\n%{http_code}\t%{time_starttransfer}\n")
            self.assertEqual(args[-1], next(prefix for prefix in BUILTINS if args[-1].startswith(prefix)) + API_URL)

    def test_auto_ties_preserve_candidate_order_and_normalize_duplicates(self):
        prefixes = ("http://mirror.test/route/", "https://another.test/")
        self.f.env["GH_MIRRORS"] = " http://mirror.test/route,\nhttp://mirror.test/route/\t https://another.test/// "
        self.f.mirror_urls(prefixes)
        self.f.probe_responses({prefix: "0.125" for prefix in prefixes})
        self.ok(self.fetch_only(GH_PROXY="auto"))
        self.assertEqual(len(self.probes()), 2)
        self.assertEqual(self.f.download_urls(), [prefixes[0] + API_URL])

    def test_unset_candidates_use_builtins_only_after_explicit_auto(self):
        self.f.env.pop("GH_MIRRORS")
        self.ok(self.fetch_only())
        self.assertEqual(self.f.urls(), [API_URL])
        self.clear_trace()
        self.ok(self.fetch_only(GH_PROXY="auto"))
        self.assertEqual({call["args"][-1] for call in self.probes()}, {prefix + API_URL for prefix in BUILTINS})
        self.assertEqual(self.f.download_urls(), [BUILTINS[0] + API_URL])

    def test_auto_excludes_fast_http_html_rate_limit_malformed_and_empty_api(self):
        invalid = ("<html>gateway unavailable</html>", "{invalid json", '{"message":"rate limited"}',
                   '[{"tag_name":123,"assets":[]}]', '[{"tag_name":"core-v2.3.2","assets":{}}]',
                   '[42]', '[]')
        self.f.guard_first_api()
        for value in invalid:
            with self.subTest(value=value):
                self.clear_trace()
                self.f.curl_responses({BUILTINS[0] + API_URL: value})
                self.f.probe_responses({BUILTINS[0]: "0.001", BUILTINS[1]: "0.120", BUILTINS[2]: "0.300"})
                self.ok(self.fetch_only(GH_PROXY="auto"))
                self.assertEqual(self.f.download_urls(), [BUILTINS[1] + API_URL])
                self.assertFalse(self.f.work.exists())
                self.assertFalse(self.f.backup.exists())

    def test_auto_excludes_invalid_status_exit_nan_zero_negative_and_timeout_metrics(self):
        invalid = ({"status": "429", "time": "0.001"}, {"status": "503", "time": "0.001"},
                   {"exit": 28, "time": "0.001"}, {"time": "NaN"}, {"time": "inf"},
                   {"time": "-0.01"}, {"time": "0"}, {"time": "12.001"}, {"time": "garbage"})
        for metric in invalid:
            with self.subTest(metric=metric):
                self.clear_trace()
                self.f.probe_responses({BUILTINS[0]: metric, BUILTINS[1]: "0.120", BUILTINS[2]: "0.300"})
                self.ok(self.fetch_only(GH_PROXY="auto"))
                self.assertEqual(self.f.download_urls(), [BUILTINS[1] + API_URL])

    def test_auto_accepts_inclusive_twelve_second_upper_bound(self):
        self.f.probe_responses({BUILTINS[0]: "12.000", BUILTINS[1]: "NaN", BUILTINS[2]: "0"})
        self.ok(self.fetch_only(GH_PROXY="auto"))
        self.assertEqual(self.f.download_urls(), [BUILTINS[0] + API_URL])

    def test_auto_all_invalid_fails_before_writes_services_or_direct_download(self):
        destination = self.f.temporary / "releases.json"
        old = b"previous verified target"
        destination.write_bytes(old)
        self.f.guard_first_api()
        snapshot = self.f.machine_snapshot()
        self.f.curl_responses({prefix + API_URL: "<html>invalid HTTP 200 candidate</html>" for prefix in BUILTINS})
        result = self.fetch_only(destination=destination, GH_PROXY="auto")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(destination.read_bytes(), old)
        self.assertEqual(self.f.download_urls(), [])
        self.assertEqual(len(self.probes()), 3)
        self.assertEqual(self.f.machine_snapshot(), snapshot)
        self.assertFalse(self.f.work.exists())
        self.assertFalse(self.f.backup.exists())
        self.assertNotIn("systemctl stop", self.f.log())
        self.assertNotIn("code ", self.f.log())
        self.assert_clean_parts()

    def test_empty_auto_candidates_fail_without_network(self):
        result = self.fetch_only(GH_PROXY="auto", GH_MIRRORS="")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.urls(), [])

    def test_manifest_seventeen_invalid_variants_failover_between_ranked_mirrors(self):
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
        self.assertEqual(len(variants), 17)
        destination = self.f.temporary / "manifest.json"
        (self.f.temporary / "release.tag").write_text("core-" + self.f.man["version"])
        url = self.f.asset_url("manifest.json")
        for variant, invalid in variants.items():
            with self.subTest(variant=variant):
                self.clear_trace()
                self.f.curl_responses({BUILTINS[0] + url: invalid})
                self.ok(self.fetch_only(url, destination, GH_PROXY="auto"))
                self.assertEqual(self.f.download_urls(), [BUILTINS[0] + url, BUILTINS[1] + url])
                self.assertEqual(json.loads(destination.read_text()), self.f.man)
                self.assertNotIn("code ", self.f.log())
                self.assertFalse(self.f.work.exists())

    def test_runtime_core_original_agent_checksum_failover_promotes_next_ranked_for_later_files(self):
        for asset in ("runtime.tar.gz", "core-linux-amd64", "core-linux-amd64.orig", "agent-linux-amd64.orig"):
            with self.subTest(asset=asset):
                self.clear_trace()
                self.f.agent.write_bytes(b"installed agent sentinel")
                url = self.f.asset_url(asset)
                valid = (self.f.assets / asset).read_bytes()
                bad = valid[:-1] + bytes([valid[-1] ^ 1])
                self.f.curl_responses({BUILTINS[0] + url: bad})
                self.ok(self.f.run(GH_PROXY="auto"))
                direct = self.direct_urls(agent=True)
                index = direct.index(url)
                expected = [BUILTINS[0] + value for value in direct[:index + 1]]
                expected += [BUILTINS[1] + value for value in direct[index:]]
                self.assertEqual(self.f.download_urls(), expected)
                run = self.f.last_license().parent
                destination = {"runtime.tar.gz": "runtime.tar.gz", "core-linux-amd64": "core",
                               "core-linux-amd64.orig": "core.orig", "agent-linux-amd64.orig": "agent.orig"}[asset]
                self.assertEqual((run / destination).read_bytes(), valid)
                self.assertEqual(len(self.probes()), 3)

    def test_auto_failure_tries_only_validated_mirrors_never_direct_or_invalid_routes(self):
        url = self.f.asset_url("manifest.json")
        self.f.curl_responses({BUILTINS[2] + API_URL: "<html>invalid</html>"})
        self.f.curl_failures([BUILTINS[0] + url, BUILTINS[1] + url])
        result = self.f.run(GH_PROXY="auto")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.download_urls(), [BUILTINS[0] + API_URL, BUILTINS[0] + url, BUILTINS[1] + url])
        self.assertNotIn(API_URL, self.f.download_urls())
        self.assertNotIn("systemctl stop", self.f.log())
        self.assertEqual(self.f.core.read_bytes(), INITIAL_CORE)
        self.assert_clean_parts()

    def test_all_asset_routes_corrupt_leave_machine_unchanged_and_bad_candidate_unpublished(self):
        url = self.f.asset_url("core-linux-amd64")
        self.f.curl_responses({prefix + url: b"corrupt core" for prefix in BUILTINS})
        snapshot = self.f.machine_snapshot()
        result = self.f.run(GH_PROXY="auto")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.machine_snapshot(), snapshot)
        self.assertEqual(self.f.core.read_bytes(), INITIAL_CORE)
        self.assertNotIn("systemctl stop", self.f.log())
        self.assertNotIn("apply 17", self.f.log())
        self.assertEqual(list(self.f.work.glob("run.*/core")), [])
        self.assert_clean_parts()

    def test_custom_invalid_api_fails_without_any_hidden_route(self):
        for invalid in ("{invalid json", '{"message":"rate limited"}', '[{"tag_name":123,"assets":[]}]'):
            with self.subTest(invalid=invalid):
                self.clear_trace()
                self.f.guard_first_api()
                self.f.curl_responses({BUILTINS[0] + API_URL: invalid})
                result = self.fetch_only(GH_PROXY=BUILTINS[0])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.f.download_urls(), [BUILTINS[0] + API_URL])
                self.assertEqual(self.probes(), [])
                self.assertFalse(self.f.work.exists())
                self.assertFalse(self.f.backup.exists())

    def test_cached_verify_restore_and_local_artifacts_skip_choice_and_probes_even_auto(self):
        self.ok(self.f.run(ARTIFACT_DIR=str(self.f.assets), GH_PROXY="auto", FAIL_CURL="1"))
        self.ok(self.f.run("verify", GH_PROXY="auto", FAIL_CURL="1"))
        self.ok(self.f.run("restore", GH_PROXY="auto", FAIL_CURL="1"))
        self.assertEqual(self.f.urls(), [])

    def test_local_and_cached_modes_have_no_prompt_with_controlling_tty(self):
        completion = {"install": "PIPE_BODY_INTACT",
                      "verify": "Root certificate readback",
                      "restore": "Restored official binaries and root certificate rows"}
        for mode in ("install", "verify", "restore"):
            with self.subTest(mode=mode):
                program = self.f.script.read_text() + '\nprintf "PIPE_BODY_INTACT\\n"\n'
                environment = {"ARTIFACT_DIR": str(self.f.assets)} if mode == "install" else {}
                result, terminal = self.tty_run(program=program, options=(mode,), expect_prompt=False,
                                                FAIL_CURL="1", **environment)
                self.ok(result)
                self.assertEqual(terminal, "")
                self.assertEqual(self.f.urls(), [])
                # verify/restore finish before bash reads the rest of the piped body,
                # so the marker is only observable for install.
                self.assertIn(completion[mode], result.stdout)

    def test_tty_no_empty_eof_default_to_direct_and_preserve_piped_shell_body(self):
        for answer in ("n\n", "\n", "\x04"):
            with self.subTest(answer=repr(answer)):
                self.clear_trace()
                result, terminal = self.tty_run(answer)
                self.ok(result)
                self.assertIn("[y/N]", terminal)
                self.assertEqual(self.f.download_urls(), [API_URL])
                self.assertEqual(self.probes(), [])
                self.assertIn("PIPE_BODY_INTACT", result.stdout)

    def test_tty_yes_selects_auto_and_preserves_piped_shell_body(self):
        self.f.probe_responses({BUILTINS[0]: "0.800", BUILTINS[1]: "0.040", BUILTINS[2]: "0.300"})
        for answer in ("y\n", "Y\n", "yes\n", "1\n"):
            with self.subTest(answer=answer):
                self.clear_trace()
                result, terminal = self.tty_run(answer)
                self.ok(result)
                self.assertIn("[y/N]", terminal)
                self.assertEqual(self.f.download_urls(), [BUILTINS[1] + API_URL])
                self.assertEqual(len(self.probes()), 3)
                self.assertIn("PIPE_BODY_INTACT", result.stdout)

    def test_explicit_modes_skip_tty_prompt(self):
        for choice in ("direct", "auto", BUILTINS[0]):
            with self.subTest(choice=choice):
                self.clear_trace()
                result, terminal = self.tty_run(expect_prompt=False, GH_PROXY=choice)
                self.ok(result)
                self.assertEqual(terminal, "")
                self.assertIn("PIPE_BODY_INTACT", result.stdout)

    def test_invalid_mirror_prefixes_exit_without_network_or_machine_changes(self):
        invalid = ("ftp://mirror.test/", "https://user:secret@mirror.test/",
                   "https://mirror.test/?token=secret", "https://mirror.test/#fragment",
                   "https://mirror.test:bad/", "https://", "https://mirror.test/\x01")
        snapshot = self.f.machine_snapshot()
        for prefix in invalid:
            for variable in ("GH_MIRRORS", "GH_PROXY"):
                with self.subTest(prefix=prefix, variable=variable):
                    self.clear_trace()
                    environment = {variable: prefix}
                    if variable == "GH_MIRRORS": environment["GH_PROXY"] = "auto"
                    result = self.f.run(**environment)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.f.urls(), [])
                    self.assertEqual(self.f.machine_snapshot(), snapshot)
                    self.assertFalse(self.f.work.exists())
                    self.assertFalse(self.f.backup.exists())
                    self.assertNotIn("secret", result.stdout + result.stderr)
                    self.assert_clean_parts()

    def test_only_official_github_https_origins_are_mirrored(self):
        urls = ("https://raw.githubusercontent.com/fixture/xpack/main/file.bin",
                "https://github.com/fixture/xpack/file.bin", "https://api.github.com/fixture/file.bin",
                "http://github.com/fixture/xpack/file.bin", "https://downloads.fixture.test/file.bin",
                "https://github.com.evil.test/file.bin", "https://user:pass@github.com/fixture/file.bin")
        destination = self.f.temporary / "opaque.bin"
        for url in urls:
            with self.subTest(url=url):
                self.clear_trace()
                response = self.f.downloads / "opaque-response"
                response.write_bytes(b"public fixture file")
                mapping = json.loads(Path(self.f.env["CURL_MAP"]).read_text())
                mapping.update({url: str(response), BUILTINS[0] + url: str(response)})
                Path(self.f.env["CURL_MAP"]).write_text(json.dumps(mapping))
                self.ok(self.fetch_only(url, destination, GH_PROXY=BUILTINS[0]))
                mirrored = url.startswith(("https://raw.githubusercontent.com/", "https://github.com/", "https://api.github.com/"))
                self.assertEqual(self.f.download_urls(), [BUILTINS[0] + url] if mirrored else [url])
                self.assertEqual(self.probes(), [])

    def test_nonofficial_url_does_not_trigger_auto_choice_or_probes(self):
        url = "https://downloads.fixture.test/opaque.bin"
        response = self.f.downloads / "opaque-response"
        response.write_bytes(b"public fixture file")
        mapping = json.loads(Path(self.f.env["CURL_MAP"]).read_text())
        mapping[url] = str(response)
        Path(self.f.env["CURL_MAP"]).write_text(json.dumps(mapping))
        self.ok(self.fetch_only(url, self.f.temporary / "opaque.bin", GH_PROXY="auto"))
        self.assertEqual(self.f.urls(), [url])
        self.assertEqual(self.probes(), [])


if __name__ == "__main__":
    unittest.main()
