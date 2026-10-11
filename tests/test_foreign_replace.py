"""Third-party authorization replacement and download progress, fully offline.

Every case runs the real unlock.sh against the temporary mock tools in
tests/test_unlock.py: no network, no service, no live database, no signing key
from a real installation.

Run: python3 -m unittest discover -s tests -p test_foreign_replace.py -v
"""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import sqlite3
import subprocess
import tempfile
import termios
import threading
import time
import unittest

from test_unlock import API_URL, Fixture, sha


FIRST = "https://ghfast.top/"
SECOND = "https://gh-proxy.com/"
PROMPT = "是否直接替换为本站内核授权"
KEEP_LOG = "-> keeping third-party certificates and licenses"
REPLACE_LOG = "-> replacing with our kernel"


class ForeignReplaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="foreign-replace-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    # ---------------------------------------------------------------- helpers
    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.f.part_files(), [], "temporary transfer artifacts survived")

    def fresh(self, third_party_roots=True, third_party_licenses=0):
        """A brand new fixture, optionally carrying third-party authorization state."""
        base = tempfile.mkdtemp(prefix="foreign-replace-case-")
        self.addCleanup(shutil.rmtree, base, True)
        self.f = Fixture(base)
        if third_party_roots: self.f.third_party_roots()
        if third_party_licenses: self.f.third_party_licenses(third_party_licenses)
        return self.f

    def local_artifacts(self):
        """Reuse the verified fixture release: the choice never depends on downloads."""
        return {"ARTIFACT_DIR": str(self.f.assets)}

    def new_flags(self):
        return [call for call in self.f.gen_license_calls()
                if "--replace-foreign" in call or "--drop-foreign-licenses" in call]

    def apply_calls(self):
        return [call for call in self.f.gen_license_calls() if " --apply " in call]

    def drop_calls(self):
        return [call for call in self.f.gen_license_calls() if "--drop-foreign-licenses" in call]

    def rows(self):
        with sqlite3.connect(self.f.db) as c:
            return c.execute("select bind_node_id,license from licenses order by rowid").fetchall()

    def tty_run(self, answer=None, options=(), expect_prompt=True, **env):
        """Install through a real controlling terminal, exactly like curl | bash."""
        program = self.f.script.read_text() + '\nprintf "PIPE_BODY_INTACT\\n"\n'
        master, slave = pty.openpty()
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        process = subprocess.Popen(["bash", "-s", "--", *options], cwd=self.f.base,
                                   env={**self.f.env, **env}, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   pass_fds=(slave,), preexec_fn=controlling_terminal)
        captured, chunks = [], []
        writer = threading.Thread(target=lambda: captured.append(process.communicate(input=program)),
                                  daemon=True)
        writer.start()
        def drain():
            while True:
                try:
                    ready, _, _ = select.select([master], [], [], 0.1)
                    if ready:
                        data = os.read(master, 65536)
                        if not data: return
                        chunks.append(data)
                except (OSError, ValueError):
                    return
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        def terminal():
            return b"".join(chunks).decode(errors="replace")
        try:
            prompted = False
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if "[Y/n]" in terminal():
                    prompted = True
                    if answer is not None: os.write(master, answer.encode())
                    break
                if process.poll() is not None: break
                time.sleep(0.05)
            if expect_prompt and not prompted:
                self.fail("Expected the third-party prompt on the controlling terminal: " + terminal())
            if not expect_prompt and prompted:
                self.fail("A third-party choice was made explicitly yet the installer prompted")
            writer.join(timeout=240)
            if writer.is_alive(): self.fail("Terminal fixture exceeded its bounded completion time")
            time.sleep(0.2)
            stdout, _ = captured[0]
            return subprocess.CompletedProcess(process.args, process.returncode, stdout,
                                               terminal()), terminal()
        finally:
            if process.poll() is None:
                process.kill()
                writer.join(timeout=5)
            os.close(master)
            os.close(slave)

    def fetch_stderr_tty(self, url, destination=None, **env):
        """Run one real fetch with stderr attached to a pty, as an interactive shell has."""
        program, extra = self.f.fetch_program(url, destination)
        master, slave = pty.openpty()
        process = subprocess.Popen(["bash", "-s", "--"], cwd=self.f.base,
                                   env={**self.f.env, **extra, **env}, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=slave, text=True, pass_fds=(slave,))
        captured = []
        writer = threading.Thread(target=lambda: captured.append(process.communicate(input=program)),
                                  daemon=True)
        writer.start()
        terminal = b""
        try:
            while writer.is_alive():
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try: terminal += os.read(master, 65536)
                    except OSError: break
            writer.join(timeout=120)
            if writer.is_alive(): self.fail("Terminal stderr fixture exceeded its bounded completion time")
            stdout, _ = captured[0]
            text = terminal.decode(errors="replace")
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, text), text
        finally:
            if process.poll() is None:
                process.kill()
                writer.join(timeout=5)
            os.close(master)
            os.close(slave)

    def mirror_routes(self, target):
        """Two gateway routes, ranked first/second, with the first one failing."""
        self.f.env["GH_MIRRORS"] = FIRST + " " + SECOND
        self.f.mirror_urls([FIRST, SECOND])
        self.f.probe_responses({FIRST: "0.100", SECOND: "0.200"})
        self.f.curl_failures([FIRST + target])

    def local_url(self, name, data=b"offline fixture payload"):
        url = "https://downloads.fixture.test/" + name
        path = self.f.downloads / ("local-" + name)
        path.write_bytes(data)
        mapping = json.loads(Path(self.f.env["CURL_MAP"]).read_text())
        mapping[url] = str(path)
        Path(self.f.env["CURL_MAP"]).write_text(json.dumps(mapping))
        return url

    # ------------------------------------------- third-party detection choices
    def test_no_third_party_state_never_prompts_and_passes_no_new_flags(self):
        result = self.f.run(**self.local_artifacts())
        self.ok(result)
        self.assertNotIn("Third-party authorization detected", result.stdout)
        self.assertNotIn("No third-party authorization detected", result.stdout)
        self.assertEqual(self.new_flags(), [])
        self.assertIn('{"ready": true, "roots": {"hk": "missing", "cn": "missing"}}', result.stdout)
        self.assertIn('"foreignLicenseCount": 0', result.stdout)
        self.assertEqual(self.f.license_status(), "applied")

    def test_replace_option_without_third_party_state_logs_nothing_to_replace(self):
        result = self.f.run_cli("--replace-foreign", **self.local_artifacts())
        self.ok(result)
        self.assertIn("No third-party authorization detected; nothing to replace", result.stdout)
        self.assertEqual(self.new_flags(), [])
        self.assertEqual(len(self.apply_calls()), 1)
        self.assertNotIn("--replace-foreign", self.apply_calls()[0])

    def test_third_party_state_without_a_terminal_keeps_by_default(self):
        self.f.third_party_roots()
        self.f.third_party_licenses(2)
        result = self.f.run(**self.local_artifacts())
        self.ok(result)
        self.assertIn('{"roots": ["cn", "hk"], "licenses": 2}', result.stdout)
        self.assertIn(KEEP_LOG, result.stdout)
        self.assertEqual(self.new_flags(), [])
        self.assertEqual(self.f.license_status(), "applied")
        self.assertEqual([bind for bind, _ in self.rows() if bind != 17], [0, 0])

    def test_controlling_terminal_replaces_on_enter_and_on_yes(self):
        for answer in ("\n", "y\n", "Y\n", "yes\n", "1\n"):
            with self.subTest(answer=repr(answer)):
                self.fresh(third_party_licenses=2)
                result, terminal = self.tty_run(answer, GH_PROXY="direct", **self.local_artifacts())
                self.ok(result)
                self.assertIn(PROMPT, terminal)
                self.assertIn("原件先留档备份", terminal)
                self.assertIn("PIPE_BODY_INTACT", result.stdout)
                self.assertIn(REPLACE_LOG, result.stdout)
                self.assertEqual(len(self.apply_calls()), 1)
                self.assertIn("--replace-foreign", self.apply_calls()[0])
                self.assertEqual(self.f.license_status(), "applied")
                self.assertEqual(len(self.rows()), 1)
                self.assertNotIn("foreign", self.rows()[0][1])
                self.assertTrue(list(self.f.backup.glob("foreign-licenses.*.json")))

    def test_controlling_terminal_keeps_on_n_and_leaves_the_piped_body_intact(self):
        self.f.third_party_roots()
        self.f.third_party_licenses(2)
        result, terminal = self.tty_run("n\n", GH_PROXY="direct", **self.local_artifacts())
        self.ok(result)
        self.assertIn(PROMPT, terminal)
        self.assertIn("PIPE_BODY_INTACT", result.stdout)
        self.assertIn(KEEP_LOG, result.stdout)
        self.assertEqual(self.new_flags(), [])
        self.assertEqual(len(self.apply_calls()), 1)
        self.assertNotIn("--replace-foreign", self.apply_calls()[0])
        self.assertEqual(self.f.license_status(), "applied")
        self.assertEqual(sorted(bind for bind, _ in self.rows()), [0, 0, 17])

    def test_choice_options_skip_the_prompt_with_a_controlling_terminal(self):
        for option, replaces in (("--replace-foreign", True), ("--keep-foreign", False)):
            with self.subTest(option=option):
                self.fresh(third_party_licenses=1)
                result, terminal = self.tty_run(None, options=("install", option),
                                                expect_prompt=False, GH_PROXY="direct",
                                                **self.local_artifacts())
                self.ok(result)
                self.assertNotIn(PROMPT, terminal)
                self.assertIn("PIPE_BODY_INTACT", result.stdout)
                self.assertIn(REPLACE_LOG if replaces else KEEP_LOG, result.stdout)
                self.assertEqual(["--replace-foreign" in call for call in self.apply_calls()],
                                 [replaces])

    def test_environment_choice_selects_replace_or_keep(self):
        for value, replaces in (("replace", True), ("keep", False)):
            with self.subTest(value=value):
                self.fresh(third_party_licenses=1)
                result = self.f.run(FOREIGN_LICENSE=value, **self.local_artifacts())
                self.ok(result)
                self.assertIn(REPLACE_LOG if replaces else KEEP_LOG, result.stdout)
                self.assertEqual(["--replace-foreign" in call for call in self.apply_calls()],
                                 [replaces])
                self.assertEqual(self.drop_calls(), [])

    def test_command_line_choice_wins_over_the_environment(self):
        for value, option, replaces in (("keep", "--replace-foreign", True),
                                        ("replace", "--keep-foreign", False)):
            with self.subTest(environment=value, option=option):
                self.fresh(third_party_licenses=1)
                result = self.f.run_cli(option, FOREIGN_LICENSE=value, **self.local_artifacts())
                self.ok(result)
                self.assertIn(REPLACE_LOG if replaces else KEEP_LOG, result.stdout)
                self.assertEqual(["--replace-foreign" in call for call in self.apply_calls()],
                                 [replaces])

    def test_invalid_environment_choice_fails_before_any_change(self):
        self.f.third_party_roots()
        self.f.third_party_licenses(1)
        watched = (self.f.core, self.f.ctl, self.f.db, self.f.state / "license.crt")
        before = {str(path): sha(path.read_bytes()) for path in watched}
        result = self.f.run(FOREIGN_LICENSE="maybe")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Invalid FOREIGN_LICENSE; expected replace or keep", result.stderr)
        self.assertNotIn("systemctl", self.f.log())
        self.assertEqual(self.new_flags(), [])
        self.assertEqual(self.apply_calls(), [])
        self.assertIsNone(self.f.license_status())
        self.assertEqual({str(path): sha(path.read_bytes()) for path in watched}, before)
        self.assertEqual(self.rows(), [(17, json.dumps({"signed": True, "foreign": True, "index": 0}))])
        # The choice is validated before the first network call of any kind.
        self.assertEqual(self.f.urls(), [])
        self.assertEqual(self.f.curl_trace(), [])
        self.assertFalse(self.f.work.exists())
        self.assertFalse(self.f.backup.exists())
        self.assertEqual(list(self.f.temporary.iterdir()), [])
        self.assertEqual(self.f.part_files(), [])

    # ------------------------------------------------- replacement end to end
    def test_replace_with_a_project_license_archives_and_applies(self):
        self.f.third_party_roots()
        self.f.third_party_licenses(2)
        result = self.f.run(FOREIGN_LICENSE="replace")
        self.ok(result)
        self.assertIn(REPLACE_LOG, result.stdout)
        self.assertEqual(len(self.apply_calls()), 1)
        self.assertIn("--replace-foreign", self.apply_calls()[0])
        self.assertEqual(self.f.license_status(), "applied")
        self.assertEqual(len(self.rows()), 1)
        self.assertNotIn("foreign", self.rows()[0][1])
        archives = list(self.f.backup.glob("foreign-licenses.*.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(len(json.loads(archives[0].read_text())["rows"]), 2)
        # This is also the real piped install: curl must never be asked for a bar.
        self.assertEqual([call["args"][-1] for call in self.f.downloads_only()],
                         [API_URL] + [self.f.asset_url(name) for name in
                                      ("manifest.json", "runtime.tar.gz", "core-linux-amd64",
                                       "core-linux-amd64.orig")])
        for call in self.f.downloads_only():
            self.assertNotIn("--progress-bar", call["args"])
            self.assertIn("-s", call["args"])

    def test_replace_without_a_project_license_drops_rows_and_stays_pending(self):
        self.f.third_party_roots()
        self.f.third_party_licenses(2)
        (self.f.state / "license.key").unlink()
        result = self.f.run(FOREIGN_LICENSE="replace", **self.local_artifacts())
        self.ok(result)
        self.assertEqual(self.apply_calls(), [])
        self.assertEqual(len(self.drop_calls()), 1)
        self.assertIn("--preserve-foreign", self.drop_calls()[0])
        self.assertIn("--foreign-backup-dir " + str(self.f.backup), self.drop_calls()[0])
        self.assertEqual(self.f.license_status(), "pending")
        self.assertIn("Third-party authorization replaced by our kernel; originals archived under",
                      result.stdout)
        self.assertIn("drop-foreign-licenses 2", self.f.log())
        self.assertEqual(self.rows(), [])
        archives = list(self.f.backup.glob("foreign-licenses.*.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(len(json.loads(archives[0].read_text())["rows"]), 2)

    def test_keep_without_a_project_license_never_drops_and_keeps_the_wording(self):
        self.f.third_party_roots()
        self.f.third_party_licenses(1)
        (self.f.state / "license.key").unlink()
        result = self.f.run(FOREIGN_LICENSE="keep", **self.local_artifacts())
        self.ok(result)
        self.assertEqual(self.drop_calls(), [])
        self.assertEqual(self.new_flags(), [])
        self.assertEqual(self.f.license_status(), "pending")
        self.assertIn(KEEP_LOG, result.stdout)
        self.assertIn("Repository components installed; third-party certificates/licenses retained;"
                      " import a project-signed license to activate", result.stdout)
        self.assertEqual(len(self.rows()), 1)

    # ------------------------------------------------------- download progress
    def test_every_route_attempt_logs_its_host_and_position(self):
        target = self.f.asset_url("manifest.json")
        self.mirror_routes(target)
        result = self.f.fetch_only(target, self.f.temporary / "manifest.json", GH_PROXY="auto")
        self.ok(result)
        self.assertIn("== Downloading manifest.json from ghfast.top (route 1/2)", result.stdout)
        self.assertIn("== Downloading manifest.json from gh-proxy.com (route 2/2)", result.stdout)
        self.assertIn("!! Download route ghfast.top failed or returned invalid data;"
                      " trying next route", result.stderr)
        self.assertIn("PIPE_BODY_INTACT", result.stdout)
        self.assertTrue((self.f.temporary / "manifest.json").is_file())

    def test_all_routes_failing_report_each_route_and_leave_no_partial_files(self):
        target = self.f.asset_url("manifest.json")
        self.f.env["GH_MIRRORS"] = FIRST + " " + SECOND
        self.f.mirror_urls([FIRST, SECOND])
        self.f.probe_responses({FIRST: "0.100", SECOND: "0.200"})
        self.f.curl_failures([FIRST + target, SECOND + target])
        result = self.f.fetch_only(target, self.f.temporary / "manifest.json", GH_PROXY="auto")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(route 1/2)", result.stdout)
        self.assertIn("(route 2/2)", result.stdout)
        self.assertIn("All download routes failed: manifest.json", result.stderr)
        self.assertEqual(self.f.part_files(), [])
        self.assertFalse((self.f.temporary / "manifest.json").exists())

    def test_a_slow_transfer_prints_a_heartbeat_while_curl_is_still_running(self):
        url = self.local_url("slow.bin")
        self.f.slow_curl(6)
        result = self.f.fetch_only(url, self.f.temporary / "slow.bin")
        self.ok(result)
        self.assertIn("== Downloading slow.bin from downloads.fixture.test (route 1/1)", result.stdout)
        beats = [line for line in result.stderr.splitlines() if "still downloading" in line]
        self.assertTrue(beats, result.stderr)
        self.assertRegex(beats[0], r"still downloading: 5s elapsed, \d+ bytes received")
        self.assertTrue((self.f.temporary / "slow.bin").is_file())

    def test_terminal_stderr_gets_a_progress_bar_and_piped_stderr_never_does(self):
        url = self.local_url("progress.bin")
        self.ok(self.f.fetch_only(url, self.f.temporary / "progress-piped.bin"))
        piped = [call for call in self.f.downloads_only() if call["args"][-1] == url]
        self.assertEqual(len(piped), 1)
        self.assertIn("-s", piped[0]["args"])
        self.assertNotIn("--progress-bar", piped[0]["args"])
        Path(self.f.env["CURL_TRACE"]).unlink()
        result, terminal = self.fetch_stderr_tty(url, self.f.temporary / "progress-tty.bin")
        self.ok(result)
        terminal_calls = [call for call in self.f.downloads_only() if call["args"][-1] == url]
        self.assertEqual(len(terminal_calls), 1)
        self.assertIn("--progress-bar", terminal_calls[0]["args"])
        self.assertNotIn("-s", terminal_calls[0]["args"])
        self.assertTrue((self.f.temporary / "progress-tty.bin").is_file())

if __name__ == "__main__":
    unittest.main()
