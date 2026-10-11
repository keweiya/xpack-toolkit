"""Download progress visibility: log heartbeat, tty bar, and the stall watchdog.

Run: python3 -m unittest discover -s tests -p test_download_progress.py -v
Every transfer uses a temporary chunked curl stand-in inside the Fixture sandbox.
"""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time
import unittest

from test_unlock import API_URL, Fixture

SLOW_CURL = r'''#!/usr/bin/env python3
"""Chunked curl stand-in: writes slowly so the wrapper heartbeat is observable."""
import json, os, pathlib, sys, time
args = sys.argv[1:]
trace = os.environ.get("SLOW_CURL_TRACE")
if trace:
    with open(trace, "a") as fh:
        fh.write(json.dumps(args) + "\n")
if "--write-out" in args or "-w" in args:
    print("\n200\t0.100")
    raise SystemExit(0)
target = pathlib.Path(args[args.index("-o") + 1])
url = args[-1]
mapping = json.loads(pathlib.Path(os.environ["CURL_MAP"]).read_text())
data = pathlib.Path(mapping[url]).read_bytes()
chunk = max(1, len(data) // 4)
step = float(os.environ.get("SLOW_CURL_STEP", "0.4"))
hang = os.environ.get("SLOW_CURL_HANG") == "1"
with open(target, "wb") as fh:
    for start in range(0, len(data), chunk):
        fh.write(data[start:start + chunk])
        fh.flush()
        if hang:
            time.sleep(120)
        time.sleep(step)
'''


class DownloadProgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="download-progress-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    def driver(self, destination):
        # The real parser plus helpers, driven by one explicit fetch.
        program = self.f.script.read_text().split('\nWORK=""', 1)[0]
        program += '\nfetch "$TEST_FETCH_URL" "$TEST_FETCH_DEST"\nprintf "FETCH_DONE\\n"\n'
        return program, {"TEST_FETCH_URL": API_URL, "TEST_FETCH_DEST": str(destination)}

    def slow_curl(self, step="0.4", hang=False):
        binary = self.f.base / "slow-bin"
        binary.mkdir(exist_ok=True)
        path = binary / "curl"
        path.write_text(SLOW_CURL)
        path.chmod(0o755)
        trace = self.f.base / "slow-curl-trace.jsonl"
        trace.unlink(missing_ok=True)
        return trace, {"PATH": str(binary) + os.pathsep + self.f.env["PATH"],
                       "SLOW_CURL_TRACE": str(trace), "SLOW_CURL_STEP": step,
                       "SLOW_CURL_HANG": "1" if hang else "0"}

    def run_driver(self, env, timeout=60, pty_stderr=False):
        destination = self.f.base / "fetch-target" / "releases.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.unlink(missing_ok=True)
        program, extra = self.driver(destination)
        command = ["bash", "-s", "--"]
        if not pty_stderr:
            return destination, subprocess.run(command, input=program, cwd=self.f.base,
                                               env={**self.f.env, **env, **extra}, capture_output=True,
                                               text=True, start_new_session=True, timeout=timeout)
        master, slave = pty.openpty()
        process = subprocess.Popen(command, cwd=self.f.base, env={**self.f.env, **env, **extra},
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=slave,
                                   text=True, start_new_session=True)
        os.close(slave)
        terminal = b""
        try:
            process.stdin.write(program)
            process.stdin.close()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    terminal += chunk
                elif process.poll() is not None:
                    break
            process.wait(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
            process.stdout.close()
            os.close(master)
        result = subprocess.CompletedProcess(command, process.returncode, "", terminal.decode(errors="replace"))
        return destination, result

    def trace(self, path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_clean(self, destination):
        self.assertEqual(list(Path(destination).parent.glob("*.part.*")), [])

    def test_log_output_prints_heartbeat_and_completion(self):
        trace, env = self.slow_curl(step="0.5")
        destination, result = self.run_driver({**env, "HEARTBEAT_SECONDS": "1", "STALL_SECONDS": "30"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("FETCH_DONE", result.stdout)
        stderr = result.stderr
        self.assertIn("releases.json: unknown size via api.github.com", stderr)
        heartbeats = [line for line in stderr.splitlines() if "/s, " in line and "releases.json:" in line]
        self.assertGreaterEqual(len(heartbeats), 1, stderr)
        self.assertRegex(heartbeats[0], r"releases\.json: [\d.]+ (B|KB), [\d.]+ (B|KB)/s, \d+s")
        self.assertRegex(stderr, r"releases\.json: [\d.]+ (B|KB) in \d+s \([\d.]+ (B|KB)/s\)")
        args, = self.trace(trace)
        self.assertIn("-s", args)
        self.assertNotIn("--progress-bar", args)
        self.assertEqual(args[args.index("--speed-limit") + 1], "1024")
        self.assertEqual(args[args.index("--speed-time") + 1], "30")
        self.assertEqual(args[args.index("--max-time") + 1], "1800")
        self.assert_clean(destination)
        self.assertEqual(json.loads(Path(destination).read_text()), json.loads(
            (self.f.downloads / "releases.json").read_text()))

    def test_known_asset_size_is_shown_as_a_percentage(self):
        trace, env = self.slow_curl(step="0.5")
        runtime = self.f.assets / "runtime.tar.gz"
        destination = self.f.base / "fetch-target" / "runtime.tar.gz"
        destination.parent.mkdir(parents=True, exist_ok=True)
        (destination.parent / "manifest.json").write_bytes((self.f.assets / "manifest.json").read_bytes())
        program = self.f.script.read_text().split('\nWORK=""', 1)[0]
        program += '\nfetch "$TEST_FETCH_URL" "$TEST_FETCH_DEST"\n'
        result = subprocess.run(["bash", "-s", "--"], input=program, cwd=self.f.base,
                                env={**self.f.env, **env, "TEST_FETCH_URL": self.f.asset_url("runtime.tar.gz"),
                                     "TEST_FETCH_DEST": str(destination), "HEARTBEAT_SECONDS": "1"},
                                capture_output=True, text=True, start_new_session=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("runtime.tar.gz: %s via github.com" % self.human(runtime.stat().st_size), result.stderr)
        self.assertRegex(result.stderr, r"runtime\.tar\.gz: [\d.]+ (B|KB) / [\d.]+ (B|KB) \(\d+%\) [\d.]+ (B|KB)/s, \d+s")
        self.assertRegex(result.stderr, r"runtime\.tar\.gz: [\d.]+ (B|KB) in \d+s")
        self.assert_clean(destination)

    @staticmethod
    def human(size):
        if size >= 1048576:
            return "%d.%d MB" % (size // 1048576, (size % 1048576) * 10 // 1048576)
        if size >= 1024:
            return "%d.%d KB" % (size // 1024, (size % 1024) * 10 // 1024)
        return "%d B" % size

    def test_tty_uses_the_curl_progress_bar_instead_of_heartbeats(self):
        trace, env = self.slow_curl(step="0.3")
        destination, result = self.run_driver({**env, "GH_PROXY": "direct", "PROGRESS": "auto"},
                                             pty_stderr=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        args, = self.trace(trace)
        self.assertIn("--progress-bar", args)
        self.assertIn("releases.json: unknown size via api.github.com", result.stderr)
        self.assertRegex(result.stderr, r"releases\.json: [\d.]+ (B|KB) in \d+s")
        self.assertNotRegex(result.stderr, r"releases\.json: [\d.]+ (B|KB), [\d.]+ (B|KB)/s, \d+s")
        self.assert_clean(destination)

    def test_progress_off_keeps_only_the_summary_line(self):
        trace, env = self.slow_curl(step="0.05")
        destination, result = self.run_driver({**env, "PROGRESS": "off", "HEARTBEAT_SECONDS": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"releases\.json: [\d.]+ (B|KB) in \d+s")
        self.assertNotIn("%", result.stderr)
        args, = self.trace(trace)
        self.assertNotIn("--progress-bar", args)
        self.assert_clean(destination)

    def test_stalled_route_aborts_quickly_and_cleans_up(self):
        trace, env = self.slow_curl(step="0.05", hang=True)
        started = time.monotonic()
        destination, result = self.run_driver({**env, "HEARTBEAT_SECONDS": "1", "STALL_SECONDS": "2"},
                                             timeout=60)
        elapsed = time.monotonic() - started
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no data for", result.stderr)
        self.assertIn("aborting this route", result.stderr)
        self.assertIn("All download routes failed", result.stderr)
        self.assertLess(elapsed, 30, "stall watchdog did not bound the transfer")
        self.assert_clean(destination)


if __name__ == "__main__":
    unittest.main()
