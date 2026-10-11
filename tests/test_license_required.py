"""A project-signed license is mandatory for activation.

Without LICENSE_FILE, local signing material or a discoverable project license the
installer must stop before replacing any binary; --no-license is the explicit
opt-out that keeps the old "components only, pending import" path.

Run: python3 -m unittest discover -s tests -p test_license_required.py -v
"""
import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from test_unlock import Fixture

REQUIRED = "本站授权文件是激活必需的"


class LicenseRequiredTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="public-unlock-license-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)
        self.empty = self.f.base / "empty-search"
        self.empty.mkdir()
        self.crack = self.f.panel / "crack"
        self.crack.mkdir()

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def no_signing_material(self):
        (self.f.state / "license.key").unlink()

    def issue(self, device_id=None):
        tools, _ = self.f.real_foreign_fixture()
        if device_id is None:
            return tools, self.f.real_project_license(tools)
        issued = self.f.base / "other-device.lic"
        result = subprocess.run([sys.executable, str(tools / "gen_license.py"), "--offline",
                                 "--device-id", device_id, "--expires", "2038-01-01", "--out", str(issued)],
                                env=self.f.env, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return tools, issued

    def test_missing_license_material_stops_before_any_change(self):
        self.f.real_foreign_fixture()
        self.no_signing_material()
        self.f.events.unlink(missing_ok=True)
        before = self.f.machine_snapshot()
        result = self.f.run(LICENSE_SEARCH_DIRS=str(self.empty))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(REQUIRED, result.stdout + result.stderr)
        self.assertEqual(self.f.machine_snapshot(), before)
        self.assertNotIn("patch_core", self.f.log())
        self.assertEqual([url for url in self.f.urls() if "core-linux" in url or "agent-linux" in url], [])
        self.assertEqual(list(self.f.backup.glob("foreign-licenses.*.json")), [])

    def test_no_license_flag_keeps_the_pending_path_and_third_party_rows(self):
        self.f.real_foreign_fixture()
        self.no_signing_material()
        before = self.f.rows("licenses")
        result = self.f.run_cli("--no-license", "--keep-foreign", LICENSE_SEARCH_DIRS=str(self.empty))
        self.ok(result)
        self.assertEqual(self.f.rows("licenses"), before)
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "pending")
        self.assertIn("stays inactive", result.stdout)
        self.assertIn("code patch_core", self.f.log())

    def test_replace_foreign_without_a_license_keeps_the_rows(self):
        self.f.real_foreign_fixture()
        self.no_signing_material()
        before = self.f.rows("licenses")
        result = self.f.run_cli("--no-license", "--replace-foreign", LICENSE_SEARCH_DIRS=str(self.empty))
        self.ok(result)
        self.assertEqual(self.f.rows("licenses"), before)
        self.assertIn("were kept (not dropped)", result.stdout)

    def test_license_file_flag_activates_without_signing_material(self):
        _, issued = self.issue()
        self.no_signing_material()
        result = self.f.run_cli("--license-file", str(issued), "--keep-foreign")
        self.ok(result)
        self.assertEqual(len(self.f.rows("licenses")), 2)
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "applied")
        self.assertIn('"status": "Bound"', result.stdout)

    def test_discovered_license_in_panel_crack_dir_is_used(self):
        _, issued = self.issue()
        target = self.crack / "1Panel-Enterprise-DISCOVERED.lic"
        shutil.copy2(issued, target)
        self.no_signing_material()
        result = self.f.run(LICENSE_SEARCH_DIRS=str(self.crack))
        self.ok(result)
        self.assertIn("Project-signed license: " + str(target), result.stdout)
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "applied")

    def test_foreign_or_mismatched_candidates_are_not_used(self):
        _, other = self.issue(device_id="another-device")
        shutil.copy2(other, self.crack / "other-device.lic")
        (self.crack / "garbage.lic").write_text("not-a-license")
        self.no_signing_material()
        result = self.f.run(LICENSE_SEARCH_DIRS=str(self.crack))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(REQUIRED, result.stdout + result.stderr)
        self.assertNotIn("other-device.lic", result.stdout + result.stderr)

    def test_terminal_prompt_accepts_a_license_path(self):
        _, issued = self.issue()
        self.no_signing_material()
        env = {**self.f.env, "LICENSE_SEARCH_DIRS": str(self.empty)}
        pid, master = pty.fork()
        if pid == 0:  # child: real terminal so /dev/tty exists
            os.chdir(str(self.f.base))
            os.execve("/bin/bash", ["bash", str(self.f.script), "install", "--no-mirror", "--keep-foreign"], env)
        deadline = time.time() + 90
        output, answered, status = "", False, None
        try:
            while time.time() < deadline:
                ready, _, _ = select.select([master], [], [], 0.5)
                if ready:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk.decode("utf-8", "replace")
                    if not answered and "请给出 .lic 路径" in output:
                        os.write(master, (str(issued) + "\n").encode())
                        answered = True
                else:
                    done, waited = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = waited
                        break
            else:
                os.kill(pid, 9)
                self.fail("prompt run timed out: " + output[-2000:])
        finally:
            os.close(master)
            if status is None:
                try:
                    _, status = os.waitpid(pid, 0)
                except ChildProcessError:
                    status = 0
        self.assertTrue(answered, "prompt never appeared: " + output[-2000:])
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, output[-2000:])
        self.assertIn("Project-signed license: " + str(issued), output)
        self.assertEqual((self.f.work / "license.status").read_text().strip(), "applied")


if __name__ == "__main__":
    unittest.main()
