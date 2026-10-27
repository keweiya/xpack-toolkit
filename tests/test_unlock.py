"""Installer flow regressions (unlock.sh syntax + release selection logic)."""

import hashlib
import importlib.util
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


def shell_function(name):
    script = UNLOCK.read_text()
    match = re.search(r"^%s\(\) \{.*?^\}" % re.escape(name), script, flags=re.S | re.M)
    if not match:
        raise AssertionError("function not found in unlock.sh: " + name)
    return match.group(0)


def run_shell(functions, body, timeout=60):
    script = "set -uo pipefail\n" + "\n".join(functions) + "\n" + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=timeout)


class ReleaseSelectionTests(unittest.TestCase):
    """select_release 现在是 shell 实现：API 与 atom 两种来源都要能选出最高稳定版并拼出资产 URL。"""

    def select(self, run_dir, platform, api_ok=True):
        harness = f"""
die() {{ printf '!! %s\\n' "$*" >&2; exit 1; }}
log() {{ :; }}
FETCH_N=0
fetch() {{ FETCH_N=$((FETCH_N+1)); if [ "$FETCH_N" = 1 ] && [ {int(api_ok)} = 0 ]; then return 1; fi; return 0; }}
PLATFORM={platform}
REPO=keweiya/xpack-toolkit
RUN={run_dir}
select_release
"""
        return run_shell([shell_function("json_objects"), shell_function("select_release")], harness)

    def test_atom_source_picks_highest_and_builds_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "releases.atom").write_text(
                "<feed><entry><title>core-v2.4.0</title></entry>"
                "<entry><title>core-v2.4.1</title></entry></feed>")
            result = self.select(run, "linux-arm64", api_ok=False)
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
            result = self.select(run, "linux-amd64")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((run / "core.url").read_text(),
                             "https://github.com/keweiya/xpack-toolkit/releases/download/core-v2.4.1/core-linux-amd64")
            self.assertEqual((run / "agent.url").read_text(),
                             "https://github.com/keweiya/xpack-toolkit/releases/download/core-v2.4.1/agent-linux-amd64")
            self.assertEqual((run / "selected.version").read_text(), "v2.4.1")

    def test_draft_and_prerelease_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "releases.json").write_text(json.dumps([
                {"tag_name": "core-v2.3.2", "draft": False, "prerelease": False,
                 "assets": [{"name": n, "browser_download_url": "https://x/" + n}
                            for n in ("manifest.json", "core-linux-amd64", "core-linux-amd64.orig")]},
                {"tag_name": "core-v2.5.0", "draft": True, "prerelease": False, "assets": []},
                {"tag_name": "core-v2.4.9", "draft": False, "prerelease": True, "assets": []},
            ]))
            result = self.select(run, "linux-amd64")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((run / "selected.version").read_text(), "v2.3.2")


class NoPythonTests(unittest.TestCase):
    """脚本本身不再调用 python；授权证书由 shell（openssl + sqlite3）负责。"""

    def test_script_has_no_python_invocation(self):
        script = UNLOCK.read_text()
        self.assertFalse("python3" in script, "unlock.sh still invokes python3")
        self.assertFalse("py_compile" in script, "unlock.sh still compiles python tools")
        self.assertFalse("<<'PY'" in script, "unlock.sh still embeds python heredocs")

    def test_shell_license_decodes_with_python_reference(self):
        spec = importlib.util.spec_from_file_location(
            "gen_license", ROOT / "tools" / "gen_license.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        fns = [shell_function(n) for n in ("lic_token", "lic_json", "lic_encode")]
        result = run_shell(fns, 'lic_encode "$(lic_json enterprise 9999-12-31 999 YG lxware '
                                '100000 all 0123456789abcdef0123456789abcdef)"')
        self.assertEqual(result.returncode, 0, result.stderr)
        content = gen.decode_license(result.stdout.strip())
        self.assertEqual(content["products"][0]["maxNodeCount"], 999)
        self.assertEqual(content["annotations"]["lxware.cn/xpack-toolkit"], "true")
        self.assertEqual(content["assigneeName"], "YG")

    def test_shell_aes_is_compatible_with_reference_codec(self):
        spec = importlib.util.spec_from_file_location(
            "gen_license", ROOT / "tools" / "gen_license.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        fns = [shell_function(n) for n in ("hexof", "lic_enc", "lic_dec")]
        blob = run_shell(fns, 'lic_enc "Bound" "nel1Pa2520pack@x"').stdout
        self.assertEqual(gen.decrypt_blob(blob), "Bound")
        python_blob = gen.encrypt_blob(b"1Panel-Enterprise-AAAA1111BBBB")
        dec = subprocess.run(["bash", "-c", "\n".join(fns) + '\nlic_dec "$1" "nel1Pa2520pack@x"',
                              "_", python_blob], capture_output=True, text=True)
        self.assertEqual(dec.stdout.strip(), "1Panel-Enterprise-AAAA1111BBBB")


class BundledSqliteTests(unittest.TestCase):
    """写授权表不依赖系统 sqlite3：仓库自带静态单文件，脚本里的 sha256 必须与它一致。"""

    def test_sha_constant_matches_bundled_binary(self):
        script = UNLOCK.read_text()
        match = re.search(r'SQLITE3_SHA_amd64="([0-9a-f]{64})"', script)
        self.assertIsNotNone(match, "SQLITE3_SHA_amd64 missing in unlock.sh")
        binary = ROOT / "tools" / "bin" / "sqlite3mini-linux-amd64"
        self.assertTrue(binary.is_file(), "bundled sqlite3 binary is missing")
        self.assertEqual(match.group(1), hashlib.sha256(binary.read_bytes()).hexdigest())

    def test_bundled_binary_executes_sql(self):
        binary = ROOT / "tools" / "bin" / "sqlite3mini-linux-amd64"
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "t.db")
            run = subprocess.run([str(binary), db,
                                  "create table k(v); insert into k values('ok');"],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            read = subprocess.run([str(binary), "-batch", "-noheader", db, "select v from k;"],
                                  capture_output=True, text=True)
            self.assertEqual(read.stdout.strip(), "ok")
            backup = subprocess.run([str(binary), db, ".backup '%s/b.db'" % tmp],
                                    capture_output=True, text=True)
            self.assertEqual(backup.returncode, 0, backup.stderr)
            self.assertTrue(os.path.getsize(os.path.join(tmp, "b.db")) > 0)


class CleanupTests(unittest.TestCase):
    """成功后要清掉下载物、内置 sqlite3、库备份与旧二进制备份，只留证书。"""

    @classmethod
    def setUpClass(cls):
        cls.script = UNLOCK.read_text()
        cls.fn = shell_function("cleanup_artifacts")

    def run_cleanup(self, tmp, keep_backup=0):
        paths = {
            "RUN": os.path.join(tmp, "run.abc"),
            "PREFLIGHT": os.path.join(tmp, "preflight"),
            "PERSIST": os.path.join(tmp, "unlock"),
            "BACKUP": os.path.join(tmp, "crack", "backup"),
            "XPACK_DB": os.path.join(tmp, "xpack.db"),
        }
        for path in (paths["RUN"], paths["PREFLIGHT"],
                     os.path.join(paths["PERSIST"], "tools"),
                     paths["BACKUP"]):
            os.makedirs(path, exist_ok=True)
        open(os.path.join(paths["PERSIST"], "tools", "sqlite3mini"), "w").write("x")
        open(os.path.join(paths["PERSIST"], "license.txt"), "w").write("cert")
        open(paths["XPACK_DB"] + ".pre-license", "w").write("bak")
        open(os.path.join(paths["BACKUP"], "1panel-core.previous"), "w").write("bin")
        body = "\n".join("%s=%s" % (k, v) for k, v in paths.items())
        body += "\nKEEP_BACKUP=%d\nlog() { :; }\ncleanup_artifacts\n" % keep_backup
        return run_shell([self.fn], body)

    def test_default_removes_downloads_and_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cleanup(tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(os.path.exists(os.path.join(tmp, "run.abc")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "unlock", "tools")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "crack")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "xpack.db.pre-license")))
            # 证书本身保留
            self.assertTrue(os.path.exists(os.path.join(tmp, "unlock", "license.txt")))

    def test_keep_backup_preserves_rollback_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cleanup(tmp, keep_backup=1)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(os.path.exists(
                os.path.join(tmp, "crack", "backup", "1panel-core.previous")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "unlock", "tools")))

    def test_install_calls_cleanup_after_replacement(self):
        replace = self.script.index('install -m 0755 "$RUN/core" "$CORE_BIN"')
        cleanup = self.script.index("cleanup_artifacts\n", self.script.index("# 清理下载内容"))
        self.assertLess(replace, cleanup)

    def test_keep_backup_flag_is_documented(self):
        self.assertIn("--keep-backup", self.script)
        self.assertIn("KEEP_BACKUP=1", self.script)


class RestoreTests(unittest.TestCase):
    """restore 用完即清：回滚后删掉备份；没有备份时从 fit2cloud 重装官方包。"""

    @classmethod
    def setUpClass(cls):
        cls.script = UNLOCK.read_text()

    def test_restore_falls_back_to_official_package(self):
        branch = self.script[self.script.index('if [ "$MODE" = restore ]'):
                             self.script.index('if [ "$MODE" = verify ]')]
        self.assertIn("OFFICIAL_BASE", branch)
        self.assertIn("fetch_direct", branch)
        self.assertNotIn("Missing core rollback image", branch)

    def test_restore_cleans_up_after_itself(self):
        branch = self.script[self.script.index('if [ "$MODE" = restore ]'):
                             self.script.index('if [ "$MODE" = verify ]')]
        self.assertIn("cleanup_artifacts", branch)

    def test_restore_from_backup_then_removes_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup = os.path.join(tmp, "crack", "backup")
            os.makedirs(backup)
            for name, payload in (("1panel-core.previous", "ORIG-CORE"),
                                  ("1panel-agent.previous", "ORIG-AGENT"),
                                  ("1panel-ctl.previous", "ORIG-CTL")):
                Path(backup, name).write_text(payload)
            core = os.path.join(tmp, "core")
            Path(core).write_text("CRACKED")
            env = os.environ.copy()
            env.update({
                "PATH": tmp + "/bin:" + env["PATH"],
                "PANEL_ROOT": tmp, "PANEL_CTL": os.path.join(tmp, "1pctl"),
                "CORE_BIN": core, "AGENT_BIN": os.path.join(tmp, "agent"),
                "CORE_SVC": "xpack-test", "AGENT_SVC": "xpack-test-agent",
                "BACKUP": backup, "UNLOCK_WORK": os.path.join(tmp, "unlock"),
                "XPACK_DB": os.path.join(tmp, "xpack.db"),
                "SERIAL_PATH": os.path.join(tmp, "serial"),
            })
            os.makedirs(tmp + "/bin")
            Path(tmp, "bin", "systemctl").write_text("#!/bin/sh\nexit 0\n")
            os.chmod(tmp + "/bin/systemctl", 0o755)
            run = subprocess.run(["bash", str(UNLOCK), "restore", "--no-progress"],
                                 capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(Path(core).read_text(), "ORIG-CORE")
            self.assertFalse(os.path.exists(backup), "backup should be removed after restore")


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
