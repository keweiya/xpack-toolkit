#!/usr/bin/env python3
"""tools/smoke_test.py 的纯函数测试（不启动容器）。"""
import base64
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import smoke_test as smoke  # noqa: E402

PCTL = """#!/bin/sh
BASE_DIR=directory
ORIGINAL_PORT=port
ORIGINAL_VERSION=v2.4.0
ORIGINAL_ENTRANCE=entrance
ORIGINAL_USERNAME=username
ORIGINAL_PASSWORD=password
LANGUAGE=en
PANEL_EDITION=cn
"""


class Patch1pctlTest(unittest.TestCase):
    def test_rewrites_known_placeholders(self):
        text = smoke.patch_1pctl(PCTL, 9999)
        self.assertIn("BASE_DIR=/opt\n", text)
        self.assertIn("ORIGINAL_PORT=9999\n", text)
        self.assertIn("ORIGINAL_USERNAME=admin\n", text)
        self.assertIn("ORIGINAL_PASSWORD=Admin123456\n", text)
        self.assertIn("LANGUAGE=zh\n", text)
        self.assertNotIn("username", text)

    def test_keeps_unrelated_lines(self):
        text = smoke.patch_1pctl(PCTL, 9999)
        self.assertIn("ORIGINAL_VERSION=v2.4.0\n", text)
        self.assertTrue(text.startswith("#!/bin/sh\n"))


@unittest.skipUnless(shutil.which("openssl"), "openssl is required")
class EncryptedPasswordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        key = Path(self.tmp.name) / "key.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"],
                       check=True, capture_output=True)
        self.public_pem = subprocess.run(
            ["openssl", "rsa", "-in", str(key), "-pubout"],
            check=True, capture_output=True).stdout.decode()

    def tearDown(self):
        self.tmp.cleanup()

    def test_payload_has_three_parts(self):
        payload = smoke.encrypted_password(self.public_pem, "Admin123456")
        parts = payload.split(":")
        self.assertEqual(len(parts), 3, payload[:80])
        key_part, iv_part, cipher_part = (base64.b64decode(part) for part in parts)
        self.assertEqual(len(iv_part), 16)
        self.assertEqual(len(cipher_part) % 16, 0)
        self.assertEqual(len(key_part), 256)  # 2048-bit RSA 输出

    def test_iv_and_cipher_are_random(self):
        first = smoke.encrypted_password(self.public_pem, "Admin123456").split(":")[1]
        second = smoke.encrypted_password(self.public_pem, "Admin123456").split(":")[1]
        self.assertNotEqual(first, second)


class FailureMarkerTest(unittest.TestCase):
    def test_markers_cover_both_languages(self):
        for message in ("服务内部错误: verify certificate failed",
                        "服务内部错误: 证书校验失败，请检查后重试"):
            self.assertTrue(any(marker in message for marker in smoke.CERT_FAILURE_MARKERS), message)

    def test_unrelated_error_is_not_a_cert_failure(self):
        self.assertFalse(any(marker in "服务内部错误: 许可证格式错误，请检查后重试！"
                             for marker in smoke.CERT_FAILURE_MARKERS))


class DockerfileTest(unittest.TestCase):
    def test_host_extras_keep_build_offline(self):
        text = smoke.render_dockerfile(("zoneinfo", "cacerts"))
        self.assertIn("COPY zoneinfo /usr/share/zoneinfo/\n", text)
        self.assertIn("COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n", text)
        self.assertNotIn("apt-get", text)

    def test_missing_extras_fall_back_to_mirrored_apt(self):
        text = smoke.render_dockerfile()
        self.assertIn("for mirror in azure.archive.ubuntu.com archive.ubuntu.com", text)
        self.assertIn("Acquire::Retries=3", text)
        self.assertIn("--no-install-recommends tzdata ca-certificates", text)
        # ubuntu:24.04 自带 procps，不该再装一遍
        self.assertNotIn("procps", text)

    def test_partial_extras_only_install_the_missing_package(self):
        text = smoke.render_dockerfile(("zoneinfo",))
        self.assertIn("COPY zoneinfo /usr/share/zoneinfo/\n", text)
        self.assertIn("--no-install-recommends ca-certificates", text)
        self.assertNotIn("tzdata", text)


class BuildImageTest(unittest.TestCase):
    def test_build_uses_host_network_and_keeps_logs(self):
        commands = []

        def fake_run(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(smoke.subprocess, "run", fake_run):
            smoke.build_image(Path("/tmp/ctx"), "tag:1", "arm64")
        build = commands[-1]
        self.assertIn("--network=host", build)
        self.assertNotIn("-q", build)
        self.assertIn("linux/arm64", build)

    def test_build_failure_surfaces_last_lines(self):
        def fake_run(command, **kwargs):
            if command[1] == "build":
                return subprocess.CompletedProcess(command, 1, "", "step 1/5\nE: boom\nERROR: exit code 100")
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(smoke.subprocess, "run", fake_run):
            with self.assertRaises(smoke.SmokeError) as raised:
                smoke.build_image(Path("/tmp/ctx"), "tag:1")
        self.assertIn("exit code 100", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
