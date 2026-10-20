#!/usr/bin/env python3
"""Docker 端到端冒烟测试：验证「破解内核 + 补丁 Agent」在真实 1Panel 运行时里能用。

只在容器里跑，绝不触碰宿主机上的 1Panel 安装（本机可能是 1Panel 子节点）。

覆盖的接口：
    1. 面板启动            GET  /entrance                     -> 200
    2. 管理员登录          POST /api/v2/core/auth/login       -> 200 + 会话 Cookie
    3. 授权落库与绑定      GET  /api/v2/core/licenses/master/status -> status=Bound
    4. 证书被内核接受      POST /api/v2/core/licenses/search  -> 证书存在 + 节点 isXpack=true
    5. 专业版接口放行      POST /api/v2/core/xpack/nodes/search -> 200 且有数据
    6. 破解有效性对照（可选 --orig-core）
       同一份自制证书上传：官方内核 = 证书校验失败；破解内核 = 不再因证书校验被拒

用法（本地）：
    python3 tools/smoke_test.py \
        --release build/release-v2.4.0 \
        --package build/dl/1panel-v2.4.0-linux-amd64.tar.gz \
        --orig-core build/release-v2.4.0/core-linux-amd64.orig

退出码 0 = 全部通过；非 0 = 有断言失败（发布流程应据此中止）。
"""
import argparse
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USERNAME = "admin"
PASSWORD = "Admin123456"
ENTRANCE_FALLBACK = "entrance"
CONTAINER_PORT = 9999

DOCKERFILE = """FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \\
 && apt-get install -y --no-install-recommends ca-certificates tzdata procps \\
 && rm -rf /var/lib/apt/lists/*
COPY core /usr/local/bin/1panel-core
COPY agent /usr/local/bin/1panel-agent
COPY 1pctl /usr/local/bin/1pctl
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/1panel-core /usr/local/bin/1panel-agent \\
        /usr/local/bin/1pctl /entrypoint.sh \\
 && mkdir -p /opt/1panel /etc/1panel
EXPOSE 9999
ENTRYPOINT ["/entrypoint.sh"]
"""

# core 启动时会创建 /etc/1panel/.1panel，agent 依赖它，所以必须先起 core。
ENTRYPOINT = """#!/bin/sh
set -u
mkdir -p /opt/1panel/log /opt/1panel/db /opt/1panel/conf /opt/1panel/tmp \\
         /opt/1panel/backup /opt/1panel/apps /opt/1panel/geo
/usr/local/bin/1panel-core &
CORE_PID=$!
i=0
while [ $i -lt 60 ]; do
    [ -f /etc/1panel/.1panel ] && break
    sleep 1
    i=$((i + 1))
done
/usr/local/bin/1panel-agent >/opt/1panel/log/agent.stdout.log 2>&1 &
exec tail --pid=$CORE_PID -f /dev/null
"""


class SmokeError(Exception):
    pass


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #
def run(command, **kwargs):
    kwargs.setdefault("text", True)
    kwargs.setdefault("capture_output", True)
    result = subprocess.run(command, **kwargs)
    if result.returncode != 0:
        raise SmokeError("command failed: {}\n{}\n{}".format(
            " ".join(str(part) for part in command), result.stdout, result.stderr))
    return result.stdout


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(url, method="GET", body=None, headers=None, timeout=15):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method,
                                    headers=headers or ({"Content-Type": "application/json"} if data else {}))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace"), response.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), []
    except (urllib.error.URLError, OSError) as error:
        return 0, str(error), []


def json_of(text):
    try:
        return json.loads(text)
    except ValueError:
        return {}


def wait_until(description, probe, timeout=150, interval=2):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            result = probe()
        except Exception as exc:  # noqa: BLE001 - 轮询期间的任何异常都只记录
            last = exc
            result = None
        if result:
            return result
        time.sleep(interval)
    raise SmokeError("timeout waiting for {}: {}".format(description, last))


# --------------------------------------------------------------------------- #
# 资产准备
# --------------------------------------------------------------------------- #
def patch_agent(original, output):
    run([sys.executable, str(ROOT / "tools/patch_agent.py"), "--patch",
         "--in", str(original), "--out", str(output)])
    listing = run([sys.executable, str(ROOT / "tools/patch_agent.py"), "--verify", "--in", str(output)])
    if "all patches present" not in listing:
        raise SmokeError("agent patch verification failed:\n" + listing)


def patch_1pctl(text, port):
    replacements = {
        "BASE_DIR": "/opt",
        "ORIGINAL_PORT": str(port),
        "ORIGINAL_ENTRANCE": ENTRANCE_FALLBACK,
        "ORIGINAL_USERNAME": USERNAME,
        "ORIGINAL_PASSWORD": PASSWORD,
        "LANGUAGE": "zh",
        "PANEL_EDITION": "cn",
    }
    lines = []
    for line in text.splitlines():
        match = re.match(r"^([A-Z_]+)=", line)
        if match and match.group(1) in replacements:
            lines.append("{}={}".format(match.group(1), replacements[match.group(1)]))
        else:
            lines.append(line)
    return "\n".join(lines) + "\n"


def extract_1pctl(package):
    with tarfile.open(package, "r:gz") as archive:
        for member in archive.getmembers():
            if member.name.endswith("/1pctl"):
                return archive.extractfile(member).read().decode()
    raise SmokeError("1pctl not found in official package: " + str(package))


def build_image(context, tag):
    print("== building smoke image {}".format(tag), flush=True)
    run(["docker", "build", "-q", "-t", tag, str(context)], timeout=900)


class Panel:
    """一个隔离的 1Panel 运行实例（容器 + 宿主机数据目录）。"""

    def __init__(self, name, image, data, port):
        self.name = name
        self.image = image
        self.data = data
        self.port = port
        self.url = "http://127.0.0.1:{}".format(port)
        self.cookies = {}

    def start(self):
        run(["docker", "start", self.name])
        self.wait_ready()

    def create(self):
        self.remove()
        run(["docker", "run", "-d", "--name", self.name,
             "-p", "127.0.0.1:{}:9999".format(self.port),
             "-v", "{}:/opt/1panel".format(self.data), self.image])
        self.wait_ready()

    def stop(self):
        subprocess.run(["docker", "stop", self.name], text=True, capture_output=True)

    def remove(self):
        subprocess.run(["docker", "rm", "-f", self.name], text=True, capture_output=True)

    def wait_ready(self, timeout=180):
        wait_until("panel http", lambda: http(self.url + "/entrance")[0] == 200, timeout=timeout)
        wait_until("panel database", lambda: (Path(self.data) / "db/core.db").is_file(), timeout=60)
        wait_until("panel auth key", lambda: self.setting("PASSWORD_PUBLIC_KEY"), timeout=120)

    def setting(self, key):
        import sqlite3
        db = Path(self.data) / "db/core.db"
        if not db.is_file():
            return None
        try:
            with sqlite3.connect("file:{}?mode=ro".format(db), uri=True) as con:
                row = con.execute("select value from settings where key = ?", (key,)).fetchone()
                return row[0] if row else None
        except sqlite3.Error:
            return None

    # -- HTTP ------------------------------------------------------------- #
    def request(self, path, method="GET", body=None, csrf=True):
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.cookies:
            headers["Cookie"] = "; ".join("{}={}".format(k, v) for k, v in self.cookies.items())
        if csrf and method != "GET":
            headers["X-CSRF-Token"] = self.cookies.get("pcsrftoken", "")
        status, text, cookies = http(self.url + path, method, body, headers)
        for cookie in cookies:
            key_value = cookie.split(";", 1)[0]
            if "=" in key_value:
                key, value = key_value.split("=", 1)
                self.cookies[key] = value
        return status, text

    def login(self):
        public_key = self.setting("PASSWORD_PUBLIC_KEY")
        if not public_key:
            raise SmokeError("panel did not store PASSWORD_PUBLIC_KEY")
        entrance = self.setting("SecurityEntrance") or ""
        payload = encrypted_password(public_key, PASSWORD)
        headers = {"Content-Type": "application/json"}
        if entrance:
            headers["EntranceCode"] = base64.b64encode(entrance.encode()).decode()
        status, text, cookies = http(self.url + "/api/v2/core/auth/login",
                                     "POST", {"name": USERNAME, "password": payload, "language": "zh"}, headers)
        for cookie in cookies:
            key, value = cookie.split(";", 1)[0].split("=", 1)
            self.cookies[key] = value
        data = json_of(text)
        if status != 200 or data.get("code") != 200:
            raise SmokeError("login failed: HTTP {} {}".format(status, text[:300]))
        if not self.cookies.get("psession"):
            raise SmokeError("login returned no psession cookie")


def encrypted_password(public_key_pem, password):
    """面板登录口令：b64(RSA(aeskey)) : b64(iv) : b64(AES-CBC(password))。"""
    sys.path.insert(0, str(ROOT / "tools"))
    from aes128 import cbc_encrypt, pkcs7_pad  # noqa: PLC0415 - 运行时按需加载

    with tempfile.TemporaryDirectory() as tmp:
        pem = Path(tmp) / "pub.pem"
        pem.write_text(public_key_pem if public_key_pem.endswith("\n") else public_key_pem + "\n")
        aes_key = os.urandom(16)
        iv = os.urandom(16)
        cipher = cbc_encrypt(pkcs7_pad(password.encode()), aes_key, iv)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(pem),
             "-pkeyopt", "rsa_padding_mode:pkcs1"],
            input=aes_key, capture_output=True)
        if result.returncode != 0:
            raise SmokeError("openssl RSA encrypt failed: " + result.stderr.decode("utf-8", "replace"))
        key_part = base64.b64encode(result.stdout).decode()
    return "{}:{}:{}".format(key_part, base64.b64encode(iv).decode(), base64.b64encode(cipher).decode())


def build_license(panel, license_file, edition="enterprise"):
    """只为当前面板生成一份自制证书文件（签名用本仓库自签根，官方不接受）。"""
    run([sys.executable, str(ROOT / "tools/gen_license.py"),
         "--edition", edition, "--expires", "9999-12-31", "--nodes", "999",
         "--assignee", "YG", "--offline", "--out", str(license_file),
         "--db", str(Path(panel.data) / "db/xpack.db"),
         "--serial-path", str(Path(panel.data) / "db/.serial")])
    if not Path(license_file).is_file():
        raise SmokeError("gen_license did not produce " + str(license_file))


def apply_license(panel, license_file):
    """把证书直接写进 licenses 表并绑定主节点（生产安装走的就是这条路径）。"""
    output = run([sys.executable, str(ROOT / "tools/gen_license.py"), "--import-file", str(license_file),
                  "--apply", "--no-restart",
                  "--db", str(Path(panel.data) / "db/xpack.db"),
                  "--serial-path", str(Path(panel.data) / "db/.serial")])
    if "插入 1" not in output and "复用 1" not in output:
        raise SmokeError("license import did not report an insert:\n" + output)


# --------------------------------------------------------------------------- #
# 测试用例
# --------------------------------------------------------------------------- #
class Checker:
    def __init__(self):
        self.failures = []

    def check(self, name, condition, detail=""):
        print(("  [ok]   " if condition else "  [FAIL] ") + name + ("" if condition else "  " + str(detail)),
              flush=True)
        if not condition:
            self.failures.append(name)
        return condition


def upload_license(panel, license_file):
    """走面板的证书上传接口，返回 (状态码, 消息)。"""
    boundary = "----xpacksmoke{}".format(int(time.time() * 1000))
    body = (
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"license.txt\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n".format(b=boundary).encode()
        + Path(license_file).read_bytes()
        + "\r\n--{b}--\r\n".format(b=boundary).encode()
    )
    headers = {
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "Cookie": "; ".join("{}={}".format(k, v) for k, v in panel.cookies.items()),
        "X-CSRF-Token": panel.cookies.get("pcsrftoken", ""),
    }
    request = urllib.request.Request(panel.url + "/api/v2/core/licenses/upload", data=body,
                                     method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json_of(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as error:
        return error.code, json_of(error.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError) as error:
        return 0, {"message": str(error)}


CERT_FAILURE_MARKERS = ("verify certificate", "证书校验", "证书链", "certificate failed")


def patched_case(image, workdir, checker):
    print("\n== 破解内核：完整接口链路", flush=True)
    data = workdir / "data-patched"
    data.mkdir()
    panel = Panel("xpack-smoke-patched", image, data, free_port())
    try:
        panel.create()
        license_file = workdir / "license-patched.txt"
        build_license(panel, license_file)

        # 空库状态下上传自制证书：官方内核会在这里被证书校验拦住，破解内核不会。
        panel.login()
        upload_status, upload_body = upload_license(panel, license_file)
        patched_message = str(upload_body.get("message", ""))
        checker.check("上传接口不再因证书校验被拒",
                      not any(marker in patched_message for marker in CERT_FAILURE_MARKERS),
                      "HTTP {} {}".format(upload_status, patched_message[:200]))

        panel.stop()
        apply_license(panel, license_file)
        panel.start()
        panel.cookies.clear()
        panel.login()

        status, text = panel.request("/api/v2/core/licenses/master/status")
        master = json_of(text).get("data") or {}
        checker.check("licenses/master/status 返回 Bound", master.get("status") == "Bound", text[:200])

        status, text = panel.request("/api/v2/core/licenses/search", "POST", {"page": 1, "pageSize": 5})
        items = (json_of(text).get("data") or {}).get("items") or []
        checker.check("licenses/search 能读到自制证书", bool(items), text[:200])
        if items:
            item = items[0]
            checker.check("证书状态为 Bound", item.get("status") == "Bound", item.get("status"))
            nodes = item.get("freeNodes") or []
            checker.check("绑定的 local 节点被识别为 XPack", any(n.get("isXpack") for n in nodes), nodes)
            checker.check("授权对象/节点数写入正确",
                          item.get("assigneeName") == "YG" and item.get("freeCount") == 999,
                          (item.get("assigneeName"), item.get("freeCount")))

        status, text = panel.request("/api/v2/core/xpack/nodes/search", "POST", {"page": 1, "pageSize": 5})
        payload = json_of(text)
        checker.check("专业版接口 xpack/nodes/search 放行", payload.get("code") == 200, text[:200])
        checker.check("专业版接口返回节点数据", bool((payload.get("data") or {}).get("items")), text[:200])
        return patched_message
    finally:
        panel.stop()
        panel.remove()


def official_case(image, workdir, checker, patched_message):
    print("\n== 官方内核：同一份证书对照", flush=True)
    data = workdir / "data-official"
    data.mkdir()
    panel = Panel("xpack-smoke-official", image, data, free_port())
    try:
        panel.create()
        license_file = workdir / "license-official.txt"
        build_license(panel, license_file)
        panel.login()
        status, body = upload_license(panel, license_file)
        message = str(body.get("message", ""))
        checker.check("官方内核在证书校验处拒绝自制证书",
                      any(marker in message for marker in CERT_FAILURE_MARKERS),
                      "HTTP {} {}".format(status, message[:200]))
        checker.check("破解内核与官方内核的结论不同",
                      message.strip() != (patched_message or "").strip(),
                      "patched={!r} official={!r}".format(patched_message, message))
    finally:
        panel.stop()
        panel.remove()


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def prepare_context(release, package, arch, workdir):
    core = release / "core-linux-{0}".format(arch)
    agent_original = release / "agent-linux-{0}.orig".format(arch)
    for path in (core, agent_original, package):
        if not Path(path).is_file():
            raise SmokeError("missing required input: " + str(path))
    context = workdir / "ctx"
    context.mkdir()
    shutil.copyfile(core, context / "core")
    patch_agent(agent_original, context / "agent")
    (context / "1pctl").write_text(patch_1pctl(extract_1pctl(package), CONTAINER_PORT))
    (context / "entrypoint.sh").write_text(ENTRYPOINT)
    (context / "Dockerfile").write_text(DOCKERFILE)
    for name in ("core", "agent", "1pctl", "entrypoint.sh"):
        (context / name).chmod(0o755)
    return context


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release", type=Path, required=True,
                        help="release 目录，如 build/release-v2.4.0")
    parser.add_argument("--package", type=Path, required=True,
                        help="官方安装包（提供 1pctl），如 build/dl/1panel-v2.4.0-linux-amd64.tar.gz")
    parser.add_argument("--arch", default="amd64", choices=("amd64", "arm64"))
    parser.add_argument("--orig-core", type=Path,
                        help="官方内核原件，给出时额外跑「官方内核拒绝自制证书」的对照")
    parser.add_argument("--image", default=None, help="冒烟镜像 tag（默认随机）")
    parser.add_argument("--keep", action="store_true", help="保留工作目录便于排查")
    args = parser.parse_args(argv)

    if not shutil.which("docker"):
        print("smoke error: docker is required", file=sys.stderr)
        return 2
    release = args.release.resolve()
    manifest_path = release / "manifest.json"
    version = json.loads(manifest_path.read_text())["version"] if manifest_path.is_file() else "unknown"
    tag = args.image or "xpack-smoke:{}".format(re.sub(r"[^a-z0-9.-]+", "-", version.lower()))

    workdir = Path(tempfile.mkdtemp(prefix="xpack-smoke-"))
    checker = Checker()
    try:
        context = prepare_context(release, args.package.resolve(), args.arch, workdir)
        build_image(context, tag)
        patched_message = patched_case(tag, workdir, checker)
        if args.orig_core:
            official_context = context.parent / "ctx-official"
            shutil.copytree(context, official_context)
            shutil.copyfile(args.orig_core.resolve(), official_context / "core")
            official_image = tag + "-official"
            build_image(official_context, official_image)
            official_case(official_image, workdir, checker, patched_message)
        else:
            print("\n== 跳过官方内核对照（未提供 --orig-core）", flush=True)
    except Exception as exc:  # noqa: BLE001 - 冒烟失败要以非 0 退出
        traceback.print_exc()
        checker.failures.append("unexpected error: {}".format(exc))
    finally:
        if not args.keep:
            subprocess.run(["docker", "image", "rm", "-f", tag], text=True, capture_output=True)
            subprocess.run(["docker", "image", "rm", "-f", tag + "-official"], text=True, capture_output=True)
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print("\nworkdir kept: " + str(workdir), flush=True)
            print("image kept : " + tag, flush=True)

    print("\n== 结果：{}".format("全部通过" if not checker.failures else
                                 "{} 项失败 -> {}".format(len(checker.failures), ", ".join(checker.failures))),
          flush=True)
    return 0 if not checker.failures else 1


if __name__ == "__main__":
    sys.exit(main())
