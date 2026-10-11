#!/usr/bin/env bash
# 生成根证书（信任锚）—— 打补丁后的内核只信这一份 CA，所以它必须持久化、跨部署保持不变。
#
#   ./tools/make_ca.sh
#
# 产物：
#   $STATE/license.key   RSA 4096 私钥（0600）
#   $STATE/license.crt   自签 CA 证书（CA:TRUE，50 年）
#
# 补丁器会把这个证书的 sha256(DER) 十六进制指纹写进 core 的 P1/P2，
# 并把证书内容写进面板 core_settings 的 4 行根证书。**换了这份证书 = 所有已改的
# 面板全部失效**（要重新下发内核），所以请把 state 目录纳入备份。
set -euo pipefail
cd "$(dirname "$0")/.."

STATE=${STATE:-state}
DAYS=${CA_DAYS:-18262}                       # 50 年
SUBJ=${CA_SUBJECT:-/C=CN/ST=License/O=License/OU=License/CN=license-center.local}

mkdir -p "$STATE"
if [ -s "$STATE/license.key" ] && [ -s "$STATE/license.crt" ]; then
  echo "已存在，不覆盖：$STATE/license.key / $STATE/license.crt"
else
  echo "生成根证书 -> $STATE"
  openssl genrsa -out "$STATE/license.key" 4096 2>/dev/null
  openssl req -x509 -new -key "$STATE/license.key" -sha256 -days "$DAYS" \
    -subj "$SUBJ" -out "$STATE/license.crt" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  chmod 600 "$STATE/license.key"
fi

STATE="$STATE" python3 - <<'PY'
import hashlib, os, ssl
state = os.environ["STATE"]
pem = open(os.path.join(state, "license.crt")).read()
fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
print("指纹 sha256(DER) : %s" % fp)
print("面板导入用授权文本 : python3 tools/deploy.sh cert")
PY
