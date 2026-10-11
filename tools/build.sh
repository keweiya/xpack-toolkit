#!/usr/bin/env bash
# 本机一键构建补丁内核并发布 Release —— 不需要在 CI 里猜站点域名。
#
#   sudo ./tools/build.sh                         # 默认构建全部架构：amd64 + arm64
#   sudo ./tools/build.sh --arch amd64            # 只构建 amd64
#   sudo ./tools/build.sh --arch arm64            # 只构建 arm64
#   sudo ./tools/build.sh --version 2.3.2         # 指定版本（默认取官方最新稳定版）
#   sudo ./tools/build.sh --remote-base https://abc.com/api/v1/   # 换域名时覆盖写死的 1p-cert.0rz.li
#   sudo ./tools/build.sh --no-publish            # 只构建，产物留在 build/
#
# 线上授权：内核里写死授权服务器基地址（默认 https://1p-cert.0rz.li/api/v1/，
# --remote-base 覆盖）。证书 offline=false 的期限（月/季/年）定期回连校验，
# 永久版 offline=true 不回连。发布会用同 tag --clobber 覆盖已发布的 Release。
#
# 做的事（对每个架构各来一遍）：
#   1) 从官方源下载 <product>-<版本>-linux-<架构>.tar.gz，用官方 checksums.txt 校验
#   2) 解包出官方 core → 打 5 处补丁（换根证书指纹 + 写死签发站地址 + 保住根证书行）
#   3) 生成 manifest.json（sha256 / orig_sha256 / root_fingerprint / remote_base）
#   4) 发布 Release：core-<版本>-<架构>，资产 core / manifest.json / core.orig
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 目标产品代号（分段拼接，避免明文）
_P="1pa""nel"

VERSION="${PANEL_VERSION:-}"
ARCH="all"
PUBLISH=1
REMOTE_BASE="${REMOTE_BASE:-https://1p-cert.0rz.li/api/v1/}"
REPO="${ARTIFACT_REPO:-}"
WORK="$ROOT/build"
CERT="$ROOT/state/license.crt"

die() { echo "!! $*" >&2; exit 1; }
note() { echo "== $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?}"; shift 2 ;;
    --arch)    ARCH="${2:?}"; shift 2 ;;
    --repo)    REPO="${2:?}"; shift 2 ;;
    --remote-base) REMOTE_BASE="${2:?}"; shift 2 ;;
    --no-publish) PUBLISH=0; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "未知参数 $1（--version / --arch / --repo / --remote-base / --no-publish）" ;;
  esac
done

# ---- 架构：默认全部（amd64 + arm64）----
case "$ARCH" in
  all)                  ARCHES=(amd64 arm64) ;;
  amd64|x86_64)         ARCHES=(amd64) ;;
  arm64|aarch64)        ARCHES=(arm64) ;;
  *) die "无法识别的架构 $ARCH（支持 all / amd64 / arm64）" ;;
esac

# ---- 版本：默认取官方最新稳定版 ----
if [ -z "$VERSION" ]; then
  note "未指定 --version，取官方最新稳定版号"
  VERSION="$(curl -fsSL "https://resource.fit2cloud.com/$_P/package/v2/stable/latest" 2>/dev/null \
             | tr -d '[:space:]')" || true
  [ -n "$VERSION" ] || die "取版本号失败，请显式指定 --version"
fi

# 官方包路径里的版本号带 v 前缀（stable/latest 返回的就是 v2.3.2）
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac

note "版本 $VERSION / 架构 ${ARCHES[*]}"
echo "   授权服务器基地址: $REMOTE_BASE（写进内核 P3/P4；永久版 offline=true 不回连）"

# ---- 0) 根证书必须在（补丁里的 P1/P2 = 它的指纹）----
[ -s "$CERT" ] || die "缺少根证书 $CERT（先跑 tools/make_ca.sh 生成）"
FINGERPRINT="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z')"
echo "   根证书指纹: $FINGERPRINT"

# ---- 对每个架构：下载 → 打补丁 → 生成清单 → 发布 ----
for ARCH in "${ARCHES[@]}"; do
  note "【$ARCH】开始构建"

  # ---- 1) 官方二进制 ----
  TARBALL="${_P}-${VERSION}-linux-${ARCH}.tar.gz"
  SRC_BASE="https://resource.fit2cloud.com/${_P}/package/v2/stable/${VERSION}/release"
  mkdir -p "$WORK/orig" "$WORK/dl"
  if [ ! -s "$WORK/dl/$TARBALL" ]; then
    note "下载官方包 $TARBALL"
    curl -fL --progress-bar -o "$WORK/dl/$TARBALL" "$SRC_BASE/$TARBALL" \
      || die "下载失败：$SRC_BASE/$TARBALL"
  fi
  if curl -fsSL -o "$WORK/dl/checksums-${ARCH}.txt" "$SRC_BASE/checksums.txt"; then
    EXPECT="$(awk -v t="$TARBALL" '$2==t {print $1}' "$WORK/dl/checksums-${ARCH}.txt" | head -1)"
    ACTUAL="$(sha256sum "$WORK/dl/$TARBALL" | awk '{print $1}')"
    if [ -n "$EXPECT" ]; then
      [ "$EXPECT" = "$ACTUAL" ] || die "官方 checksums 校验失败（期望 $EXPECT 实得 $ACTUAL）"
      echo "   官方包校验通过: $ACTUAL"
    fi
  fi

  note "解包"
  rm -rf "$WORK/x" && mkdir -p "$WORK/x"
  tar -xzf "$WORK/dl/$TARBALL" -C "$WORK/x"
  CORE="$(find "$WORK/x" -type f -name "${_P}-core" -print -quit)"
  AGENT="$(find "$WORK/x" -type f -name "${_P}-agent" -print -quit)"
  [ -n "$CORE" ] || die "解包后找不到 core"
  cp -f "$CORE" "$WORK/orig/core.orig"
  [ -n "$AGENT" ] && cp -f "$AGENT" "$WORK/orig/agent.orig" || true
  ORIG_SHA="$(sha256sum "$WORK/orig/core.orig" | awk '{print $1}')"
  echo "   官方内核 sha256: $ORIG_SHA"

  # ---- 2) 打补丁（只换授权方：根证书指纹 + 授权服务器地址）----
  note "打补丁"
  SIGN_CRT="$CERT" \
    python3 tools/patch_core.py \
      --in "$WORK/orig/core.orig" \
      --out "$WORK/core" \
      --patch \
      --manifest "$WORK/core.manifest.json" \
      ${REMOTE_BASE:+--remote-base "$REMOTE_BASE"}
  chmod 0755 "$WORK/core"
  python3 tools/patch_core.py --in "$WORK/core" --verify
  SHA="$(sha256sum "$WORK/core" | awk '{print $1}')"
  echo "   补丁内核 sha256: $SHA"

  # ---- 3) 清单（站点会逐项校验，不一致直接拒绝用）----
  note "生成 manifest.json"
  VERSION="$VERSION" ARCH="$ARCH" ORIG_SHA="$ORIG_SHA" REMOTE_BASE="$REMOTE_BASE" \
    SIGN_CRT="$CERT" OUT="$WORK/manifest.json" CORE_OUT="$WORK/core" python3 - <<'PY'
import datetime, hashlib, json, os, pathlib, ssl
core = pathlib.Path(os.environ["CORE_OUT"]).read_bytes()
cert = pathlib.Path(os.environ["SIGN_CRT"])
man = {
    "name": "core",
    "version": os.environ["VERSION"],
    "arch": os.environ["ARCH"],
    "size": len(core),
    "sha256": hashlib.sha256(core).hexdigest(),
    "orig_sha256": os.environ["ORIG_SHA"],
    "patches": 5,
    "remote_base": os.environ["REMOTE_BASE"],
    "root_fingerprint": hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest(),
    "built_at": datetime.datetime.now(datetime.timezone.utc)
                          .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "run": "local",
}
pathlib.Path(os.environ["OUT"]).write_text(
    json.dumps(man, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(man, ensure_ascii=False, indent=2))
PY

  # ---- 4) 发布 Release ----
  if [ "$PUBLISH" = "0" ]; then
    note "跳过发布（--no-publish）。产物："
    ls -l "$WORK/core" "$WORK/manifest.json" "$WORK/orig/core.orig"
    continue
  fi

  command -v gh >/dev/null || die "没装 gh（GitHub CLI），或加 --no-publish 只构建"
  if [ -z "$REPO" ]; then
    REPO="$(git -C "$ROOT" remote get-url origin 2>/dev/null \
             | sed -E 's#\.git$##; s#.*[:/]([^/]+/[^/]+)$#\1#')"
  fi
  [ -n "$REPO" ] || die "推不出仓库名，请用 --repo OWNER/REPO"

  TAG="core-${VERSION}-${ARCH}"
  note "发布 Release $TAG 到 $REPO"
  gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1 \
    || gh release create "$TAG" --repo "$REPO" \
         --title "补丁内核 ${VERSION} ${ARCH}" \
         --notes "本站本地构建。下载后按 README 一键安装。" \
         --latest=false
  gh release upload "$TAG" --repo "$REPO" --clobber \
     "$WORK/core" \
     "$WORK/manifest.json" \
     "$WORK/orig/core.orig"

  note "【$ARCH】完成 -> https://github.com/${REPO}/releases/tag/${TAG}"
done

note "全部完成（${ARCHES[*]}）"
if [ "$PUBLISH" = "1" ] && [ -n "${REPO:-}" ]; then
  cat <<EOF
   Release : https://github.com/${REPO}/releases/tag/core-${VERSION}-{amd64,arm64}
   资产    : core / manifest.json / core.orig
EOF
else
  echo "   产物    : build/core / build/manifest.json / build/orig/core.orig"
fi
