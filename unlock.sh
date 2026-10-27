#!/usr/bin/env bash
# 1Panel v2 内网本地破解内核一键安装 / 更新。
#
# 依赖：bash + coreutils + openssl（系统自带）。授权表写入优先用系统 sqlite3，
#       没有就自动下载仓库内置的静态单文件（tools/bin/sqlite3mini-linux-<arch>），
#       所以目标机不需要装 python、也不需要装 sqlite3。
#
# 流程（不再需要本站签名私钥，也不再校验任何签名）：
#   1) 检测宿主机 1Panel 版本与 Release 最新发版；
#      若 Release 版本较新，先把宿主机 1Panel 升级到与 Release 一致（官方包升级）；
#   2) 从 Release 下载破解内核（已移除全部授权检查），替换官方/第三方内核；
#   3) 本地生成企业版授权证书（999 节点、永久有效、离线），写 licenses 表并绑定
#      主节点；机器中既有证书一律保留不删除，若主节点已绑定则先解绑
#      （交互终端会提示确认，非交互默认自动解绑）。
#
# 已有安装直接重跑同一条命令即可，无需手动卸载。
set -euo pipefail
umask 077
REPO="${REPO:-keweiya/xpack-toolkit}"

# 先定义日志/失败出口：下面的 root、架构检查在它们之前就要用。
log() { printf '== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 启动方式决定下载线路：`curl <前缀>https://raw.githubusercontent.com/.../unlock.sh | sudo bash`
# 里如果套了加速前缀，就整轮沿用那个前缀，不再探测官方直连。
# 管道执行时 curl 还在把脚本喂给 bash，所以能在 /proc 里抓到它的命令行。
# ---------------------------------------------------------------------------
mirror_prefix_from_url() {
  local url="$1" scheme rest host tail
  scheme="${url%%://*}"
  rest="${url#*://}"
  host="${rest%%/*}"
  tail="${rest#*/}"
  case "$tail" in
    http://*|https://*) printf '%s://%s/\n' "$scheme" "$host" ;;
  esac
}

BOOTSTRAP_PREFIX=""
detect_bootstrap_route() {
  local pid comm arg found=""
  for pid in /proc/[0-9]*; do
    [ "${pid#/proc/}" = "$$" ] && continue
    comm="$(cat "$pid/comm" 2>/dev/null)" || continue
    case "$comm" in curl|wget) ;; *) continue ;; esac
    while IFS= read -r -d '' arg; do
      case "$arg" in
        # 允许带 ?v=… 缓存穿透参数：raw.githubusercontent 对分支 URL 有 5 分钟 CDN 缓存。
        http://*unlock.sh*|https://*unlock.sh*) found="${arg%%\?*}" ;;
      esac
    done < "$pid/cmdline" 2>/dev/null || true
    [ -n "$found" ] && break
  done
  [ -n "$found" ] || return 0
  BOOTSTRAP_PREFIX="$(mirror_prefix_from_url "$found")"
}
detect_bootstrap_route

[ "$(id -u)" -eq 0 ] || die "Run as root"
[ "$(uname -s)" = Linux ] || die "This release provides Linux cores"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  armv7l) ARCH=armv7 ;; ppc64le|s390x|riscv64) ARCH="$(uname -m)" ;;
  *) die "Unknown architecture: $(uname -m)" ;;
esac
PLATFORM="linux-$ARCH"
PANEL_CTL="${PANEL_CTL:-/usr/local/bin/1pctl}"

PANEL_ROOT="${PANEL_ROOT:-/opt/1panel}"
CORE_BIN="${CORE_BIN:-/usr/local/bin/1panel-core}"
AGENT_BIN="${AGENT_BIN:-/usr/local/bin/1panel-agent}"
CORE_SVC="${CORE_SVC:-1panel-core}"
AGENT_SVC="${AGENT_SVC:-1panel-agent}"
XPACK_DB="${XPACK_DB:-$PANEL_ROOT/db/xpack.db}"
SERIAL_PATH="${SERIAL_PATH:-$PANEL_ROOT/db/.serial}"
BACKUP="${BACKUP:-$PANEL_ROOT/crack/backup}"
PERSIST="${UNLOCK_WORK:-$PANEL_ROOT/unlock}"
OFFICIAL_BASE="https://resource.fit2cloud.com/1panel/package/v2/stable"
MODE=install

trap 'printf "!! Failed; artifacts/backups retained: %s / %s\n" "$PERSIST" "$BACKUP" >&2' ERR

PROGRESS="${PROGRESS:-auto}"
STALL_SECONDS="${STALL_SECONDS:-30}"
STALL_BYTES="${STALL_BYTES:-1024}"
DL_MAX_TIME="${DL_MAX_TIME:-1800}"

progress_bar_enabled() {
  case "$PROGRESS" in
    on) return 0 ;;
    off) return 1 ;;
    auto) [ -t 2 ] ;;
    *) die "Invalid PROGRESS; expected auto, on or off" ;;
  esac
}

# ---------------------------------------------------------------------------
# 运行时依赖
#   · 下载/校验/版本门禁：纯 bash + coreutils + openssl（系统默认安装）
#   · 授权证书写库：系统 sqlite3，缺失时下载仓库内置的静态 sqlite3mini
# 脚本不再需要 python。
# ---------------------------------------------------------------------------
# SQLite 执行器：优先系统的 sqlite3，没有就用仓库内置的静态单文件
# （tools/bin/sqlite3mini-linux-<arch>，源码 tools/sqlite3mini.c，sha256 固定校验）。
SQLITE3_SHA_amd64="ba5c50b4b24809fa88b760285c221e88c71851cc945e38133823880e002367d7"
SQLITE3_SHA_arm64=""
SQLITE3_BIN=""

ensure_sqlite3() {
  [ -n "$SQLITE3_BIN" ] && return 0
  if command -v sqlite3 >/dev/null 2>&1; then
    SQLITE3_BIN="$(command -v sqlite3)"; return 0
  fi
  local want got dir
  eval "want=\"\${SQLITE3_SHA_$ARCH:-}\""
  [ -n "$want" ] || return 1
  dir="$PERSIST/tools"
  mkdir -p "$dir"
  if [ ! -x "$dir/sqlite3mini" ]; then
    fetch "https://raw.githubusercontent.com/$REPO/main/tools/bin/sqlite3mini-linux-$ARCH" \
      "$dir/sqlite3mini" silent || return 1
    chmod 0755 "$dir/sqlite3mini"
  fi
  got="$(sha256sum "$dir/sqlite3mini" | awk '{print $1}')"
  [ "$got" = "$want" ] || return 1
  SQLITE3_BIN="$dir/sqlite3mini"
  log "Using bundled static sqlite3 ($ARCH)"
}

norm_version() {
  case "$1" in
    v[0-9]*.[0-9]*.[0-9]*) printf '%s\n' "$1" ;;
    [0-9]*.[0-9]*.[0-9]*) printf 'v%s\n' "$1" ;;
  esac
}

# $1 已装版本 $2 Release 版本 -> newer（Release 更新）| equal | older
compare_versions() {
  local a="${1#v}" b="${2#v}" low
  if [ "$a" = "$b" ]; then printf 'equal\n'; return 0; fi
  low="$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)"
  if [ "$low" = "$a" ]; then printf 'newer\n'; else printf 'older\n'; fi
}

# 顶层 JSON 数组按对象切分（字符串里的括号不计），每行一个对象。
json_objects() {
  awk '
  {
    n = length($0)
    for (i = 1; i <= n; i++) {
      c = substr($0, i, 1)
      if (in_str) {
        buf = buf c
        if (esc) esc = 0
        else if (c == "\\") esc = 1
        else if (c == "\"") in_str = 0
        continue
      }
      if (c == "\"") { in_str = 1; buf = buf c; continue }
      if (c == "{") { depth++; if (depth == 1) { buf = "{"; continue } }
      if (c == "}") { depth--; if (depth == 0) { print buf "}"; buf = ""; continue } }
      if (depth > 0) buf = buf c
    }
  }'
}

# manifest.json 里某平台的某个字段（字符串去掉引号，数字原样）。
manifest_field() {  # $1 platform $2 field
  awk -v plat="$1" -v f="$2" '
    inside && /^    \},?$/ { inside = 0 }
    !inside && index($0, "\"" plat "\": {") { inside = 1; next }
    inside {
      pat = "\"" f "\": "
      i = index($0, pat)
      if (i) {
        v = substr($0, i + length(pat))
        sub(/,$/, "", v); gsub(/[" ]/, "", v); print v; exit
      }
    }' "$RUN/manifest.json"
}

# sha256 + ELF 头/架构校验（$1 文件 $2 期望 sha $3 arch $4 描述）
verify_asset() {
  local file="$1" want="$2" arch="$3" label="$4" got magic machine
  got="$(sha256sum "$file" | awk '{print $1}')"
  [ "$got" = "$want" ] || die "$label SHA-256 mismatch"
  magic="$(head -c 6 "$file" | od -An -v -tx1 | tr -d ' \n')"
  [ "$magic" = 7f454c460201 ] || die "$label is not a 64-bit little-endian ELF"
  machine="$(od -An -v -tu2 -j18 -N2 "$file" | tr -d ' ')"
  case "$arch" in
    amd64) [ "$machine" = 62 ] || die "$label ELF architecture mismatch" ;;
    arm64) [ "$machine" = 183 ] || die "$label ELF architecture mismatch" ;;
  esac
  printf 'Verified %s sha256 + arch: %s\n' "$label" "$(printf '%s' "$want" | cut -c1-16)"
}

# ---------------------------------------------------------------------------
# 授权证书（纯 shell：openssl 做 AES-128-CBC，sqlite3 写 licenses 表）
# 与 tools/gen_license.py 的字段编码完全一致，两条实现可互读对方的库。
# ---------------------------------------------------------------------------
LIC_STATIC_KEY="nel1Pa2520pack@x"

hexof() { od -An -v -tx1 | tr -d ' \n'; }

lic_key() {  # $1 证书名 $2 可选 YYYYMMDD（status 字段用）-> 16 字节 key
  local n="$1" k
  case "$n" in license-Panel-*) n="${n#license-Panel-}" ;; esac
  if [ -n "${2:-}" ]; then k="$n-$2"; else k="${n}2520pack@x"; fi
  while [ "${#k}" -lt 16 ]; do k="${k}u"; done
  printf '%s' "${k:0:16}"
}

lic_enc() {  # $1 明文 $2 key -> base64(iv||密文)
  local tmp rc
  tmp="$(mktemp "${TMPDIR:-/tmp}/xpack-enc.XXXXXX")"
  head -c 16 /dev/urandom > "$tmp"
  printf '%s' "$1" | openssl enc -aes-128-cbc -K "$(printf '%s' "$2" | hexof)" \
      -iv "$(head -c 16 "$tmp" | hexof)" >> "$tmp" 2>/dev/null
  rc=$?
  [ "$rc" = 0 ] && base64 -w0 < "$tmp"
  rm -f "$tmp"
  return "$rc"
}

lic_dec() {  # $1 base64 $2 key -> 明文
  local tmp size rc
  tmp="$(mktemp "${TMPDIR:-/tmp}/xpack-dec.XXXXXX")"
  printf '%s' "$1" | base64 -d > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  size="$(wc -c < "$tmp")"; size="${size// /}"
  if [ "$size" -lt 32 ] || [ $((size % 16)) -ne 0 ]; then rm -f "$tmp"; return 1; fi
  dd if="$tmp" of="$tmp.ct" bs=16 skip=1 2>/dev/null
  openssl enc -d -aes-128-cbc -K "$(printf '%s' "$2" | hexof)" \
      -iv "$(head -c 16 "$tmp" | hexof)" -in "$tmp.ct" 2>/dev/null
  rc=$?
  rm -f "$tmp" "$tmp.ct"
  return "$rc"
}

lic_sql() { "$SQLITE3_BIN" -batch -noheader "$@"; }
lic_db_ready() { [ -f "$1" ] && lic_sql "$1" "select count(*) from licenses;" >/dev/null 2>&1; }

lic_token() { openssl rand -hex "$1" | tr 'a-f' 'A-F'; }

lic_machine_id() {  # $1 panel serial 路径
  if [ -f "$1" ]; then tr -d '\n' < "$1"; return 0; fi
  if [ -f /etc/machine-id ]; then tr -d '\n' < /etc/machine-id; return 0; fi
  if [ -f /var/lib/dbus/machine-id ]; then tr -d '\n' < /var/lib/dbus/machine-id; return 0; fi
  printf '0%.0s' $(seq 32)
}

# 生成证书内容 JSON：$1 edition $2 expires $3 nodes $4 assignee $5 issuer $6 sms $7 version $8 device
lic_json() {
  local edition="$1" exp="$2" nodes="$3" who="$4" issuer="$5" sms="$6" ver="$7" dev="$8"
  local label="Professional" name token iso prods
  [ "$edition" = enterprise ] && label="Enterprise"
  name="1Panel-${label}-$(lic_token 6)"
  token="1P-$(lic_token 12)"
  iso="${exp}T00:00:00Z"
  prods="{\"name\":\"product-1panel-pro\",\"expiresAt\":\"$iso\",\"maxNodeCount\":$nodes,\"versionConstraint\":\"$ver\"}"
  if [ "$edition" = enterprise ]; then
    prods="$prods,{\"name\":\"product-1panel-xpack\",\"expiresAt\":\"$iso\",\"maxNodeCount\":$nodes,\"versionConstraint\":\"$ver\"}"
  fi
  printf '{"licenseName":"%s","usageName":"1panel","assigneeName":"%s","versionConstraint":"%s","deviceID":"%s","license":"%s","trial":false,"offline":true,"timerDiff":"0","issuer":"%s","products":[%s],"annotations":{"lxware.cn/username":"Bound","lxware.cn/edition":"%s","lxware.cn/nodes":"%s","lxware.cn/xpack-toolkit":"true"},"smsTotal":%s,"smsUsed":0}' \
    "$name" "$who" "$ver" "$dev" "$token" "$issuer" "$prods" "$edition" "$nodes" "$sms"
}

lic_json_field() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

# 三段式：base64(内容)-base64(签名)-base64(证书)；破解内核不校验签名与证书链。
lic_encode() {
  printf '%s-%s-%s' "$(printf '%s' "$1" | base64 -w0)" \
    "$(head -c 64 /dev/zero | base64 -w0)" "$(head -c 16 /dev/zero | base64 -w0)"
}

lic_is_toolkit_name() { [[ "$1" =~ ^1Panel-(Enterprise|Professional)-[0-9A-F]{12}$ ]]; }

# 主节点已绑定的证书名（--prompt-unbind 交互确认用），逗号分隔。
lic_bound_names() {  # $1 db
  local db="$1" id name_enc name_plain bind_enc out="" master
  master="$(lic_sql "$db" "select id from nodes where name='local';" 2>/dev/null)" || return 1
  for id in $(lic_sql "$db" "select id from licenses;"); do
    [ -n "$id" ] || continue
    name_enc="$(lic_sql "$db" "select coalesce(license_name,'') from licenses where id=$id;")"
    name_plain="$(lic_dec "$name_enc" "$LIC_STATIC_KEY" 2>/dev/null)" || continue
    bind_enc="$(lic_sql "$db" "select coalesce(bind_node_id,'') from licenses where id=$id;")"
    [ -n "$bind_enc" ] || continue
    [ "$(lic_dec "$bind_enc" "$(lic_key "$name_plain")" 2>/dev/null)" = "$master" ] || continue
    if lic_is_toolkit_name "$name_plain"; then continue; fi
    out="${out:+$out, }$name_plain"
  done
  printf '%s\n' "$out"
}

# 写库 + 绑定主节点。依赖 LIC_DB LIC_SERIAL LIC_TEXT LIC_NAME LIC_DEVICE
# LIC_ASSIGNEE LIC_VERSION LIC_ISSUER LIC_SMS LIC_NODES LIC_PRODUCT_PRO。
lic_apply() {
  local master rows id name_enc name_plain bind_enc free_enc free_plain node
  local unbind_ids="" del_ids="" toolkit_ids="" free_mig="" seen=","
  local bak="$LIC_DB.pre-license" stamp key tzdate sql
  local v_license_name v_usage v_assignee v_version v_device v_license v_offline v_trial
  local v_issuer v_product v_last_sync v_bind v_free_count v_free_nodes v_status v_message

  master="$(lic_sql "$LIC_DB" "select id from nodes where name='local';" 2>/dev/null)" || return 1
  [ -n "$master" ] && [ "$(printf '%s\n' "$master" | grep -c .)" = 1 ] || {
    printf 'expected exactly one master node in %s\n' "$LIC_DB" >&2; return 1; }

  rows="$(lic_sql "$LIC_DB" "select id from licenses;")" || return 1
  for id in $rows; do
    [ -n "$id" ] || continue
    name_enc="$(lic_sql "$LIC_DB" "select coalesce(license_name,'') from licenses where id=$id;")"
    name_plain="$(lic_dec "$name_enc" "$LIC_STATIC_KEY" 2>/dev/null)" || name_plain=""
    if lic_is_toolkit_name "$name_plain"; then
      del_ids="$del_ids $id"; toolkit_ids="$toolkit_ids $id"
    fi
  done

  # 旧脚本证书的子节点绑定迁移到新证书
  for id in $toolkit_ids; do
    name_enc="$(lic_sql "$LIC_DB" "select coalesce(license_name,'') from licenses where id=$id;")"
    name_plain="$(lic_dec "$name_enc" "$LIC_STATIC_KEY" 2>/dev/null)" || continue
    free_enc="$(lic_sql "$LIC_DB" "select coalesce(free_nodes,'') from licenses where id=$id;")"
    [ -n "$free_enc" ] || continue
    free_plain="$(lic_dec "$free_enc" "$(lic_key "$name_plain")" 2>/dev/null)" || continue
    for node in $(printf '%s' "$free_plain" | tr ',' ' '); do
      [ -n "$node" ] || continue
      case "$seen" in *",$node,"*) continue ;; esac
      seen="$seen$node,"
      free_mig="${free_mig:+$free_mig,}$node"
    done
  done

  # 主节点已绑定的第三方/官方证书先解绑（保留记录，只清 bind_node_id）
  for id in $rows; do
    [ -n "$id" ] || continue
    case " $del_ids " in *" $id "*) continue ;; esac
    name_enc="$(lic_sql "$LIC_DB" "select coalesce(license_name,'') from licenses where id=$id;")"
    name_plain="$(lic_dec "$name_enc" "$LIC_STATIC_KEY" 2>/dev/null)" || continue
    bind_enc="$(lic_sql "$LIC_DB" "select coalesce(bind_node_id,'') from licenses where id=$id;")"
    [ -n "$bind_enc" ] || continue
    [ "$(lic_dec "$bind_enc" "$(lic_key "$name_plain")" 2>/dev/null)" = "$master" ] || continue
    unbind_ids="$unbind_ids $id"
  done

  if [ ! -e "$bak" ]; then
    lic_sql "$LIC_DB" ".backup '$bak'" || return 1
  fi

  stamp="$(date +'%Y-%m-%d %H:%M:%S%:z')"
  key="$(lic_key "$LIC_NAME")"
  tzdate="$(date +%Y%m%d)"
  v_license_name="$(lic_enc "$LIC_NAME" "$LIC_STATIC_KEY")"
  v_license="$(lic_enc "$LIC_TEXT" "$LIC_STATIC_KEY")"
  v_usage="$(lic_enc '1panel' "$key")"
  v_assignee="$(lic_enc "$LIC_ASSIGNEE" "$key")"
  v_version="$(lic_enc "$LIC_VERSION" "$key")"
  v_device="$(lic_enc "$LIC_DEVICE" "$key")"
  v_offline="$(lic_enc 'true' "$key")"
  v_trial="$(lic_enc 'false' "$key")"
  v_issuer="$(lic_enc "$LIC_ISSUER" "$key")"
  v_product="$(lic_enc "$LIC_PRODUCT_PRO" "$key")"
  v_last_sync="$(lic_enc "$(date +%s)" "$key")"
  v_bind="$(lic_enc "$master" "$key")"
  v_free_count="$(lic_enc "$LIC_NODES" "$key")"
  v_status="$(lic_enc 'Bound' "$(lic_key "$LIC_NAME" "$tzdate")")"
  v_message="$(lic_enc '' "$key")"
  v_free_nodes=""
  [ -z "$free_mig" ] || v_free_nodes="$(lic_enc "$free_mig" "$key")"

  sql=".bail on
BEGIN IMMEDIATE;"
  for id in $unbind_ids; do
    name_enc="$(lic_sql "$LIC_DB" "select coalesce(license_name,'') from licenses where id=$id;")"
    name_plain="$(lic_dec "$name_enc" "$LIC_STATIC_KEY" 2>/dev/null)" || continue
    sql="$sql
UPDATE licenses SET bind_node_id='$(lic_enc '' "$(lic_key "$name_plain")")' WHERE id=$id;"
  done
  for id in $del_ids; do
    sql="$sql
DELETE FROM licenses WHERE id=$id;"
  done
  sql="$sql
INSERT INTO licenses (license_name,usage_name,assignee_name,version_constraint,device_id,license,offline,trial,issuer,product_pro,last_sync_at,sms_total,sms_used,bind_node_id,free_count,free_nodes,status,message,created_at,updated_at) VALUES ('$v_license_name','$v_usage','$v_assignee','$v_version','$v_device','$v_license','$v_offline','$v_trial','$v_issuer','$v_product','$v_last_sync','$LIC_SMS','0','$v_bind','$v_free_count','$v_free_nodes','$v_status','$v_message','$stamp','$stamp');
COMMIT;"
  printf '%s\n' "$sql" | "$SQLITE3_BIN" -batch "$LIC_DB" || {
    printf 'license insert failed\n' >&2; return 1; }

  if [ -f "$LIC_SERIAL" ]; then
    [ "$(tr -d '\n' < "$LIC_SERIAL")" = "$LIC_DEVICE" ] || {
      printf 'certificate device ID differs from panel serial\n' >&2; return 1; }
  else
    printf '%s' "$LIC_DEVICE" > "$LIC_SERIAL" && chmod 600 "$LIC_SERIAL" || return 1
  fi
  printf 'deleted=%s unbound=%s migrated=%s\n' "$(printf '%s' "$del_ids" | grep -c .)" \
    "$(printf '%s' "$unbind_ids" | grep -c .)" "${free_mig:-none}"
}

# 回读校验：主节点有且仅有一条绑定证书，offline、未过期、device 与 serial 一致。
lic_verify() {  # $1 db $2 serial
  local db="$1" serial="$2" master id name_enc name_plain bind_enc bound="" count=0
  local name product offline device
  master="$(lic_sql "$db" "select id from nodes where name='local';" 2>/dev/null)" || return 1
  for id in $(lic_sql "$db" "select id from licenses;"); do
    [ -n "$id" ] || continue
    name_enc="$(lic_sql "$db" "select coalesce(license_name,'') from licenses where id=$id;")"
    name_plain="$(lic_dec "$name_enc" "$LIC_STATIC_KEY" 2>/dev/null)" || continue
    bind_enc="$(lic_sql "$db" "select coalesce(bind_node_id,'') from licenses where id=$id;")"
    [ -n "$bind_enc" ] || continue
    [ "$(lic_dec "$bind_enc" "$(lic_key "$name_plain")" 2>/dev/null)" = "$master" ] || continue
    count=$((count + 1)); bound="$id"
  done
  [ "$count" = 1 ] || { printf 'expected one master-bound license, found %s\n' "$count" >&2; return 1; }
  name="$(lic_dec "$(lic_sql "$db" "select coalesce(license_name,'') from licenses where id=$bound;")" "$LIC_STATIC_KEY")"
  product="$(lic_dec "$(lic_sql "$db" "select coalesce(product_pro,'') from licenses where id=$bound;")" "$(lic_key "$name")")"
  offline="$(lic_dec "$(lic_sql "$db" "select coalesce(offline,'') from licenses where id=$bound;")" "$(lic_key "$name")")"
  device="$(lic_dec "$(lic_sql "$db" "select coalesce(device_id,'') from licenses where id=$bound;")" "$(lic_key "$name")")"
  [ "$offline" = true ] || { printf 'master-bound license must be offline\n' >&2; return 1; }
  case "$product" in
    ''|*[!0-9]*) printf 'invalid product_pro\n' >&2; return 1 ;;
  esac
  if [ "$product" != 0 ] && [ "$product" -le "$(date +%s)" ]; then
    printf 'master-bound license must be unexpired\n' >&2; return 1
  fi
  [ -f "$serial" ] && [ "$(tr -d '\n' < "$serial")" = "$device" ] || {
    printf 'certificate device ID differs from panel serial\n' >&2; return 1; }
  printf '%s\n' "$name"
}


usage() {
  printf '%s\n' 'Usage: unlock.sh [install|restore|verify] [options]' \
    '  --http-proxy URL            Set a local HTTP(S) network proxy for curl' \
    '  --progress / --no-progress  Force download progress on/off (default: auto)' \
    '  --skip-agent                Replace only the core, keep the current agent' \
    '  --prompt-unbind             Prompt before releasing an existing master binding' \
    '  --help                      Show this help'
}

SKIP_AGENT=0
PROMPT_UNBIND=0
MODE_SET=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    install|deploy|restore|verify)
      [ "$MODE_SET" = 0 ] || die "Specify only one operation"
      MODE="$1"; MODE_SET=1 ;;
    --http-proxy)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "--http-proxy requires a proxy URL"
      export XPACK_HTTP_PROXY="$2"; shift ;;
    --http-proxy=*) export XPACK_HTTP_PROXY="${1#*=}"; [ -n "$XPACK_HTTP_PROXY" ] || die "--http-proxy requires a proxy URL" ;;
    --progress) PROGRESS=on ;;
    --no-progress) PROGRESS=off ;;
    --skip-agent) SKIP_AGENT=1 ;;
    --prompt-unbind) PROMPT_UNBIND=1 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; die "Unknown installation argument" ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# 下载线路：开跑前探测一次，决定整轮是直连还是走加速镜像
#   · 直连 GitHub 能通（国外机器）→ 全程直连，不碰镜像
#   · 直连不通/超时（国内机器）  → 全程使用 GH_MIRROR 前缀
# 需要强制走加速：GH_MIRROR_FORCE=1 sudo -E bash unlock.sh install
# ---------------------------------------------------------------------------
GH_MIRROR="${GH_MIRROR:-https://ghfast.top/}"
MIRROR_PREFIX=""
ROUTE_READY=0
probe_route() {
  [ "$ROUTE_READY" = 0 ] || return 0
  ROUTE_READY=1
  local PROBE="https://raw.githubusercontent.com/$REPO/main/unlock.sh" STATUS=""
  local -a PROXY=()
  [ -z "${XPACK_HTTP_PROXY:-}" ] || PROXY=(--proxy "$XPACK_HTTP_PROXY")
  if [ -n "$BOOTSTRAP_PREFIX" ]; then
    MIRROR_PREFIX="$BOOTSTRAP_PREFIX"
    log "GitHub download route: $MIRROR_PREFIX (from the bootstrap URL)"
    return 0
  fi
  if [ -n "${GH_MIRROR_FORCE:-}" ]; then
    MIRROR_PREFIX="$GH_MIRROR"
    log "GitHub download route: $MIRROR_PREFIX (forced)"
    return 0
  fi
  STATUS="$(curl --proto '=http,https' --proto-redir '=http,https' --tlsv1.2 -sS -o /dev/null \
    --connect-timeout 4 --max-time 8 --write-out '%{http_code}' \
    "${PROXY[@]}" "$PROBE" 2>/dev/null || true)"
  if [ "$STATUS" = 200 ]; then
    log "GitHub download route: direct"
  else
    MIRROR_PREFIX="$GH_MIRROR"
    log "GitHub unreachable directly; every download goes through $MIRROR_PREFIX"
  fi
}
run_download() {
  local PART="$1" CANDIDATE="$2" PID STATUS=0 ELAPSED=0 SIZE=0 START NOW
  shift 2
  local -a BASE=(--proto '=http,https' --proto-redir '=http,https' --tlsv1.2 -fSL
                 --connect-timeout 10 --max-time "$DL_MAX_TIME"
                 --speed-limit "$STALL_BYTES" --speed-time "$STALL_SECONDS"
                 --retry 1 --retry-max-time 20)
  START="$(date +%s)"
  # 进度条保持在单行刷新（curl --progress-bar 自带 \r 回写），不额外打印心跳。
  if progress_bar_enabled; then
    curl "${BASE[@]}" --progress-bar "$@" -o "$PART" "$CANDIDATE" &
  else
    curl "${BASE[@]}" -s "$@" -o "$PART" "$CANDIDATE" 2> "$PART.log" &
  fi
  PID=$!
  wait "$PID" || STATUS=$?
  NOW="$(date +%s)"; ELAPSED=$((NOW - START)); [ "$ELAPSED" -gt 0 ] || ELAPSED=1
  SIZE="$(wc -c < "$PART" 2>/dev/null)" || SIZE=0
  if [ "$STATUS" = 0 ]; then
    printf '   ... %s bytes in %ss (%s B/s)\n' "${SIZE// /}" "$ELAPSED" "$(( ${SIZE// /} / ELAPSED ))" >&2
  else
    printf '!! transfer failed (curl exit %s) after %ss, %s bytes received\n' \
      "$STATUS" "$ELAPSED" "${SIZE// /}" >&2
  fi
  return "$STATUS"
}
run_download_silent() {
  # 工具脚本等小文件：完全静默，不打印进度条与完成信息。
  local PART="$1" CANDIDATE="$2" STATUS=0
  shift 2
  curl --proto '=http,https' --proto-redir '=http,https' --tlsv1.2 -fSL \
    --connect-timeout 10 --max-time "$DL_MAX_TIME" \
    --speed-limit "$STALL_BYTES" --speed-time "$STALL_SECONDS" \
    --retry 1 --retry-max-time 20 -s "$@" -o "$PART" "$CANDIDATE" 2> "$PART.log"
  STATUS=$?
  [ "$STATUS" = 0 ] || printf '!! transfer failed (curl exit %s): %s\n' "$STATUS" "${CANDIDATE##*/}" >&2
  return "$STATUS"
}
fetch() {
  local URL="$1" DEST="$2" SILENT="${3:-}" PREFIX CANDIDATE PART ERROR HOST ATTEMPT=0
  local -a ROUTES=("$URL") CURL_PROXY=()
  case "$URL" in
    https://github.com/*|https://raw.githubusercontent.com/*)
      # 加速网关不代理 api.github.com（会 403），API 请求始终直连
      probe_route
      if [ -n "$MIRROR_PREFIX" ]; then
        ROUTES=("$MIRROR_PREFIX$URL" "$URL")
      fi ;;
  esac
  [ -z "${XPACK_HTTP_PROXY:-}" ] || CURL_PROXY=(--proxy "$XPACK_HTTP_PROXY")
  for CANDIDATE in "${ROUTES[@]}"; do
    ATTEMPT=$((ATTEMPT + 1))
    PART="$(mktemp "$DEST.part.XXXXXX")"
    HOST="${CANDIDATE#*://}"; HOST="${HOST%%/*}"
    [ -n "$SILENT" ] || log "Downloading ${DEST##*/} from $HOST (route $ATTEMPT/${#ROUTES[@]})"
    if [ -n "$SILENT" ]; then
      run_download_silent "$PART" "$CANDIDATE" "${CURL_PROXY[@]}"
    else
      run_download "$PART" "$CANDIDATE" "${CURL_PROXY[@]}"
    fi
    if [ $? -eq 0 ]; then
      mv -f -- "$PART" "$DEST"
      return 0
    fi
    [ -n "$SILENT" ] || printf '!! Download route %s failed; trying next route\n' "$HOST" >&2
    rm -f -- "$PART" "$PART.log"
  done
  die "All download routes failed: ${DEST##*/}"
}
fetch_direct() {
  # 官方包不经过 GitHub 镜像；仅沿用代理。
  local URL="$1" DEST="$2" PART
  local -a CURL_PROXY=()
  [ -z "${XPACK_HTTP_PROXY:-}" ] || CURL_PROXY=(--proxy "$XPACK_HTTP_PROXY")
  PART="$(mktemp "$DEST.part.XXXXXX")"
  log "Downloading ${DEST##*/} from fit2cloud (direct)"
  run_download "$PART" "$URL" "${CURL_PROXY[@]}" || { rm -f -- "$PART" "$PART.log"; die "Download failed: ${DEST##*/}"; }
  mv -f -- "$PART" "$DEST"
}

# ---------------------------------------------------------------------------
# 版本检测 / Release 预检
# ---------------------------------------------------------------------------
detect_installed_version() {
  # 版本来源优先级：数据库 SystemVersion → 内核自报 → 1pctl 里的包版本。
  # 数据来源都可以用 shell 直接读，不需要 python。
  local version="" out uniq
  if [ -n "$SQLITE3_BIN" ] && [ -f "$PANEL_ROOT/db/core.db" ]; then
    version="$("$SQLITE3_BIN" -readonly "$PANEL_ROOT/db/core.db" \
      "select value from settings where key='SystemVersion' limit 1;" 2>/dev/null | head -1)"
    version="$(norm_version "$version")"
  fi
  if [ -z "$version" ] && [ -x "$CORE_BIN" ]; then
    out="$("$CORE_BIN" version 2>/dev/null </dev/null || true)"
    if [ -n "$out" ]; then
      uniq="$(printf '%s\n' "$out" \
        | grep -oE '(^|[^[:alnum:]_.])v?[0-9]+\.[0-9]+\.[0-9]+' \
        | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | sed 's/^\([0-9]\)/v\1/' | sort -u)"
      if [ "$(printf '%s\n' "$uniq" | grep -c .)" = 1 ]; then version="$uniq"; fi
    fi
  fi
  if [ -z "$version" ]; then version="$(ctl_version)"; fi
  if [ -z "$version" ]; then
    die "Installed panel version was not detected; no panel changes were made"
  fi
  printf '%s\n' "$version"
}

ctl_version() {
  # 已安装 1pctl 里写死了本包版本（ORIGINAL_VERSION=v2.4.1），升级后会跟着换。
  # 数据库里的 SystemVersion 要等官方内核迁移跑完才更新，升级瞬间还是旧值。
  [ -f "$PANEL_CTL" ] || return 0
  grep -m1 -oE 'ORIGINAL_VERSION=["'"'"']?v?[0-9]+\.[0-9]+\.[0-9]+' "$PANEL_CTL" 2>/dev/null \
    | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | sed 's/^[0-9]/v&/' || true
}

wait_for_version() {
  # 升级后数据库里的版本号由官方内核启动时迁移写入，这里等它追上（最多 60s）。
  local WANT="$1" GOT="" I=0
  while [ "$I" -lt 30 ]; do
    GOT="$(detect_installed_version 2>/dev/null || true)"
    [ "$GOT" = "$WANT" ] && { printf '%s\n' "$GOT"; return 0; }
    I=$((I + 1))
    sleep 1
  done
  printf '%s\n' "$GOT"
}

select_release() {
  # 选出最高稳定 Release，写出下载 URL 与版本号。
  # 先走 GitHub API；被限流/被网关拦（403）时退到 releases.atom，资产 URL 按约定拼。
  local SOURCE=api TAGS BEST TAG BASE OBJ DRAFT PRE
  if ! fetch "https://api.github.com/repos/$REPO/releases?per_page=100" "$RUN/releases.json" 1 2>/dev/null; then
    SOURCE=atom
    log "GitHub API unavailable; falling back to the releases feed"
    fetch "https://github.com/$REPO/releases.atom" "$RUN/releases.atom" 1 || \
      die "Cannot read the release list (API and atom feed both failed)"
  fi

  if [ "$SOURCE" = api ]; then
    # 一行一个 release 对象，逐对象取 tag/draft/prerelease（字符串内的括号不计）
    TAGS="$(tr -d '\n' < "$RUN/releases.json" | json_objects | while IFS= read -r OBJ; do
      TAG="$(printf '%s' "$OBJ" | grep -oE '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
      DRAFT="$(printf '%s' "$OBJ" | grep -oE '"draft":[[:space:]]*(true|false)' | head -1 | grep -oE '(true|false)$')"
      PRE="$(printf '%s' "$OBJ" | grep -oE '"prerelease":[[:space:]]*(true|false)' | head -1 | grep -oE '(true|false)$')"
      case "$TAG" in core-v[0-9]*.[0-9]*.[0-9]*) ;; *) continue ;; esac
      if [ "$DRAFT" = true ]; then continue; fi
      if [ "$PRE" = true ]; then continue; fi
      printf '%s\n' "$TAG"
    done)"
  else
    TAGS="$(grep -oE 'core-v[0-9]+\.[0-9]+\.[0-9]+' "$RUN/releases.atom" | sort -u)"
  fi

  TAGS="$(printf '%s\n' "$TAGS" | grep -E '^core-v[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)"
  [ -n "$TAGS" ] || die "No stable project release is published"
  BEST="$(printf '%s\n' "$TAGS" | sed 's/^core-//' | sort -V | tail -1)"
  TAG="core-$BEST"
  BASE="https://github.com/$REPO/releases/download/$TAG"

  printf '%s' "$BASE/manifest.json" > "$RUN/manifest.url"
  printf '%s' "$BASE/core-$PLATFORM" > "$RUN/core.url"
  printf '%s' "$BASE/core-$PLATFORM.orig" > "$RUN/orig.url"

  # 预构建的破解 Agent：API 里确认有这个资产才下载；atom 只能按约定拼。
  if [ "$SOURCE" = api ]; then
    OBJ="$(tr -d '\n' < "$RUN/releases.json" | json_objects | while IFS= read -r O; do
      case "$O" in *"\"tag_name\": \"$TAG\""*) printf '%s\n' "$O"; break ;; esac
    done)"
    for need in manifest.json "core-$PLATFORM" "core-$PLATFORM.orig"; do
      printf '%s' "$OBJ" | grep -q "\"name\": \"$need\"" || \
        die "Unsupported: latest Release $TAG has no verified assets for $PLATFORM"
    done
    if printf '%s' "$OBJ" | grep -q "\"name\": \"agent-$PLATFORM\""; then
      printf '%s' "$BASE/agent-$PLATFORM" > "$RUN/agent.url"
    else
      printf '1' > "$RUN/agent.missing"
    fi
  else
    printf '%s' "$BASE/agent-$PLATFORM" > "$RUN/agent.url"
  fi

  printf '%s' "$TAG" > "$RUN/release.tag"
  printf '%s' "$BEST" > "$RUN/selected.version"
  printf 'Release %s selected for %s\n' "$BEST" "$PLATFORM"
}

# ---------------------------------------------------------------------------
# Release manifest 校验（纯 shell；Release 资产由 CI 生成，结构固定）
# ---------------------------------------------------------------------------
manifest_check() {
  local m="$RUN/manifest.json" ver
  [ -s "$m" ] || die "Release manifest is empty"
  grep -Eq '"schema_version"[[:space:]]*:[[:space:]]*2' "$m" \
    || die "Expected an offline schema-2 release manifest"
  grep -Eq '"name"[[:space:]]*:[[:space:]]*"xpack-toolkit"' "$m" \
    || die "Unexpected manifest name"
  grep -Eq '"mode"[[:space:]]*:[[:space:]]*"offline"' "$m" \
    || die "Expected an offline release manifest"
  grep -q "\"$PLATFORM\": {" "$m" || die "Release has no verified core for $PLATFORM"
  ver="$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$m" | head -1)"
  if [ -n "$ver" ] && [ -f "$RUN/release.tag" ]; then
    [ "$(cat "$RUN/release.tag")" = "core-$ver" ] || die "Release tag/version mismatch"
  fi
  [ "$(manifest_field "$PLATFORM" os)" = linux ] || die "Invalid platform declaration"
  [ "$(manifest_field "$PLATFORM" arch)" = "${PLATFORM#linux-}" ] || die "Invalid platform declaration"
  [ "$(manifest_field "$PLATFORM" core_asset)" = "core-$PLATFORM" ] || die "Invalid platform declaration"
}

# ---------------------------------------------------------------------------
# 1pctl 配置值保真
# ---------------------------------------------------------------------------
# 官方发行包里的 /usr/local/bin/1pctl 是「占位符模板」：BASE_DIR=directory、
# ORIGINAL_PORT=port、ORIGINAL_ENTRANCE=entrance、ORIGINAL_USERNAME=username、
# ORIGINAL_PASSWORD=password。官方 installer 安装时会用 sed 把这些占位符替换成
# 用户真实配置。unlock.sh 升级时若直接覆盖 1pctl 而不回填，core 会去读
# directory/1panel/tmp/.secret，agent 会把端口解析成字符串 "port"，两者都以
# exit 2 崩溃。因此覆盖前先提取旧 1pctl 的配置值，覆盖后原样回填。
CTL_CONFIG_KEYS="BASE_DIR ORIGINAL_PORT ORIGINAL_USERNAME ORIGINAL_PASSWORD ORIGINAL_ENTRANCE LANGUAGE PANEL_EDITION"

extract_ctl_config() {
  local SRC="$1" OUT="$2" KEY VALUE
  [ -f "$SRC" ] || return 1
  : > "$OUT"
  while IFS='=' read -r KEY VALUE; do
    case " $CTL_CONFIG_KEYS " in
      *" $KEY "*) printf '%s=%s\n' "$KEY" "$VALUE" >> "$OUT" ;;
    esac
  done < "$SRC"
  [ -s "$OUT" ]
}

apply_ctl_config() {
  # 把旧 1pctl 里的配置值写回官方模板（占位符 directory/port/... 替换成真实值）。
  local SAVED="$1"
  [ -f "$SAVED" ] || return 0
  awk -v saved="$SAVED" '
    BEGIN {
      while ((getline line < saved) > 0) {
        eq = index(line, "=")
        if (eq > 1) kv[substr(line, 1, eq - 1)] = substr(line, eq + 1)
      }
    }
    match($0, /^[A-Z_][A-Z0-9_]*=/) {
      k = substr($0, 1, RLENGTH - 1)
      if (k in kv) { print k "=" kv[k]; next }
    }
    { print }
  ' "$PANEL_CTL" > "$PANEL_CTL.xpack-new" || { rm -f "$PANEL_CTL.xpack-new"; return 1; }
  cat "$PANEL_CTL.xpack-new" > "$PANEL_CTL"
  rm -f "$PANEL_CTL.xpack-new"
}

upgrade_1pctl() {
  local SRCDIR="$1" CTL_CONFIG
  [ -f "$SRCDIR/1pctl" ] || return 0
  CTL_CONFIG="$(mktemp "${TMPDIR:-/tmp}/xpack-ctl.XXXXXX")"
  if extract_ctl_config "$PANEL_CTL" "$CTL_CONFIG"; then
    backup_binary "$PANEL_CTL" ctl
    install -m 0755 "$SRCDIR/1pctl" "$PANEL_CTL"
    apply_ctl_config "$CTL_CONFIG"
  else
    log "Could not read config from existing 1pctl; keeping it unchanged"
  fi
  rm -f "$CTL_CONFIG"
}

# ---------------------------------------------------------------------------
# 3.1 官方 1Panel 升级（仅当 Release 版本较新时）
# ---------------------------------------------------------------------------
update_panel() {
  local VERSION="$1" TARBALL DEST SRCDIR
  TARBALL="$RUN/1panel-$VERSION-$PLATFORM.tar.gz"
  fetch_direct "$OFFICIAL_BASE/$VERSION/release/1panel-$VERSION-$PLATFORM.tar.gz" "$TARBALL"
  SRCDIR="$RUN/official-$VERSION"
  mkdir -p "$SRCDIR"
  tar xzf "$TARBALL" -C "$SRCDIR" --strip-components=1
  [ -f "$SRCDIR/1panel-core" ] && [ -f "$SRCDIR/1panel-agent" ] || die "Official package lacks binaries"

  log "Upgrading 1Panel $INSTALLED_VERSION -> $VERSION (official package)"
  systemctl stop "$CORE_SVC" 2>/dev/null || true
  systemctl stop "$AGENT_SVC" 2>/dev/null || true
  backup_binary "$CORE_BIN" core
  backup_binary "$AGENT_BIN" agent

  install -m 0755 "$SRCDIR/1panel-core" "$CORE_BIN"
  install -m 0755 "$SRCDIR/1panel-agent" "$AGENT_BIN"
  upgrade_1pctl "$SRCDIR"
  if [ -f "$SRCDIR/GeoIP.mmdb" ]; then
    mkdir -p "$PANEL_ROOT/geo"
    install -m 0644 "$SRCDIR/GeoIP.mmdb" "$PANEL_ROOT/geo/GeoIP.mmdb"
  fi
  if [ -d "$SRCDIR/lang" ]; then cp -r "$SRCDIR/lang" /usr/local/bin/; fi

  systemctl start "$CORE_SVC"
  systemctl is-active --quiet "$CORE_SVC"
  systemctl start "$AGENT_SVC" 2>/dev/null || true
  log "1Panel upgraded to $VERSION; database migrations completed"
}

backup_binary() {
  local SRC="$1" NAME="$2" SUM
  [ -f "$SRC" ] || return 0
  SUM="$(sha256sum "$SRC")"; SUM="${SUM%% *}"
  mkdir -p "$BACKUP"
  install -m 0755 "$SRC" "$BACKUP/1panel-$NAME.$SUM"
  install -m 0755 "$SRC" "$BACKUP/1panel-$NAME.previous"
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
PREFLIGHT="$(mktemp -d "${TMPDIR:-/tmp}/xpack-preflight.XXXXXX")"
trap 'rm -rf -- "$PREFLIGHT"' EXIT
mkdir -p "$PERSIST" "$BACKUP"

# restore 只用 shell 覆盖文件；install/verify 走 shell + coreutils + openssl。

if [ "$MODE" = restore ]; then
  CORE_ORIG="$BACKUP/1panel-core.previous"
  AGENT_ORIG="$BACKUP/1panel-agent.previous"
  [ -f "$CORE_ORIG" ] || die "Missing core rollback image: $CORE_ORIG"
  systemctl stop "$CORE_SVC" 2>/dev/null || true
  [ -f "$AGENT_ORIG" ] && systemctl stop "$AGENT_SVC" 2>/dev/null || true
  install -m 0755 "$CORE_ORIG" "$CORE_BIN"
  [ -f "$AGENT_ORIG" ] && install -m 0755 "$AGENT_ORIG" "$AGENT_BIN"
  CTL_ORIG="$BACKUP/1panel-ctl.previous"
  [ -f "$CTL_ORIG" ] && install -m 0755 "$CTL_ORIG" "$PANEL_CTL"
  systemctl start "$CORE_SVC"
  [ -f "$AGENT_ORIG" ] && { systemctl start "$AGENT_SVC"; systemctl is-active --quiet "$AGENT_SVC"; }
  systemctl is-active --quiet "$CORE_SVC"
  log "Restored previous 1Panel binaries (licenses in the database are untouched)"
  exit 0
fi

if [ "$MODE" = verify ]; then
  # 安装完成后下载内容已清理，这里重新选一次 Release 并比对 sha256 判断是否破解内核。
  RUN="$(mktemp -d "$PERSIST/run.XXXXXX")"
  log "$(select_release)"
  RELEASE_VERSION="$(<"$RUN/selected.version")"
  fetch "$(<"$RUN/manifest.url")" "$RUN/manifest.json"
  manifest_check
  WANT_SHA="$(manifest_field "$PLATFORM" sha256)"
  ORIG_SHA="$(manifest_field "$PLATFORM" orig_sha256)"
  GOT_SHA="$(sha256sum "$CORE_BIN" | awk '{print $1}')"
  if [ "$GOT_SHA" = "$WANT_SHA" ]; then
    log "Cracked kernel matches Release $RELEASE_VERSION ($(printf '%s' "$GOT_SHA" | cut -c1-16))"
  elif [ "$GOT_SHA" = "$ORIG_SHA" ]; then
    die "Cracked kernel not detected: $CORE_BIN is the official upstream binary of $RELEASE_VERSION"
  else
    log "Installed kernel differs from Release $RELEASE_VERSION (likely an older cracked build)"
  fi
  if [ -f "$PERSIST/license.status" ] && [ "$(<"$PERSIST/license.status")" != applied ]; then
    log "Components verified; license is pending import (no sqlite3 when it was installed)"
  elif ensure_sqlite3 && lic_db_ready "$XPACK_DB"; then
    LIC_NAME="$(lic_verify "$XPACK_DB" "$SERIAL_PATH")" || die "License readback failed"
    log "License bound to master node: $LIC_NAME"
  else
    log "sqlite3 not available; skipped license database readback"
  fi
  systemctl is-active --quiet "$CORE_SVC"
  rm -rf -- "$RUN"
  log "Cracked kernel verified on $CORE_BIN"
  exit 0
fi

# install / deploy
INSTALLED_VERSION="$(detect_installed_version)"
log "Installed panel $INSTALLED_VERSION / $PLATFORM"

RUN="$(mktemp -d "$PERSIST/run.XXXXXX")"
RELEASE_LINE="$(select_release)"
log "$RELEASE_LINE"
RELEASE_VERSION="$(<"$RUN/selected.version")"

# 下载 manifest（内核资产）并校验结构
fetch "$(<"$RUN/manifest.url")" "$RUN/manifest.json"
manifest_check

# 3.1 版本比较：Release 较新则先官方升级到一致版本
VERSION_STATE="$(compare_versions "$INSTALLED_VERSION" "$RELEASE_VERSION")"
if [ "$VERSION_STATE" = older ]; then
  die "Unsupported: project release is older than installed panel"
fi
if [ "$VERSION_STATE" = newer ]; then
  update_panel "$RELEASE_VERSION"
else
  log "Installed panel is already at Release version $RELEASE_VERSION; skip official upgrade"
fi

# 版本门禁：本地内核版本必须与 Release 一致，否则不做任何替换。
# 刚升级完时数据库里的 SystemVersion 还没被官方内核的迁移刷新，先等它追上；
# 等不到就看内核二进制自己报的版本（数据库下一轮启动会自己补上）。
INSTALLED_VERSION="$(detect_installed_version)"
if [ "$INSTALLED_VERSION" != "$RELEASE_VERSION" ]; then
  # 升级刚完成时数据库还是旧值：先看随包换掉的 1pctl，再等数据库迁移追上
  CTL_VERSION="$(ctl_version)"
  if [ "$CTL_VERSION" = "$RELEASE_VERSION" ]; then
    log "Version check passed on the installed 1pctl ($CTL_VERSION); database catches up on next start"
    INSTALLED_VERSION="$CTL_VERSION"
  else
    log "Waiting for the upgraded panel to report $RELEASE_VERSION (database migration)"
    INSTALLED_VERSION="$(wait_for_version "$RELEASE_VERSION")"
    [ "$INSTALLED_VERSION" = "$RELEASE_VERSION" ] || \
      die "Version mismatch (installed $INSTALLED_VERSION / 1pctl $CTL_VERSION / release $RELEASE_VERSION); nothing was replaced"
  fi
fi
log "Version check passed: panel $INSTALLED_VERSION == release $RELEASE_VERSION"

# 3.1 从 Release 下载破解内核并校验（sha256 + ELF 架构；Release 资产本身即破解产物）
fetch "$(<"$RUN/core.url")" "$RUN/core"
verify_asset "$RUN/core" "$(manifest_field "$PLATFORM" sha256)" "$ARCH" "cracked core"

# Agent：用 Release 里已经打好补丁的二进制，装机器只校验 + 替换。
# Release 缺这个架构的 Agent 资产时只换内核，不在本机做任何二进制改写。
NEED_AGENT=0
if [ "$SKIP_AGENT" != 1 ] && [ -f "$AGENT_BIN" ]; then NEED_AGENT=1; fi
AGENT_SOURCE=""
if [ "$NEED_AGENT" = 1 ]; then
  if [ -f "$RUN/agent.url" ] && fetch "$(<"$RUN/agent.url")" "$RUN/agent"; then
    verify_asset "$RUN/agent" "$(manifest_field "$PLATFORM" agent_sha256)" "$ARCH" "patched agent" \
      || die "Downloaded patched agent failed verification"
    AGENT_SOURCE="$RUN/agent"
    log "Using prebuilt patched $ARCH agent from Release"
  else
    NEED_AGENT=0
    log "No downloadable $PLATFORM agent; core replaced, agent left untouched"
  fi
fi

# 备份并替换内核
backup_binary "$CORE_BIN" core
[ -z "$AGENT_SOURCE" ] || backup_binary "$AGENT_BIN" agent
systemctl stop "$CORE_SVC"
[ -z "$AGENT_SOURCE" ] || systemctl stop "$AGENT_SVC"
install -m 0755 "$RUN/core" "$CORE_BIN"
[ -z "$AGENT_SOURCE" ] || install -m 0755 "$AGENT_SOURCE" "$AGENT_BIN"

# 3.2 内网本地生成企业版授权（999 节点 / 永久 / 离线），写库并绑定主节点。
#     证书文件与走库逻辑都是 shell（openssl + sqlite3），不依赖 python。
LICENSE_OUT="$PERSIST/license.txt"
export LIC_EDITION="${EDITION:-enterprise}"
LIC_EXPIRES="${EXPIRES:-9999-12-31}"
LIC_NODES="${NODES:-999}"
LIC_ASSIGNEE="${ASSIGNEE:-YG}"
LIC_ISSUER="${ISSUER:-lxware}"
LIC_SMS="${SMS_TOTAL:-100000}"
LIC_VERSION="${VERSION_CONSTRAINT:-all}"
LIC_DB="$XPACK_DB"
LIC_SERIAL="$SERIAL_PATH"
LIC_DEVICE="$(lic_machine_id "$SERIAL_PATH")"
if [ "${LIC_EXPIRES%%-*}" -ge 9999 ] 2>/dev/null; then
  LIC_PRODUCT_PRO=0
else
  LIC_PRODUCT_PRO="$(date -d "$LIC_EXPIRES" +%s 2>/dev/null || printf '0')"
fi
LIC_JSON_TEXT="$(lic_json "$LIC_EDITION" "$LIC_EXPIRES" "$LIC_NODES" "$LIC_ASSIGNEE" \
  "$LIC_ISSUER" "$LIC_SMS" "$LIC_VERSION" "$LIC_DEVICE")"
LIC_NAME="$(lic_json_field "$LIC_JSON_TEXT" licenseName)"
LIC_TEXT="$(lic_encode "$LIC_JSON_TEXT")"
printf '%s\n' "$LIC_TEXT" > "$LICENSE_OUT"
log "License generated: $LIC_NAME (nodes $LIC_NODES, expires $LIC_EXPIRES, offline)"

if ensure_sqlite3 && lic_db_ready "$XPACK_DB"; then
  if [ "$PROMPT_UNBIND" = 1 ] && [ -t 0 ]; then
    BOUND_NAMES="$(lic_bound_names "$XPACK_DB")"
    if [ -n "$BOUND_NAMES" ]; then
      printf '主节点已绑定证书「%s」，是否先解绑再绑定新证书？[Y/n] ' "$BOUND_NAMES"
      read -r ANSWER
      case "$ANSWER" in
        n|N|no|NO|0) die "existing master binding left in place; unbind it first or re-run without prompt" ;;
      esac
    fi
  fi
  lic_apply || die "Failed to write the license into $XPACK_DB"
  printf 'applied\n' > "$PERSIST/license.status"
  log "License written to $XPACK_DB and bound to the master node (third-party certificates kept)"
else
  printf 'pending\n' > "$PERSIST/license.status"
  log "sqlite3 CLI or a licenses table is missing; certificate kept at $LICENSE_OUT"
  log "The cracked kernel skips every license check, so Pro features work without the row"
fi

# 重启并回读验证
if [ -n "$AGENT_SOURCE" ]; then
  systemctl start "$AGENT_SVC"
  systemctl is-active --quiet "$AGENT_SVC"
fi
systemctl start "$CORE_SVC"
systemctl is-active --quiet "$CORE_SVC"
if ensure_sqlite3 && lic_db_ready "$XPACK_DB"; then
  LIC_NAME="$(lic_verify "$XPACK_DB" "$SERIAL_PATH")" || die "License readback failed"
  log "License verified: $LIC_NAME bound to the master node"
fi

# 静默清理下载的临时内容（release 资产与工具脚本），退出前不残留运行目录。
rm -rf -- "$RUN" "$PREFLIGHT" 2>/dev/null || true

log "Kernel replaced (all license checks removed)"
log "Third-party certificates preserved; any prior master binding was released first"
log "Downloaded artifacts cleaned up"
log "Rollback: bash unlock.sh restore (previous images: $BACKUP)"
