# xpack-toolkit

面板 v2 的 X-Pack 工具包。**唯一面向用户的一键入口是 [unlock.sh](<unlock.sh>)**；
[tools/](<tools/>) 中的 Python 文件是内部构建或运行时 helper，不是另一套用户安装脚本。
使用现有公开根证书与真实签名的离线许可证，保留证书链、RSA 验签、许可 JSON 解析、
数据库字段加密和真实主节点绑定。

- 已验证版本：`v2.3.2`，统一 Release tag 为 `core-v2.3.2`，不按架构拆分。
- 官方 Linux 包有六种架构：`amd64`、`arm64`、`armv7`、`ppc64le`、`s390x`、`riscv64`。
  **当前 core 工具的 C7 适配及构建验证仅覆盖 `amd64` / `arm64`**；其它四种不会作为可用资产发布或宣称支持。
  Agent 独立补丁器当前只验证 `v2.3.2 amd64`，其它架构不据此宣称 agent 补丁支持。
- 用户安装依赖：Python 3（标准库）、openssl、curl、systemctl；维护者发布另需 Git 和 GitHub CLI `gh`。
- 新签发默认：企业版、999 节点、到期日 2099-12-31、离线；已有或预签许可证保留原期限与节点额度。

CentOS、Ubuntu、Debian、麒麟、统信等发行版使用 Linux core；资产按 CPU 架构区分，
不是每个发行版分别构建同架构二进制。具体发行版仍需满足面板官方安装条件，当前发布验证范围仅为上述两种 CPU 架构。

## 原理与签名输入

默认内核只有 P1/P2/C7 三处等长补丁：P1/P2 替换内置根证书指纹，C7 保留启动时的根证书行。
公开 Release 固定 `mode="offline"`、`remote_base=""`，保留官方 HK/CN 地址；真实验证链保持原样：

```text
读取并解密 core_settings 根证书 → 核对内置 SHA-256 指纹
→ x509.Verify 证书链 → rsa.VerifyPKCS1v15 完整许可签名
→ 解析许可 JSON / 解密 DB 元数据 → 真实设备、期限、离线标志、节点额度检查
```

安装会按面板格式加密写入根证书四行与许可显示字段，保存完整签名文件，按数据库中的真实主节点绑定并回读验证。
999 是许可证额度，不代表创建 999 个节点。旧恒成功补丁、伪造状态或空快照不作为成功依据。

安装前至少具备以下一种签名输入：

1. `LICENSE_FILE`：匹配现有根证书、当前设备且未到期的完整离线签名文件。
2. 本地 `SIGN_KEY`：与根证书匹配的私钥；默认位置为 `STATE/license.key`，用于本机签发。
3. 现有面板数据库保存的完整、有效且匹配根证书的离线签名许可证：导出复用并修复加密字段与节点绑定。

**只有公开证书、旧明文字段或显示“企业版”不等于有效签名输入。**
新机器缺少上述输入时会在停止服务、替换内核之前返回失败。脚本和 Release 始终不下载或打包私钥。

## 一键安装、校验与回滚

提供预签文件安装指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo env VERSION=v2.3.2 LICENSE_FILE=/secure/license.txt bash -s -- install
```

或下载唯一入口，使用本地私钥：

```bash
curl -fsSL -O https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh
sudo env VERSION=v2.3.2 SIGN_KEY=/secure/license.key bash unlock.sh install
sudo bash unlock.sh verify
sudo bash unlock.sh restore
```

已有完整有效离线签名许可证的机器，可重复执行安装修复升级后的内核与字段，保留原期限、节点额度和签名内容：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo env VERSION=v2.3.2 bash -s -- install
```

`NODES` / `EXPIRES` / `ASSIGNEE` 只影响使用本地私钥的新签发。
`NO_APPLY=1` 仍要求验签有效，只保留签名文件供手动导入，不代表已经激活；`SKIP_AGENT=1` 跳过 agent 修改。

安装器先从**同一个版本 tag**下载 [manifest.json](<https://github.com/keweiya/xpack-toolkit/releases/download/core-v2.3.2/manifest.json>) 与 [runtime.tar.gz](<https://github.com/keweiya/xpack-toolkit/releases/download/core-v2.3.2/runtime.tar.gz>)，
按 manifest 校验 runtime 的 SHA-256、大小与公开文件白名单后才运行 helper；之后仅下载当前平台的两个精确名称资产，
校验内核 SHA-256、官方原件 SHA-256、平台与根证书指纹。只访问 GitHub Release 返回的这些 exact download URLs；
不尝试长短名称、不探测其它架构 tag、不用 404 fallback，也不从 raw 分别读取工具或证书。
首次 curl 只获取入口本身；Python runtime 和证书均来自同 tag 的校验包。

流程：Release / runtime / 平台 / 根指纹验证 → 签名预检查 → 内核资产 SHA 校验 → 从已校验官方原件重建三补丁离线内核
→ 备份 → 停服务安装 → 加密写入根证书和许可 → 真实主节点绑定 → 重启回读验证。
失败返回非零；`verify` / `restore` 优先使用本机已缓存 runtime，无需重新联网下载。
回滚先校验备份官方原件，再恢复 core、已备份 agent 与根证书四行。
默认备份目录 `/opt/1panel/crack/backup`，运行缓存 `/opt/1panel/unlock`；可用 `BACKUP` / `UNLOCK_WORK` 覆盖。

## 统一 Release 资产契约

`core-v2.3.2` 只有一份共享 manifest 和 runtime，当前默认发布六个资产：

```text
manifest.json
runtime.tar.gz
core-linux-amd64
core-linux-amd64.orig
core-linux-arm64
core-linux-arm64.orig
```

[manifest.json](<https://github.com/keweiya/xpack-toolkit/releases/download/core-v2.3.2/manifest.json>) schema 为：

```json
{
  "schema_version": 2,
  "name": "xpack-toolkit",
  "version": "v2.3.2",
  "mode": "offline",
  "remote_base": "",
  "root_fingerprint": "cb8cc410354dbbda7b542c952a8c8ffb47a0f3d886c7e7273c89cb7a44156030",
  "built_at": "UTC timestamp",
  "platforms": {
    "linux-amd64": {
      "arch": "amd64", "os": "linux", "size": 85651618,
      "sha256": "patched core SHA-256", "orig_sha256": "official core SHA-256",
      "core_asset": "core-linux-amd64", "orig_asset": "core-linux-amd64.orig", "patches": 3
    },
    "linux-arm64": {
      "arch": "arm64", "os": "linux", "size": 82772130,
      "sha256": "patched core SHA-256", "orig_sha256": "official core SHA-256",
      "core_asset": "core-linux-arm64", "orig_asset": "core-linux-arm64.orig", "patches": 3
    }
  },
  "runtime": {"asset": "runtime.tar.gz", "sha256": "runtime SHA-256", "size": 12345}
}
```

示例中的 SHA-256 / UTC / runtime 大小为说明占位，实际值由构建生成；可选 `source_commit` 记录 `git rev-parse HEAD`。
平台字段只能对应实际成功构建并验证的架构，不从官方包清单自动扩大支持范围。

[runtime.tar.gz](<https://github.com/keweiya/xpack-toolkit/releases/download/core-v2.3.2/runtime.tar.gz>) 仅含以下八个普通文件，无私钥、缓存、构建 helper 或其它脚本：

```text
tools/gen_license.py
tools/patch_core.py
tools/patch_agent.py
tools/cert_store.py
tools/aes128.py
tools/gosym.py
tools/official_rootcert.json
state/license.crt
```

## 维护者内部构建与发布

[release.py](<tools/release.py>) 是内部 Python 标准库 CLI，替代旧构建 shell helper；普通用户仍只运行 [unlock.sh](<unlock.sh>)。

```bash
python3 tools/release.py --version v2.3.2 --arches amd64,arm64 --build-only
# 默认输出 build/release-v2.3.2；不传 --publish 同样只构建。
python3 tools/release.py --version v2.3.2 --cache-dir build/dl --output build/release-v2.3.2 --build-only
# 维护者已登录 gh 时才执行；默认两种已验证架构。
python3 tools/release.py --version v2.3.2 --publish --repo keweiya/xpack-toolkit
```

`--repo` 可省略，依次读取 `GITHUB_REPOSITORY`、GitHub origin；`--build-only` 与 `--publish` 互斥。
版本可写 `2.3.2`，统一规范为 `v2.3.2`；`--arches` 是逗号分隔的唯一列表，仅接受已验证的两种架构。
不读取环境变量启用远端改写，也不覆盖现有公钥。

每次从官方获取该版本的 `checksums.txt`，严格要求对应 tarball 有且只有一个有效 SHA-256 条目，
支持 `filename` / `*filename` / `./filename` / `*./filename`；缺失、重复、格式错误、下载失败或哈希不符都返回非零。
默认复用现有 `build/dl/` 的官方 tar，但每次仍对照新取官方 SHA 校验。
缓存校验失败会保留文件，不删除用户文件；每个架构在独立临时 workdir 从官方原件重新打补丁并验证。
全部架构与 runtime 成功后才替换指定输出资产；不清空缓存或其它既有构建文件。

发布也先完成所有构建和校验，再用 `gh release view` 检查**统一版本 tag**；
只有确认 HTTP 404 且仓库可读才视为尚不存在，其它网络、权限、认证错误直接终止。
已存在时执行 `gh release delete --yes` 保留 Git tag，再一次 `gh release create --latest` 上传当前构建的全部资产；
没有 matrix 并发删除，也不使用 upload `--clobber` 遗留旧资产。
构建失败发生在删除旧 Release 之前；旧架构 tag 的一次性迁移由维护者单独处理，CLI 不跨 tag 删除。

本机安装这份 Release 目录仍使用唯一入口：

```bash
sudo env VERSION=v2.3.2 ARTIFACT_DIR="$PWD/build/release-v2.3.2" LICENSE_FILE=/secure/license.txt bash unlock.sh install
```

## CI

[build.yml](<.github/workflows/build.yml>) 只提供手动 `workflow_dispatch`，默认版本 `v2.3.2`。
只有一个 `buildrelease` job 和一个发布步骤：

```bash
python3 tools/release.py --version "$VERSION" --publish --repo "$GITHUB_REPOSITORY"
```

默认构建 `amd64,arm64`，串行完成所有构建后发布一个版本 Release。
需要仓库 `contents: write` 与 `GITHUB_TOKEN`，公钥固定使用已跟踪的 [license.crt](<state/license.crt>)；
无私钥 secret、根证书替换、远端授权地址、R2 或多架构 matrix 配置。

## 公开文件与升级

| 文件 | 内部用途 |
| --- | --- |
| [unlock.sh](<unlock.sh>) | 唯一一键安装入口，签名预检、安装、校验和回滚 |
| [release.py](<tools/release.py>) | 官方 SHA 校验、独立多架构构建、共享 manifest/runtime 与统一 Release 管理 |
| [patch_core.py](<tools/patch_core.py>) | 当前 core P1/P2/C7 两架构适配，保留真实验签 |
| [patch_agent.py](<tools/patch_agent.py>) | 独立 agent 补丁器，当前只验证 v2.3.2 amd64 |
| [gen_license.py](<tools/gen_license.py>) | 内部签发、验签、完整许可证导入导出及真实节点绑定 |
| [cert_store.py](<tools/cert_store.py>) | 根证书四行加密写入、回读和还原 |
| [aes128.py](<tools/aes128.py>) / [gosym.py](<tools/gosym.py>) | 标准库 AES-128 与 Go 符号解析 |
| [official_rootcert.json](<tools/official_rootcert.json>) | 官方根证书字段回滚参考 |
| [license.crt](<state/license.crt>) | 现有公开信任锚，构建和校验只需公钥 |

- [公开根证书](<state/license.crt>) 的 SHA-256 指纹前缀 `cb8cc410` 保持不变，避免破坏已有安装。
- 历史提交曾公开私钥；当前不跟踪或分发私钥不代表历史泄露消失，这套 CA 是公开信任锚。
  新签发依赖本地匹配私钥或签发方提供的完整预签许可证。
- 独立 CA 应离线保管私钥，同时更换公钥、重建内核、重新签发导入，不直接覆盖已有安装根证书。
- 面板升级会覆盖内核；已有完整有效签名许可证可重复应用，旧伪造字段仍需补齐真正签名输入。
