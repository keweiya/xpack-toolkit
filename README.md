# xpack-toolkit

面板 v2 的 X-Pack 工具包：使用本站根证书和**真实签名的离线许可证**，
保留证书链、RSA 验签、许可 JSON 解析、DB 字段加密与真实主节点绑定。
附带安装、校验、回滚、本地构建和 GitHub Actions 构建。

- 新签发默认值：企业版、999 节点、到期日 2099-12-31、离线；预签或已有许可证保留原期限 / 节点数
- 架构：amd64 / arm64
- 依赖：Python 3（纯标准库）、openssl、curl、systemctl；本地发布另需 GitHub CLI `gh`

## 原理

默认内核只包含 **P1/P2/C7 三处补丁**：P1/P2 替换内置根证书指纹，C7 保留启动时的根证书行。
默认 `remote_base=""`、`mode="offline"`，官方 HK/CN 地址保持或恢复原值。
构建时显式提供非空远端地址才增加 P3/P4；安装脚本会从哈希校验后的官方原件重新构建离线内核。

本地校验链保留原样：

```text
读取 core_settings 根证书并解密 → 核对内置 SHA-256 指纹
→ x509.Verify 证书链 → rsa.VerifyPKCS1v15 验证完整许可签名
→ 解析许可 JSON / 解密 DB 许可元数据 → 校验设备 / 期限 / 离线标志 / 节点额度
```

安装将根证书 4 行和许可证显示字段按面板实际格式加密入库，
保存完整签名文件，按数据库中的**真实主节点**建立绑定并回读验证。
999 是许可证额度，不代表凭空创建 999 个节点。
旧版恒成功、跳过校验、伪造节点或空快照回退描述已移除；旧补丁内核应从官方原件重建。

## 目录

| 文件 | 作用 |
| --- | --- |
| [unlock.sh](<unlock.sh>) | 签名 / 产物预检查、安装、加密入库、真实节点绑定与校验、回滚 |
| [patch_core.py](<tools/patch_core.py>) | 默认 P1/P2/C7；显式远端参数才启用 P3/P4，保留验签 |
| [patch_agent.py](<tools/patch_agent.py>) | v2.3.2 amd64 已匹配偏移 / 字节校验；其它版本或架构须另行适配 |
| [cert_store.py](<tools/cert_store.py>) | 加密写入 / 回读 / 还原根证书 4 行 |
| [gen_license.py](<tools/gen_license.py>) | 签发、验签、导入 / 导出完整签名文件、加密字段与真实节点绑定 |
| [deploy.sh](<tools/deploy.sh>) | 统一调用本地 unlock 的 install / restore / verify / cert |
| [build.sh](<tools/build.sh>) | 官方校验和严格验证、本机构建、可选发布 Release |
| [aes128.py](<tools/aes128.py>) | 纯标准库 AES-128，DB 存储字段加解密 |
| [gosym.py](<tools/gosym.py>) | Go 符号表解析 |
| [build.yml](<.github/workflows/build.yml>) | 手动构建并发布 Release，可选 R2 |
| [license.crt](<state/license.crt>) | 公开信任锚；构建 / 校验只需公钥证书，私钥本地保管 |

公共仓库使用短名工具和根目录 `state/`，没有默认 `web/state`。

## 一键安装

代码、公钥证书和 Release 资产免 token 下载；脚本**始终不下载私钥**。
安装前至少具备以下一项：

1. `LICENSE_FILE`：匹配当前根证书、设备 ID、未到期的完整离线签名文件。
2. 本机匹配根证书的 `SIGN_KEY`：默认 `STATE/license.key`，用于本地签发。
3. 现有面板 DB 保存着匹配当前根证书且验签有效的完整离线许可证：脚本导出后重复应用，修复字段加密与节点绑定。

**新机器裸跑一次 curl，没有本地私钥、预签文件或可复用的完整签名许可证时，
会在停止服务 / 替换内核前失败。** 公钥证书、旧明文字段或仅显示“企业版”的状态不是签名输入。

提供预签文件的一次安装：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo env LICENSE_FILE=/secure/license.txt bash -s -- install
```

或先下载检查，再使用本地签名材料运行：

```bash
curl -fsSL -O https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh
sudo env SIGN_KEY=/secure/license.key bash unlock.sh install
```

现有机器已有上述完整有效许可证时，可直接重复安装；期限 / 节点额度保持原样：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash -s -- install
```

已克隆仓库时使用本地工具，环境变量示例：

```bash
sudo env STATE="$PWD/state" SIGN_KEY=/secure/license.key VERSION=v2.3.2 \
  NODES=999 EXPIRES=2099-12-31 ASSIGNEE=YG bash unlock.sh install
sudo env LICENSE_FILE=/secure/license.txt NO_APPLY=1 bash unlock.sh install  # 保留已验签文件供手动导入
sudo env LICENSE_FILE=/secure/license.txt SKIP_AGENT=1 bash unlock.sh install
```

`NODES` / `EXPIRES` / `ASSIGNEE` 仅在本地私钥新签发时生效；预签和 DB 导出的文件保留其原始签名内容。
`NO_APPLY=1` 仍需有效签名输入，仅跳过许可证入库，不代表已激活。

流程：签名预检查 → Release 的 `sha256` / `orig_sha256` / 架构 / 根指纹校验
→ 官方原件重建离线内核并检查 agent → 备份已验证官方原件
→ 停服务 / 安装 → 加密写入根证书与许可证 → 绑定真实主节点 → 重启、回读验证。
失败返回非零，旧状态、空快照或在线请求日志不是成功依据。

## 校验与回滚

```bash
sudo bash unlock.sh verify
sudo bash unlock.sh restore
```

回滚先校验备份为官方原件，再恢复内核、已备份 agent 与根证书 4 行。
默认备份目录 `/opt/1panel/crack/backup`，运行产物与已验签文件留在 `/opt/1panel/unlock`；
可用 `BACKUP` / `UNLOCK_WORK` 覆盖。还原官方根证书后，本站许可证不再属于官方信任链。

## 本地构建

```bash
./tools/build.sh --version v2.3.2 --arch amd64 --no-publish
./tools/build.sh --version v2.3.2 --arch arm64 --no-publish
./tools/build.sh --version v2.3.2 --arch all   # 构建两架构并发布，需已登录 gh
```

固定使用 [公开根证书](<state/license.crt>)，构建无需私钥。
官方校验和下载失败、条目缺失 / 重复 / 格式错误、哈希不匹配均立即失败；
支持 SHA-256 清单中的 `filename` / `*filename` / `./filename`。
默认三处补丁 / `mode=offline`；非空 `--remote-base URL` 或显式 `REMOTE_BASE` 才启用远端五处补丁。

本地产物如下，多架构顺序构建时最终保留最后一个架构；本机部署应显式构建本机架构：

```text
build/core
build/manifest.json
build/orig/core.orig
build/core.manifest.json   # 补丁器逐项清单，公共 manifest 的 patches 由其 patches 列表计数
```

手动部署，不用 Release：

```bash
sudo env LICENSE_FILE=/secure/license.txt ./tools/deploy.sh install
sudo env SIGN_KEY=/secure/license.key ./tools/deploy.sh cert
sudo ./tools/deploy.sh verify
sudo ./tools/deploy.sh restore
```

[deploy.sh](<tools/deploy.sh>) 只包装 [unlock.sh](<unlock.sh>)，导出 `STATE=$ROOT/state`、`LOCAL=1`、`ARTIFACT_DIR=$ROOT/build`。
`deploy` 是 `install` 的兼容别名；证书参数使用环境变量，不再使用旧位置参数。

## CI 构建

Actions → `build` → Run workflow，选版本 / 架构，`base` 默认留空。
版本规范为 `v` 前缀，tag 兼容 `core-v2.3.2-amd64` / `core-v2.3.2-arm64`。
公共 Release 资产固定为：

- `core`：补丁内核
- `manifest.json`：`sha256` / `orig_sha256` / `root_fingerprint` / `patches` / `mode` / `remote_base`
- `core.orig`：官方原件，重建 / 回滚用

`SIGN_CRT` 实际为 [state/license.crt](<state/license.crt>)；可选 secret `ROOT_CERT_PEM` 覆盖 CI 公钥证书，私钥不进入 CI。
variable `PANEL_VERSION` 可提供默认版本。R2 配置全部省略时只发布 Release，不安装 rclone；
启用 R2 需完整配置 secrets `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` 和 variable `R2_BUCKET`，缺项报错。

## 单独签发 / 导出

```bash
sudo env STATE="$PWD/state" SIGN_KEY=/secure/license.key ./tools/deploy.sh cert
# 已安装完整、有效的本站签名许可证可导出：
sudo env STATE="$PWD/state" python3 tools/gen_license.py \
  --export-existing /secure/existing-license.txt --db /opt/1panel/db/xpack.db
```

许可证为 `base64(JSON)-base64(RSA 签名)-base64(证书)` 三段式文件：首段是许可 JSON，
RSA 签名覆盖解码后的 JSON 字节，首段本身不加密。DB 许可元数据另按面板 AES 存储格式加密。
签发器 / 导入器保留完整签名文件，校验设备、期限、离线标志和额度。
离线安装要求真实 `offline=true`，并保留本地验签，不是把请求或校验函数改成恒成功。

## 根证书与升级

- 现有 [公开根证书](<state/license.crt>)（SHA-256 指纹前缀 `cb8cc410`）保持不变，避免破坏已有升级。
  历史提交曾公开私钥；删除当前私钥跟踪不代表历史泄露消失，这套 CA 是公开信任锚，不是保密身份凭据。
- 新脚本只下载公开代码、证书和 Release 资产。新签发需本地匹配私钥，或签发方提供预签文件；不要依赖公开下载私钥。
- 自建独立 CA 应离线保管私钥，同步更换公钥证书、重建内核、重新签发和导入；不要直接覆盖现有安装根证书。
- 面板升级会覆盖内核。现有完整有效签名许可证可重复应用；若 DB 只留有旧伪造字段，升级时仍需提供签名输入。
