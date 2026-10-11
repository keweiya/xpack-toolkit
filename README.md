# xpack-toolkit

面板 v2 的 X-Pack 解锁工具包：**只换授权方**（把授权服务器与根证书换成自己的），
官方授权流程照跑，其余一律不改。附带一键脚本、本地构建脚本和 GitHub Actions 构建。

- 目标：企业版 + 999 节点 + 永久 + 离线授权（默认值，可用参数覆盖）
- 架构：amd64 / arm64
- 依赖：Python 3（纯标准库）、openssl、systemctl

## 原理

面板导入许可证时走官方代码：

```
loadRootCertFromStore(host)   从 core_settings 读 LicenseRootCert{HK,CN}
checkRootCertFingerprint      该 PEM 的 sha256 vs 内置常量
x509.Verify(第 3 段叶子证书, [根证书])
rsa.VerifyPKCS1v15(叶子公钥, sha256(第 1 段解码字节), 第 2 段签名)
```

所以只要做两件事，官方校验就会**真实通过**（内容解析、字段落库、状态、节点绑定全部走官方代码，没有任何伪造）：

1. 把内核里内置的根证书指纹 / 授权服务器地址换成自己的（5 处等长改写，见 `tools/patch_core.py`）
2. 把 `core_settings` 的 4 行根证书写成本仓库的 `state/license.crt`

## 目录

| 文件 | 作用 |
| --- | --- |
| `unlock.sh` | **一键安装**：下载 Release 内核 → 安装 → 写根证书 → 放行 agent → 写授权 |
| `tools/patch_core.py` | 内核补丁器（P1/P2 根证书指纹、P3/P4 授权服务器地址、C7 保住根证书行） |
| `tools/patch_agent.py` | agent 放行 `isXpack` 门（多节点用；v2.3.2 amd64 硬编码偏移） |
| `tools/cert_store.py` | 把根证书写进 / 还原出 `core_settings` 的 4 行 |
| `tools/gen_license.py` | 生成授权证书；`--apply` 直接写入面板并重启 |
| `tools/make_ca.sh` | 生成 / 复用根证书（信任锚） |
| `tools/build.sh` | 本机构建补丁内核并发布 Release |
| `tools/aes128.py` | 纯标准库 AES-128（`core_settings` 存储值加解密用） |
| `tools/gosym.py` | Go 符号表解析（补丁器跨版本定位用） |
| `.github/workflows/build.yml` | CI：手动触发 → 下载官方包 → 打补丁 → 发布 Release |
| `state/license.crt` / `state/license.key` | 信任锚：根证书 + 私钥（**一键脚本靠它在本机签发授权**） |

## 一键安装

公开仓库，免 token：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash
```

或者先看再跑：

```bash
curl -fsSL -O https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh
sudo bash unlock.sh
```

已克隆仓库时直接本地跑（会用仓库里的 `tools/` 与 `state/`）：

```bash
sudo bash unlock.sh
```

可调参数（环境变量）：

```bash
sudo VERSION=v2.3.2 NODES=999 EXPIRES=2099-12-31 ASSIGNEE=YG bash unlock.sh
sudo NO_APPLY=1   bash unlock.sh    # 只装内核 + 证书，授权自己手动导入
sudo SKIP_AGENT=1 bash unlock.sh    # 不处理 agent
```

脚本做的事：检测架构 → 取该架构最新 Release → 校验 `sha256` 与 `root_fingerprint`
→ 备份并替换内核 → 写根证书 4 行 → 重启 → 放行 agent → 生成企业版永久离线授权并写入面板。

## 离线化：删除在线验证 + 定时验证

授权链路原本依赖 `1p-cert.0rz.li`。只要有一次出网失败，`updateStatus` 就拿不到授权内容，
紧接着 `license_snapshot.RefreshWithLog` 用**空快照覆盖**启动时建好的快照，
`GET /api/v2/core/licenses/status` 于是永远返回空 —— 面板显示「社区版」。

内核补丁把这件两件事从二进制里摘掉，授权完全本地生效：

| 补丁 | 目标 | 效果 |
| --- | --- | --- |
| `P5a/P5b` | `xpack/utils/license_snapshot.Refresh` | `bind_node_id` 解析失败/为 0 时回退本地节点 1，快照不再为空 |
| `P6` | `xpack/cron/jobs.(*LicenseCheck).Run` | 删除每日 0:23 的定时授权校验任务 |
| `P7` | `xpack/utils/license_helper.Report` | 删除向授权服务器上报 |
| `P8` | `xpack/utils/license_helper.CheckVersion` | 删除在线版本校验 |
| `P9` | `xpack/utils/alert.SyncSmsCountAsync` | 删除在线短信计数同步 |
| `P10` | `xpack/utils/license_helper.handleRequest` | 切断唯一出网出口（所有授权服务器 HTTP 请求） |

补丁按 Go 符号名定位（`how="symbol"`），换版本或换架构时自动重定位，不依赖固化偏移。
`P5a/P5b` 用 `Refresh` 函数体内的指令特征定位（amd64：`test rbx,rbx` + `test rax,rax`；
arm64：`cbnz x1` + `cbz x0`），两种架构都不依赖固化偏移。
arm64 的补丁字节单独维护（`ARM64_PATCHES`）—— AArch64 的 `ret`/`nop`/`mov xN,xzr`
与 x86 完全不同，直接套用 amd64 字节会把指令流写坏。
`CheckInLocal` 与解密逻辑**不做短路** —— 否则字段会被二次加密写成乱码。

验证（应看不到任何 `alert response failed` / `sync alert count` 日志）：

```bash
journalctl -u <product>-core --since "1 min ago" | grep -i xpack
```

## 回滚

```bash
sudo bash unlock.sh restore
```

把内核、agent、`core_settings` 的 4 行全部还原成官方原件。备份目录：`/opt/<product>/backup`。

## 本地构建内核

```bash
sudo ./tools/make_ca.sh                       # 1. 生成 / 复用根证书（已存在则不覆盖）
sudo ./tools/build.sh --no-publish            # 2. 构建 amd64 + arm64，产物在 build/
sudo ./tools/build.sh --arch amd64            #    只构建一个架构
sudo ./tools/build.sh                         # 3. 构建并发布到当前仓库的 Release
```

产物：`build/core`、`build/manifest.json`、`build/orig/core.orig`。

手动部署（不用 Release）：

```bash
cp build/orig/core.orig build/orig/core.orig   # 官方原件
sudo ./tools/deploy.sh deploy                  # 装内核 + 写根证书 + 放行 agent
sudo ./tools/deploy.sh cert                    # 生成一份可导入的授权文本
sudo ./tools/deploy.sh verify                  # 查看当前补丁状态
```

## CI 构建

Actions → `build` → Run workflow，选版本 / 架构 / 授权服务器基地址。
产物发布为 Release `core-<版本>-<架构>`，资产：

- `core` —— 补丁内核
- `manifest.json` —— `sha256` / `orig_sha256` / `root_fingerprint` / `remote_base`
- `core.orig` —— 官方原件（回滚用）

可选 Secrets / Variables：`ROOT_CERT_PEM`（不配则用仓库里的 `state/license.crt`）、
`R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` + `R2_BUCKET`（上传到 Cloudflare R2，可选）、
`PANEL_VERSION`（默认版本）。

## 单独生成授权

```bash
python3 tools/gen_license.py --edition enterprise --nodes 999 --offline \
    --expires 2099-12-31 --assignee YG --out license.txt     # 只生成
python3 tools/gen_license.py --edition enterprise --nodes 999 --offline --apply   # 直接写入面板
```

授权格式：`base64(JSON)-base64(RSA 签名)-base64(证书)`。
`--offline`（默认）的永久版只在本地验签、不回连；`--no-offline` 的期限会定期回连授权服务器。

## 注意

- `state/license.crt` + `state/license.key` 是**信任锚**：换了它，所有已部署的补丁内核全部失效
  （指纹对不上），必须重新构建内核并重新写根证书。请把 `state/` 纳入备份。
- 本仓库是公开的，根证书私钥随之公开 —— 任何拿到本仓库的人都能为这套内核签发授权。
  如需收紧：把 `state/` 移出仓库，改走 `secrets.ROOT_CERT_PEM`，授权改由 Release 预签。
- 面板升级会覆盖内核，升级后重跑一次 `unlock.sh` 即可。
- 只在本机使用；请自行确认你对该机器与软件的使用权。
