# xpack-toolkit

1Panel v2 内网本地破解内核一键安装 / 更新工具。已有安装直接重跑同一条命令即可，无需手动卸载。

## 一键安装 / 更新

国外服务器：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash
```

国内服务器（走 ghfast.top 加速镜像）：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash
```

下载线路由**你敲的那条命令**决定，脚本不再额外探测：

- 命令里套了加速前缀（上面那条）→ 脚本启动时从还在跑的 `curl` 命令行里读出前缀，**整轮所有下载都用它，不探测官方直连**
- 命令是官方直连（国外机器）→ 探一次 `raw.githubusercontent.com`（4 秒连接 / 8 秒总超时）：通了全程直连；不通则全程走 `GH_MIRROR`（默认 `https://ghfast.top/`）
- 先存成文件再跑（没有 curl 命令行可读）→ 走「官方直连」那一支
- 需要强制加速：`GH_MIRROR_FORCE=1 sudo -E bash unlock.sh install`；要换前缀：`GH_MIRROR=https://…/`

## 运行依赖

目标机只需要 `bash` + coreutils + `openssl`（1Panel 宿主机默认都有）：**不装 python，也不需要装 sqlite3**。

| 环节 | 实现 |
| --- | --- |
| 版本检测 / 版本比较 | shell 读 `core.db`（拿到 SQLite 执行器时）、`core version`、1pctl 的 `ORIGINAL_VERSION`，`sort -V` 比较 |
| Release 选择 | shell + awk 解析 GitHub API JSON（字符串内括号不计的对象切分），原子回退到 atom feed |
| 资产校验 | `sha256sum` + `od` 读 ELF 魔数与 `e_machine` |
| manifest 校验 | `awk` 按平台块提取字段 |
| 1pctl 配置回填 | `awk` 键值替换 |
| 授权证书 | `openssl enc -aes-128-cbc` 加密字段；写 `licenses` 表优先用系统 `sqlite3`，没有就下载仓库内置的静态单文件 `tools/bin/sqlite3mini-linux-amd64`（1.5 MB，源码 `tools/sqlite3mini.c`，脚本按 `SQLITE3_SHA_amd64` 校验） |

内置执行器的字段编码与 `tools/gen_license.py` 完全一致，两种实现可以互读对方的库（回归测试里双向校验）。

重建内置二进制（改了 `tools/sqlite3mini.c` 后）：

```bash
gcc -Os -static -I sqlite-amalgamation-<ver> tools/sqlite3mini.c \
    sqlite-amalgamation-<ver>/sqlite3.c -lm -o tools/bin/sqlite3mini-linux-amd64
strip --strip-all tools/bin/sqlite3mini-linux-amd64
sha256sum tools/bin/sqlite3mini-linux-amd64   # 写回 unlock.sh 的 SQLITE3_SHA_amd64
```

arm64 的 sha 目前留空：arm64 机器若没有系统 sqlite3，则只生成证书文件、不写库（破解内核没有授权门控，专业版功能不受影响）。需要时按上面命令交叉编译后填上 `SQLITE3_SHA_arm64`。

`tools/*.py` 只用于 CI 打补丁与本地回归验证，不参与安装流程。

脚本自动完成：

1. **版本检测与升级**：读取宿主机 1Panel 版本与仓库最高稳定 Release；若 Release 版本较新，先通过官方安装包把宿主机 1Panel 升级到与 Release 一致（数据库迁移随官方内核启动自动完成）。
2. **版本门禁 + 直接替换**：先比对本地面板版本与 Release 版本，不一致就先按官方包升级到一致；升级后仍不一致则**一个文件都不替换**直接退出。内核和 Agent 都是 Release 里**预构建好的破解产物**，装机器只做「校验 sha256 + ELF 架构 → 覆盖」，目标机上不做任何二进制改写；Release 缺该架构 Agent 资产时只换内核。授权证书在装机器上由 shell 现场生成（`openssl` + `sqlite3`），不再下发任何脚本工具。
3. **本地生成授权证书**：生成企业版授权（999 节点、永久有效、离线），直接写入 `licenses` 表并绑定主节点。**本工具之前生成的证书会删除重做（子节点绑定自动迁移）**；第三方/官方证书一律保留，若主节点已绑定其它证书则先解除旧绑定。

破解内核已**移除全部授权检查**：授权中间件放行、本地签名/根证书校验恒通过、节点额度校验恒通过、授权上报/解绑不回连服务器。因此**不需要宿主机额外签发/生成任何授权证书，也不需要签名私钥**。

### Release 资产用途

| 资产 | 谁在用 | 说明 |
| --- | --- | --- |
| `core-linux-<arch>` | 安装脚本 | 已移除全部授权检查的内核，校验 sha256/架构后直接替换 |
| `agent-linux-<arch>` | 安装脚本 | 已打好 X-Pack 补丁的 Agent，校验后直接替换 |
| `core-linux-<arch>.orig` / `agent-linux-<arch>.orig` | 回滚、诊断 | 官方原件，`restore` 回滚时使用 |
| `runtime.tar.gz` | 离线复用 / 审计 | 发布时刻的工具与证书快照；安装流程当前从 `main` 分支拉工具，该资产留作离线备用 |
| `manifest.json` | 安装脚本 | 各资产的 sha256/尺寸/补丁数，安装前逐项核对 |

> 装机器拿到的就是 CI 里跑过双架构冒烟的那两个二进制，安装期不再做任何二进制改写（`--skip-agent` 可只换内核）。

## 安装成功后的清理

成功退出前会删掉这一轮下载与生成的全部中间产物，只留证书：

| 路径 | 处理 |
| --- | --- |
| `$PANEL_ROOT/unlock/run.*` | 删除（Release 资产：core / agent / manifest） |
| `$PANEL_ROOT/unlock/tools/sqlite3mini` | 删除（内置静态 sqlite3） |
| `$PANEL_ROOT/unlock/runtime.*` | 删除（旧版本遗留的运行目录） |
| `$PANEL_ROOT/db/xpack.db.pre-license` | 删除（写库前的 licenses 表备份） |
| `$PANEL_ROOT/crack/backup/` | **默认删除**（旧内核/Agent/1pctl 备份）；`--keep-backup` 保留 |
| `$PANEL_ROOT/unlock/license.txt` | 保留（生成的证书，`verify` 会回读） |
| `$PANEL_ROOT/unlock/license.status` | 保留（`applied` / `pending` 状态） |

删掉备份后 `bash unlock.sh restore` 就没有回滚镜像了，脚本会明确报错并提示用 `--keep-backup` 重装。想留退路就先跑 `install --keep-backup`。

`verify` 模式同样会清理：它临时下载的内置 sqlite3 用完即删。

## 选项

```bash
sudo bash unlock.sh install --prompt-unbind    # 解绑旧证书前交互确认
sudo bash unlock.sh install --skip-agent       # 只换内核，Agent 保持原样
sudo bash unlock.sh verify                     # 回读校验破解内核与已绑定授权
sudo bash unlock.sh restore                    # 回滚到替换前的官方内核（需 --keep-backup 留下的镜像）
sudo bash unlock.sh install --keep-backup      # 保留旧二进制，之后可 restore
```

- `--http-proxy URL`：设置本机网络代理（探测与下载都走它）。
- `GH_MIRROR`：自定义加速前缀，默认 `https://ghfast.top/`；`GH_MIRROR_FORCE=1` 跳过探测强制使用。
- `curl` 仍沿用 `http_proxy` / `https_proxy`。

## 内核破解方式

`tools/patch_core.py` 按 Go 符号名（pclntab）唯一定位并改写这些授权门函数，全部改成「恒成功」返回桩，与 1Panel 版本 / 架构解耦：

| 补丁 | 目标函数 | 效果 |
| --- | --- | --- |
| C1 | `middleware.checkLicense` | 授权中间件放行 |
| C2 | `middleware.checkLicenseSyncFresh` | 同步新鲜度恒 true |
| C3 | `license_helper.CheckInLocal` | 本地签名/根证书校验恒通过 |
| C4 | `license_helper.checkRootCertFingerprint` | 内置根指纹比对恒通过 |
| C5 | `license_helper.EnsureFreeNodeBindAllowed` | 节点额度校验恒通过 |
| C6 | `xpack/helper.(*licenseHelper).BindFree` | 免费节点绑定恒成功 |
| C7 | `license_helper.Report` | 跳过授权上报 |
| C8 | `license_helper.Unbind` | 跳过远端解绑 |

授权文件仍保持官方三段式结构，供面板 `getLicenseContent` 正常解析、字段落库与界面展示；签名段仅在检测到本机 `SIGN_KEY` 时才做真实 RSA 签名，没有私钥就用占位符（内核不校验）。

`tools/patch_agent.py` 处理 `1panel-agent` 的 X-Pack 开关（包级 `isXpack` 字节 + 授权告警）：同样先按 pclntab 符号名定位函数，再在函数体内按代码模式唯一定位指令，8 处全部等长覆盖、不改二进制体积。

| 补丁 | 位置 | 效果 |
| --- | --- | --- |
| A1 | `(*multiNodeHelper).IsXpack` | 入口返回 true |
| A2 | `xpack.initXpack` 授权分支 | 去掉 `if !isXpack` 跳过逻辑 |
| A3 | `xpack.initXpack` 日志取值 | 日志显示 isXpack=true |
| A4 | `xpack.initXpack` 写入点 | isXpack 恒写 1 |
| A5 | `common_xpack.InitLicenseInfo` 写入点 | isXpack 恒写 1 |
| A6 | `app/service.syncNodeInfo` 写入点 | isXpack 恒写 1 |
| A7 | `app/service.syncNodeInfo` 分支 | 恒走 InitXpack，永不 ResetXpack（**可选**：v2.4.1 起守卫直接判 A6 改写的那条读指令，改完即生效，找不到就不打） |
| A8 | `alert_xpack.GetLicenseAlert` | 入口返回 nil，不再弹授权告警 |

arm64 不写死指令偏移，改成结构化解码：先从 `IsXpack()` 里解出 `isXpack` 全局字节的地址（`adrp` + `ldrb` 的页 + 页内偏移），再在 `initXpack` / `InitLicenseInfo` / `syncNodeInfo` 里找写这个地址的 `strb`，回溯出 `edition` 字段的读法，最后把这几处 `ldrb` 全换成 `mov wN,#1`（入口另加两个返回桩）。因为地址和字段都是现场解出来的，v2.3.x 和 v2.4.x 共用同一份代码，上游再发新版也不用来回改表。

校验已经打过补丁的 Agent 时要带 `--orig` 指向官方原件：入口桩打完之后 `IsXpack()` 里已经没有 `adrp`/`ldrb` 可解，需要拿原件推站点偏移。

### 版本差异（v2.3.2 → v2.4.1）

| 项目 | 变化 | 对破解流程的影响 |
| --- | --- | --- |
| 内核门控 | 8 个函数符号名、参数完全一致 | 定位方式零改动，重跑 `--verify` 即可确认 |
| 内核桩 | C1 `checkLicense` 入口字节按版本自适应（`c3` / `b80100000031db31c9c3` / `31c031dbc3`） | 脚本自动挑能放下的那一种，不写死 |
| Agent | 授权开关变成 `xpack/utils/edition.isXpack` 包级字节，3 写 7 读 | 旧的写死偏移失效，改成「符号 + 代码模式」定位（A1–A8） |
| Agent 架构 | arm64 代码与 amd64 完全不同（`ldrb/strb`、`tbz`） | arm64 靠结构化解码定位，两架构共用一套逻辑，站点数随版本 7–8 个自适应 |
| 授权接口 | `/api/v2/core/enterprise/*` 消失，统一到 `/api/v2/core/licenses/*` | 冒烟测试改打 `/licenses/master/status`、`/licenses/search`、`/xpack/nodes/search` |
| 登录协议 | `POST /api/v2/core/auth/login`，口令为 `b64(RSA(aeskey)):b64(iv):b64(AES-CBC(pwd))` 三段式，进户口令必须走 `EntranceCode` 头（JSON 字段被忽略） | `smoke_test.py` 内置这套加密，首次登录无验证码可直接自动化 |
| 证书校验 | 官方内核在 `POST /licenses/upload` 处直接 `verify certificate failed` | 破解内核越过该校验；生产安装仍走「写库 + 绑定」路径，不依赖 upload 的三段式格式 |

## 发布架构

内核补丁与脚本工具**分层发布**，日常改动不需要重新发版：

- **内核资产**（`core` / `core.orig` / `agent.orig` / `manifest.json`）——只随 1Panel 版本升级重新发版一次，之后保持不变。
- **脚本工具**（`unlock.sh` / `tools/*.py` / `state/license.crt`）——直接从 `main` 分支下载，push 到 `main` 即对下次安装生效。

因此改证书显示、授权默认值、安装流程时，只需提交到 `main`，用户重跑同一条命令即可，无需重新构建 Release。

## 自动跟进官方新版本

`.github/workflows/upstream-watch.yml` 每天定时盯上游，全流程无人值守；**任何一步不过就不会有 Release**：

1. **检测**（`tools/upstream_watch.py`）——读官方版本指针 `resource.fit2cloud.com/1panel/package/v2/stable/latest`，与本仓库已发布的 `core-vX.Y.Z` 比大小；官方包还没传全就记 `pending`，下一轮再试，不报红。
2. **单测**——`python3 -m unittest discover -s tests`。
3. **构建**（`tools/release.py --build-only`）——按 SHA 校验官方包后逐平台打补丁，不发布。
4. **资产自检**（`tools/verify_release.py`）——manifest 大小/哈希与实际文件一致、内核 8/8 补丁已打、Agent 原件能完整复现 8/8、等长覆盖不改体积。
5. **接口冒烟**（`tools/smoke_test.py`，需 root/sudo：容器内面板以 root 建库，`db` 目录 0700，冒烟直接使用 Release 里发布的那两个二进制）——**只在 Docker 容器里跑**，绝不碰宿主机的 1Panel，`amd64` / `arm64` 各跑一遍（arm64 走 qemu 模拟）：启动面板 → 登录 → 自制证书上传（官方内核此处失败、破解内核通过）→ 落库绑定 → `licenses/master/status` 为 `Bound`、节点 `isXpack=true` → 专业版接口放行。
6. **发布**——前 5 步全绿才执行 `release.py --publish`，原子替换同名 Release。

`build.yml` 是唯一一条发布流水线，既能手动触发（`workflow_dispatch`，版本号由人填），也被 `upstream-watch.yml` 通过 `uses:` 复用（`workflow_call`），两边跑的是完全相同的门禁步骤。

## 当前支持

- 仓库当前最高稳定版本 `v2.4.1`；机器版本高于它时提前退出。
- 内核：`amd64 / x86_64`、`arm64 / aarch64`。
- Agent 重建：`amd64` / `arm64`，两个架构各自一套指令模式，都在 Docker 里冒烟验证过。
- 所有架构放在同一 Release，始终选最高稳定版本；不回退、不降级机器。

## 安装失败

按终端错误检查后，重跑同一条命令即可。备份与运行记录默认保存在 `/opt/1panel/crack/backup` 与 `/opt/1panel/unlock`。
