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

**Release 来源仓库由同一条命令决定**：脚本启动时扫 `/proc` 找还在跑的 `curl`，从 `unlock.sh` 地址反推 `OWNER/REPO`，所以 `curl <自己的 raw 地址> | sudo bash` 会优先用**自己仓库的 Release**。

要让这个推断成立，脚本本身必须**大于 64 KB**（Linux 管道默认容量）：`curl … | sudo bash` 里 bash 要等 curl 送出第一批字节才开始执行，如果整个脚本能一次塞进管道缓冲，curl 会在脚本刚跑起来时就退出，`/proc` 里再看就只剩 0 个 curl（实测确认）。把文件撑过 64 KB 后，curl 会阻塞在管道上等 bash 读完，检测窗口就稳定存在——`unlock.sh` 末尾那段注释块就是干这个的，**不要删**（`tests/test_unlock.py` 里有下限断言）。

脚本仍会打印一行，直接看它就知道用的是谁的：

```
== Release source: NonOT7/xpack-toolkit (detected from the bootstrap URL)   # 抓到了
== Release source: NonOT7/xpack-toolkit (from REPO)                        # 你显式指定了
== Release source: keweiya/xpack-toolkit (REPO_DEFAULT; 拿不到 curl 命令行)  # 回落
```

第三种只会出现在「脚本先存成文件再跑」（没有 curl 可读）的情况下，此时用的是 `REPO_DEFAULT`，所以 **fork 仍然要把 `REPO_DEFAULT` 改成自己**（见下）。

## Fork 之后怎么用

一键脚本**不要写死仓库名**，也不要指望 fork 出来的 Release 会自动被别人的命令用上：

| 场景 | 行为 |
| --- | --- |
| 别人 `curl` 你的上游地址 | 用**上游**的 Release（`REPO_DEFAULT`）+ 上游的构建产物 |
| 你在**自己的 fork** 里跑 Actions 发出 `core-vX.Y.Z` | 产物只落在**你自己的 Releases**，上游脚本不会去拉 |
| 你 `curl` **自己的** raw 地址 | 自动推断出 `你的用户名/xpack-toolkit`，全程用自己的 Release、自己的 `sqlite3mini` |

> **README 不会跟着 fork 自动改名。** fork 出来的仓库里，上面那两条安装命令仍然写着 `keweiya/xpack-toolkit`——照着 README 敲的人，用的还是上游产物。脚本的自动推断只在「你敲的地址属于你自己」时才生效，所以 fork 后第一件事是把 README 里的地址换掉。

在自己 fork 里发一版：

0. 先把 README 和 `unlock.sh` 里的仓库名换成自己（**两处都要改**，`README` 与 `REPO_DEFAULT` 不一致时单测会直接变红）：

```bash
sed -i "s#keweiya/xpack-toolkit#<你的用户名>/xpack-toolkit#g" README.md unlock.sh
grep -rn "keweiya/xpack-toolkit" README.md unlock.sh   # 应该没有输出
```

   `REPO_DEFAULT` 为什么**必改**：地址推断是尽力而为——`curl … | sudo bash` 里 curl 传完就退出，扫不到就回落到 `REPO_DEFAULT`。改成自己的仓库名后，无论推断成功与否都不会装到上游产物；反之只改 README、不改 `REPO_DEFAULT`，一旦推断失败就会静默装成上游版本。

1. fork 后在 **Actions** 页点「I understand my workflows, go ahead and enable them」（fork 默认禁用工作流）；
2. **Scheduled workflows 在 fork 里默认不启用**，要自动跟上游就走手动 `workflow_dispatch`；
3. `upstream-watch` → `build.yml` 全绿后，Release 发到 `你的用户名/xpack-toolkit`（`build.yml` 里用 `$GITHUB_REPOSITORY`，不需要改代码、不需要配 secret）；
4. 装机器上执行：

```bash
curl -fsSL https://raw.githubusercontent.com/<你的用户名>/xpack-toolkit/main/unlock.sh | sudo bash
```

显式指定来源（先存文件再跑、或想临时切仓库时用）：

```bash
curl -fsSL https://raw.githubusercontent.com/<你的用户名>/xpack-toolkit/main/unlock.sh -o unlock.sh
sudo env REPO=<你的用户名>/xpack-toolkit bash unlock.sh install
```

> `sudo REPO=... bash` 不成立：sudo 不解析 `VAR=value` 形式的环境变量，要用 `sudo env VAR=value bash` 或先 `export` 再 `sudo -E bash`。

自建 Release 必须与上游**同名同结构**才能被脚本识别：tag 形如 `core-vX.Y.Z`，资产含 `manifest.json`、`core-linux-<arch>`、`core-linux-<arch>.orig`，有 `agent-linux-<arch>` 才会替换 Agent——这些都由 `build.yml` 自动产出。

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

成功退出前把脚本自己产生的东西全删掉，只留面板自身的文件：

| 路径 | 处理 |
| --- | --- |
| `$PANEL_ROOT/unlock/run.*` | 删除（Release 资产：core / agent / manifest） |
| `$PANEL_ROOT/unlock/tools/sqlite3mini` | 删除（内置静态 sqlite3） |
| `$PANEL_ROOT/unlock/runtime.*` | 删除（旧版本遗留的运行目录） |
| `$PANEL_ROOT/unlock/license.txt` | 删除（生成的证书；授权已写进 `xpack.db`） |
| `$PANEL_ROOT/unlock/license.status` | 删除（`applied` / `pending` 标记） |
| `$PANEL_ROOT/unlock/` | 空了就 `rmdir`，不留空壳 |
| `$PANEL_ROOT/db/xpack.db.pre-license` | 删除（写库前的 licenses 表备份） |
| `$PANEL_ROOT/crack/backup/` | **默认删除**（旧内核/Agent/1pctl 备份）；`--keep-backup` 保留 |

跑完 `$PANEL_ROOT` 下只剩面板自己的 `db/`、`log/`、`apps/` 等目录，脚本痕迹为零。

**不删的东西**：面板自身的 `1panel-core` / `1panel-agent` / `1pctl` / `db/*.db` / `serial`，以及任何不是本脚本产生的文件（比如 `/usr/local/bin/1panel-kvm`、历史手工破解留下的 `*.bak-*`）。

删掉备份后 `bash unlock.sh restore` 会改从 fit2cloud 重下官方包覆盖回去，所以回滚能力不受影响。想省一次下载就先跑 `install --keep-backup`。

`verify` 模式同样清理：临时下载的内置 sqlite3、证书副本用完即删；授权状态直接从 `xpack.db` 回读。

## 选项

```bash
sudo bash unlock.sh install --prompt-unbind    # 解绑旧证书前交互确认
sudo bash unlock.sh install --skip-agent       # 只换内核，Agent 保持原样
sudo bash unlock.sh verify                     # 回读校验破解内核与已绑定授权
sudo bash unlock.sh restore                    # 回滚到官方内核（有备份用备份，没有就重下官方包）
sudo bash unlock.sh install --keep-backup      # 保留旧二进制，restore 优先用本地镜像
```

`restore` 的两条路径：

- **有本地备份**（上次装的时候带了 `--keep-backup`）→ 直接用 `$PANEL_ROOT/crack/backup` 里的原件覆盖回去，快且不联网。
- **没有备份**（默认安装会删掉）→ 按当前版本从 `resource.fit2cloud.com` 重新下载官方包，装回 `1panel-core` / `1panel-agent` / `1pctl`（含 `GeoIP.mmdb`、`lang`），效果等同官方重装。版本取 `1pctl` 里的 `ORIGINAL_VERSION`，取不到可用 `VERSION=v2.4.1` 指定。

两条路径都会在结束时清理临时目录与备份（`--keep-backup` 可保留），`licenses` 表里的证书不动。

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

arm64 不写死指令偏移，改成结构化解码：先从 `IsXpack()` 里解出 `isXpack` 全局字节的地址（`adrp` + `ldrb` 的页 + 页内偏移），再在 `initXpack` / `InitLicenseInfo` / `syncNodeInfo` 里找写这个地址的 `strb`，回溯出 `edition` 字段的读法，最后把这几处 `ldrb` 全换成 `mov wN,#1`（入口另加两个返回桩）。因为地址和字段都是现场解出来的，v2.3.x、v2.4.x、v2.5.0 共用同一份代码，上游再发新版也不用来回改表。

amd64 的代码模式表允许一个站点挂多组候选 `((orig, patch), ...)`：官方换编译器后同一段逻辑可能落到别的寄存器上（v2.5.0 就把 A2/A4 的 `rdx` 换成了 `rax`），候选按顺序试、唯一命中者胜出，补丁字节跟着命中的那组候选走，所以同一份表能同时适配 v2.4.x 与 v2.5.0，不需要按版本分叉。

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

### 版本差异（v2.4.x → v2.5.0）

| 项目 | 变化 | 对破解流程的影响 |
| --- | --- | --- |
| 内核门控 | C1–C8 八个符号名与函数体形状不变；v2.5.0 内核 8 个站点全部 `--verify` 直接命中 | 内核侧零改动 |
| Agent `isXpack` 布局 | `xpack/utils/edition` 结构体里 `isXpack` 仍在 `+0x98`，3 写 7 读的关系不变 | 站点数量不变，仍靠符号 + 代码模式定位 |
| Agent 寄存器分配 | `initXpack` 里取值寄存器从 `rdx` 换成 `rax`：`movzbl 0x98(%rdx)` → `movzbl 0x98(%rax)`（A4 写入点）、`cmpb $0,0x98(%rdx)` → `cmpb $0,0x98(%rax)`（A2 守卫锚点） | 表里给 A2/A4 各挂 `rdx`、`rax` 两组候选，按顺序匹配，两个版本共用一份代码 |
| Agent 守卫形态 | v2.5.0 的 A7 不再有独立分支（条件跳转在 A6 那条读指令之后 16 字节内），`A7_ANCHOR` 落空 | 走「找不到就不打」的可选路径，最终站点数 amd64 8 个、arm64 7 个 |

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
5. **接口冒烟**（`tools/smoke_test.py`，需 root/sudo：容器内面板以 root 建库，`db` 目录 0700，冒烟直接使用 Release 里发布的那两个二进制）——**只在 Docker 容器里跑**，绝不碰宿主机的 1Panel，`amd64` / `arm64` 各跑一遍（arm64 走 qemu 模拟）：启动面板 → 登录 → 自制证书上传（官方内核此处失败、破解内核通过）→ 落库绑定 → `licenses/master/status` 为 `Bound`、节点 `isXpack=true` → 专业版接口放行。冒烟镜像构建**不碰 Ubuntu 源**：宿主机已有的 tzdata 与根证书直接 COPY 进镜像（基础镜像自带 `procps`），只有宿主机缺这两样时才回落到 apt，且先试 Azure 内网镜像再试公共源——`apt-get update` 曾在 runner 的构建网络里整段 `exit 100`，把这条门禁卡在跟被测内核无关的环节上。
6. **发布**——前 5 步全绿才执行 `release.py --publish`，原子替换同名 Release。

`build.yml` 是唯一一条发布流水线，既能手动触发（`workflow_dispatch`，版本号由人填），也被 `upstream-watch.yml` 通过 `uses:` 复用（`workflow_call`），两边跑的是完全相同的门禁步骤。

## 当前支持

- 仓库当前最高稳定版本 `v2.4.1`；机器版本高于它时提前退出。
- 内核：`amd64 / x86_64`、`arm64 / aarch64`。
- Agent 重建：`amd64` / `arm64`，两个架构各自一套指令模式，都在 Docker 里冒烟验证过。
- 所有架构放在同一 Release，始终选最高稳定版本；不回退、不降级机器。

## 安装失败

按终端错误检查后，重跑同一条命令即可。备份与运行记录默认保存在 `/opt/1panel/crack/backup` 与 `/opt/1panel/unlock`。

### 明明有新版，却装成旧版本

先看开跑后那行 `== Release source: …`，它写着本次到底用了谁的 Release：

| 输出 | 含义 | 处理 |
| --- | --- | --- |
| `… (from REPO)` | 你显式指定了仓库 | 自己确认 `REPO=` 有没有写错 |
| `… (detected from the bootstrap URL)` | 从抓取地址推断成功 | 正常情况下这就是对的 |
| `… (REPO_DEFAULT; 拿不到 curl 命令行)` | 推断没抓到，用了脚本内默认仓库 | 见下 |

出现第三种、且你用的是 fork：说明脚本回落到了 `REPO_DEFAULT`（上游），所以装的是上游版本。两种改法，任选其一：

```bash
# ① 临时：显式指定仓库（sudo 不解析 VAR=value，必须用 env）
curl -fsSL https://raw.githubusercontent.com/<你>/xpack-toolkit/main/unlock.sh \
  | sudo env REPO=<你>/xpack-toolkit bash

# ② 永久：在 fork 里把默认仓库改成自己（README 与 unlock.sh 一起改，单测会校验一致性）
sed -i "s#keweiya/xpack-toolkit#<你>/xpack-toolkit#g" README.md unlock.sh
```

顺带确认 fork 那边真的发出了目标版本：`gh release list -R <你>/xpack-toolkit`，且该 tag 不是 draft / prerelease（脚本只认正式版）。
