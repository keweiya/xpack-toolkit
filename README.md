# xpack-toolkit

1Panel v2 一键解锁安装工具。已有安装直接重新运行同一条命令，无需手动卸载。

## 一键安装 / 更新

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash
```

脚本自动完成：

1. 获取仓库最高稳定版本，读取机器版本，先按主版本、次版本、补丁版本比较。
2. 仓库版本大于等于机器版本才继续；低于机器版本或最新资产缺少当前架构，立即退出。
3. 重新替换旧工具内核；amd64 的 Agent 从可信官方原件重建，不再依赖旧 Agent 或旧备份。
4. 保留其它来源的证书和许可证，留档旧验证根，再启用项目验证根；有效项目许可证自动导入绑定（`--replace-foreign` 时改为归档并直接替换第三方许可证）。
5. 重启服务并回读验证。网站、应用、面板数据和有效许可证均保留。

版本校验通过前仅临时下载和只读检测。兼容其它来源旧内核：保存旧二进制和许可证验证根，再替换仓库组件。网站 HTTPS、系统证书及第三方许可证签名原文均保留；导入项目许可证时仅解除旧许可证的主节点绑定，不删除旧许可证。不卸载整个 1Panel。

## GitHub 镜像选择

镜像地址内置在脚本中：`https://ghfast.top/`、`https://gh-proxy.com/`、`https://ghproxy.net/`。安装时询问是否使用镜像，回车默认直连，没有交互终端也默认直连，未选择时不会自动启用。选择使用后，并发测量有效 GitHub API 响应的首字节延迟，用最低者下载内核和全部相关 GitHub 文件，失效时只切换到其它测速合格的镜像。

跳过询问可在上面命令末尾加参数：`--use-mirror` 或 `--mirror auto` 启用内置镜像并自动选最低延迟；`--mirror https://ghfast.top/`（也支持 `--mirror=URL`）只用指定镜像；`--no-mirror` 只用直连；`--http-proxy http://127.0.0.1:7890` 设置本机网络代理。例如：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash -s -- --use-mirror
```

兼容环境变量 `GH_PROXY=auto/镜像地址/direct`（命令行优先）与 `GH_MIRRORS`（仅改测速候选，不会自行启用）；curl 沿用 `http_proxy` / `https_proxy`，经 sudo 运行需显式传入。入口脚本本身无法直连时，可自行给原始 URL 加镜像前缀，例如 `curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash`；入口选择与脚本内下载模式相互独立。所有下载仍做格式、版本与 SHA-256 校验。

## 下载进度与卡死保护

每个文件下载都会先打印“文件名 + 声明大小 + 实际路由”，再持续显示进度，最后给出耗时与平均速度：

```
   runtime.tar.gz: 38.7 MB via gh-proxy.com
   runtime.tar.gz: 12.4 MB / 38.7 MB (32%) 1.8 MB/s, 7s
   runtime.tar.gz: 38.7 MB in 21s (1.8 MB/s)
```

- 终端里由 curl 自己画单行进度条（百分比 / 已下载 / 速度 / 预计剩余）。
- 输出重定向到日志、没有终端时，改为每 `HEARTBEAT_SECONDS` 秒打印一行心跳（大小、百分比、速度、已用时间），不会出现“看着像卡死”的静默下载。
- 每条路由带 `--speed-limit`/`--speed-time` 与 `--max-time` 双保险：`STALL_SECONDS` 秒内没有任何新数据就判定卡死，打印 `no data for Ns` 后中断该路由并自动切换下一条；切换前会回显失败原因（含校验错误）。
- 单次传输上限 `DL_MAX_TIME`（默认 1800 秒）；只影响单条路由，不影响整体安装。

可用 `--progress` / `--no-progress` 强制开关，或用环境变量 `PROGRESS=auto|on|off`（默认 `auto`：有终端用进度条，否则用心跳）、`HEARTBEAT_SECONDS`、`STALL_SECONDS`、`STALL_BYTES`、`DL_MAX_TIME` 调整。

## 直接替换第三方授权

机器上已有的授权如果来自其它签发者（面板里显示“第三方许可证”），默认只做归档并保留，需要自己导入项目许可证。要让项目授权**直接替换**它们：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh -o /tmp/unlock.sh
sudo env LICENSE_FILE=/root/1Panel-Enterprise-XXXXXX.lic bash /tmp/unlock.sh install --use-mirror --replace-foreign
```

- `--replace-foreign`（等价 `REPLACE_FOREIGN=1`）会在替换前把第三方许可证的原始行完整归档到 `/opt/1panel/crack/backup/foreign-licenses.<sha256>.json`，然后把它们从 `licenses` 表里删除，只留项目签名授权；回读校验要求主节点上只有一条本项目授权。
- 归档文件按内容哈希命名并带校验和，重跑不会覆盖或丢档；`bash unlock.sh restore` 仍可还原官方内核与根证书行。
- 没有可用的项目签名授权时（既没有 `LICENSE_FILE`，也没有本机签名私钥），`--replace-foreign` 会在替换任何文件之前直接报错退出，不会把机器留在“第三方授权被删、新授权没上”的中间状态。
- 不加该参数时行为不变：第三方证书与许可证留档保留，只解除其主节点绑定。


## 当前支持

- 仓库当前最高稳定版本 `v2.3.2`；机器版本高于它时提前退出。
- 内核：`amd64 / x86_64`、`arm64 / aarch64`。
- Agent 重建：`amd64`；arm64 保留现有 Agent。
- 所有架构放在[同一版本 Release](https://github.com/keweiya/xpack-toolkit/releases)，始终选最高稳定版本；不回退到旧版或降级机器。

已有有效项目签名许可证会复用原到期日和节点额度。没有项目许可证时仍安装组件，明确显示“待导入”，第三方许可证及原绑定保持原样；准备匹配本机的预签许可证或本地签名材料后重新运行。脚本不下载私钥，也不把第三方许可证当作项目签名。

## 安装失败

按终端错误检查后，重新运行上面同一条命令即可。备份和运行记录默认保存在 `/opt/1panel/crack/backup` 与 `/opt/1panel/unlock`。
