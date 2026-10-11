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
4. 保留其它来源的证书和许可证，留档旧验证根，再启用项目验证根；有效项目许可证自动导入绑定。
5. 重启服务并回读验证。网站、应用、面板数据和有效许可证均保留。

版本校验通过前仅临时下载和只读检测。兼容其它来源旧内核：保存旧二进制和许可证验证根，再替换仓库组件。网站 HTTPS、系统证书及第三方许可证签名原文均保留；导入项目许可证时仅解除旧许可证的主节点绑定，不删除旧许可证。不卸载整个 1Panel。

## GitHub 镜像选择

镜像地址内置在脚本中：`https://ghfast.top/`、`https://gh-proxy.com/`、`https://ghproxy.net/`。安装时询问是否使用镜像，回车默认直连，没有交互终端也默认直连，未选择时不会自动启用。选择使用后，并发测量有效 GitHub API 响应的首字节延迟，用最低者下载内核和全部相关 GitHub 文件，失效时只切换到其它测速合格的镜像。

跳过询问可在上面命令末尾加参数：`--use-mirror` 或 `--mirror auto` 启用内置镜像并自动选最低延迟；`--mirror https://ghfast.top/`（也支持 `--mirror=URL`）只用指定镜像；`--no-mirror` 只用直连；`--http-proxy http://127.0.0.1:7890` 设置本机网络代理。例如：

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash -s -- --use-mirror
```

兼容环境变量 `GH_PROXY=auto/镜像地址/direct`（命令行优先）与 `GH_MIRRORS`（仅改测速候选，不会自行启用）；curl 沿用 `http_proxy` / `https_proxy`，经 sudo 运行需显式传入。入口脚本本身无法直连时，可自行给原始 URL 加镜像前缀，例如 `curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash`；入口选择与脚本内下载模式相互独立。所有下载仍做格式、版本与 SHA-256 校验。

## 第三方授权处理

检测到第三方证书或许可证时会询问：`是否直接替换为本站内核授权？[Y/n]`，回车即替换。替换会先把第三方证书和许可证原文留档到备份目录，再启用本站验证根、移除第三方许可证记录；此时若已提供项目签名许可证（`LICENSE_FILE` 或本机签名材料）会自动导入绑定，否则面板由本站内核解锁、授权显示待导入。选择保留则只替换内核与验证根，第三方证书和许可证原样不动。

跳过询问可加参数：`--replace-foreign` 直接替换，`--keep-foreign` 保留，或用环境变量 `FOREIGN_LICENSE=replace|keep`（命令行优先）。下载过程会显示当前线路、进度条和每 5 秒的心跳，长时间无数据也不会看起来像卡死。

留档文件在备份目录：第三方许可证原文 `foreign-licenses.<sha256>.json`，第三方证书原文 `core_settings_license_rootcert.preserved.<sha256>.json`；恢复官方镜像与官方根证书用 `bash unlock.sh restore`。

## 当前支持

- 仓库当前最高稳定版本 `v2.3.2`；机器版本高于它时提前退出。
- 内核：`amd64 / x86_64`、`arm64 / aarch64`。
- Agent 重建：`amd64`；arm64 保留现有 Agent。
- 所有架构放在[同一版本 Release](https://github.com/keweiya/xpack-toolkit/releases)，始终选最高稳定版本；不回退到旧版或降级机器。

已有有效项目签名许可证会复用原到期日和节点额度。没有项目许可证时仍安装组件并明确显示“待导入”，第三方许可证按上面的选择保留原样或留档后替换；准备匹配本机的预签许可证或本地签名材料后重新运行即可自动导入绑定。脚本不下载私钥，也不把第三方许可证当作项目签名。

## 安装失败

按终端错误检查后，重新运行上面同一条命令即可。备份和运行记录默认保存在 `/opt/1panel/crack/backup` 与 `/opt/1panel/unlock`。
