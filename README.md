# xpack-toolkit

1Panel v2 内网本地破解内核一键安装 / 更新工具。已有安装直接重跑同一条命令即可，无需手动卸载。

## 一键安装 / 更新

```bash
# 国外服务器
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash

# 国内服务器（走 gh-proxy 镜像）
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash
```

脚本自动完成：

1. **版本检测与升级**：读取宿主机 1Panel 版本与仓库最高稳定 Release；若 Release 版本较新，先通过官方安装包把宿主机 1Panel 升级到与 Release 一致（数据库迁移随官方内核启动自动完成）。
2. **替换破解内核**：从 Release 下载已移除全部授权检查的破解内核，替换官方或第三方内核；amd64 的 Agent 从官方原件重建。安装/证书工具（`gen_license.py` 等）直接从 `main` 分支拉取，不打包进 Release。
3. **本地生成授权证书**：生成企业版授权（999 节点、永久有效、离线），直接写入 `licenses` 表并绑定主节点。**机器中既有的证书/许可证一律保留不删除**；若主节点已绑定其它证书，会先解除旧绑定（交互终端提示确认，非交互默认自动解绑）。

破解内核已**移除全部授权检查**：授权中间件放行、本地签名/根证书校验恒通过、节点额度校验恒通过、授权上报/解绑不回连服务器。因此**不需要宿主机额外签发/生成任何授权证书，也不需要签名私钥**。

## 选项

```bash
sudo bash unlock.sh install --use-mirror       # 启用内置镜像并自动选最低延迟
sudo bash unlock.sh install --prompt-unbind    # 解绑旧证书前交互确认
sudo bash unlock.sh install --skip-agent       # 不重建/替换 amd64 Agent
sudo bash unlock.sh verify                     # 回读校验破解内核与已绑定授权
sudo bash unlock.sh restore                    # 回滚到替换前的官方内核
```

- `--mirror auto|URL` / `--no-mirror`：选择 GitHub 下载线路。
- `--http-proxy URL`：设置本机网络代理。
- 兼容环境变量 `GH_PROXY`、`GH_MIRRORS`，`curl` 沿用 `http_proxy` / `https_proxy`。

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

## 发布架构

内核补丁与脚本工具**分层发布**，日常改动不需要重新发版：

- **内核资产**（`core` / `core.orig` / `agent.orig` / `manifest.json`）——只随 1Panel 版本升级重新发版一次，之后保持不变。
- **脚本工具**（`unlock.sh` / `tools/*.py` / `state/license.crt`）——直接从 `main` 分支下载，push 到 `main` 即对下次安装生效。

因此改证书显示、授权默认值、安装流程时，只需提交到 `main`，用户重跑同一条命令即可，无需重新构建 Release。

## 当前支持

- 仓库当前最高稳定版本 `v2.3.2`；机器版本高于它时提前退出。
- 内核：`amd64 / x86_64`、`arm64 / aarch64`。
- Agent 重建：`amd64`；arm64 保留现有 Agent。
- 所有架构放在同一 Release，始终选最高稳定版本；不回退、不降级机器。

## 安装失败

按终端错误检查后，重跑同一条命令即可。备份与运行记录默认保存在 `/opt/1panel/crack/backup` 与 `/opt/1panel/unlock`。
