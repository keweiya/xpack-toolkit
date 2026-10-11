# xpack-toolkit

1Panel v2 一键解锁安装工具。已有安装直接重新运行同一条命令，无需手动卸载。

## 一键安装 / 更新

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash
```

脚本自动完成：

1. 获取仓库最高稳定版本，读取机器版本，先按主版本、次版本、补丁版本比较。
2. 仓库版本大于等于机器版本才继续；低于机器版本或最新资产缺少当前架构，立即退出。
3. 重新替换旧工具内核；amd64 的 Agent 从可信官方原件重建，不再依赖旧 Agent 或旧备份。
4. 保留其它来源的证书和许可证，留档旧验证根，再启用项目验证根；有效项目许可证自动导入绑定。
5. 重启服务并回读验证。网站、应用、面板数据和有效许可证均保留。

版本校验通过前仅临时下载和只读检测。兼容其它来源旧内核：保存旧二进制和许可证验证根，再替换仓库组件。网站 HTTPS、系统证书及第三方许可证签名原文均保留；导入项目许可证时仅解除旧许可证的主节点绑定，不删除旧许可证。不卸载整个 1Panel。

## 当前支持

下载默认直连，失败自动依次切换 `https://ghfast.top/`、`https://gh-proxy.com/`、`https://ghproxy.net/`。镜像返回 HTML、无效 JSON 或校验不符会继续切换；全部失败才退出。入口命令已使用 ghfast；入口镜像失效时可替换其前缀为其它镜像，或去掉前缀直连。

可在上述命令的 `sudo bash` 处设置：`sudo env GH_PROXY=https://gh-proxy.com/ bash` 优先指定镜像；`GH_MIRRORS` 自定义逗号/空格分隔的镜像列表；`GH_PROXY=direct` 仅直连；`XPACK_HTTP_PROXY=http://127.0.0.1:7890` 使用本机 HTTP 代理。curl 也沿用环境里的 `http_proxy` / `https_proxy`；经 sudo 运行时需显式传入。

- 仓库当前最高稳定版本 `v2.3.2`；机器版本高于它时提前退出。
- 内核：`amd64 / x86_64`、`arm64 / aarch64`。
- Agent 重建：`amd64`；arm64 保留现有 Agent。
- 所有架构放在[同一版本 Release](https://github.com/keweiya/xpack-toolkit/releases)，始终选最高稳定版本；不回退到旧版或降级机器。

已有有效项目签名许可证会复用原到期日和节点额度。没有项目许可证时仍安装组件，明确显示“待导入”，第三方许可证及原绑定保持原样；准备匹配本机的预签许可证或本地签名材料后重新运行。脚本不下载私钥，也不把第三方许可证当作项目签名。

## 安装失败

按终端错误检查后，重新运行上面同一条命令即可。备份和运行记录默认保存在 `/opt/1panel/crack/backup` 与 `/opt/1panel/unlock`。
