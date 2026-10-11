# xpack-toolkit

1Panel v2 一键解锁安装工具。已有安装直接重新运行同一条命令，无需手动卸载。

## 一键安装 / 更新

```bash
curl -fsSL https://raw.githubusercontent.com/keweiya/xpack-toolkit/main/unlock.sh | sudo bash
```

脚本自动完成：

1. 识别服务器架构和已安装的 1Panel 版本，选择同版本 Release。
2. 下载并校验匹配的内核、运行组件与官方原件。
3. 重新替换旧工具内核；amd64 的 Agent 从可信官方原件重建，不再依赖旧 Agent 或旧备份。
4. 复用已有有效离线许可证，修复显示字段并自动绑定主节点。
5. 重启服务并回读验证。网站、应用、面板数据和有效许可证均保留。

重复运行会更新工具组件；错误的旧备份另存留档，再建立可信备份。不会卸载整个 1Panel。

## 当前支持

- 已安装 1Panel `v2.3.2` 的 Linux 服务器。
- 内核：`amd64 / x86_64`、`arm64 / aarch64`。
- Agent 重建：`amd64`；arm64 保留现有 Agent。
- 同版本所有架构放在[同一个 Release](https://github.com/keweiya/xpack-toolkit/releases)，版本未发布时提前退出，不用其它版本替换。

已有有效签名许可证会自动复用，保留原到期日和节点额度。首次安装需准备匹配本机的预签许可证或本地签名材料；脚本不下载私钥。

## 安装失败

按终端错误检查后，重新运行上面同一条命令即可。备份和运行记录默认保存在 `/opt/1panel/crack/backup` 与 `/opt/1panel/unlock`。
