# dpanel 专业版（PE）授权解锁

[`donknap/dpanel`](https://github.com/donknap/dpanel) 的 Professional Edition 二进制内置授权门控，未授权时所有 `/pro/*` 接口返回 `500 .proLicenseFileIsCorrect`。本工具在二进制层移除该门控，解锁全部专业版能力（Passkey、Two-FA、容器快照/回滚、远程镜像仓库、主题等）。

## 一键生成

```bash
python3 tools/dpanel_unlock.py --download v1.11.1 --plat gnu-amd64 -o dpanel-pe
```

已有本地二进制时：

```bash
python3 tools/dpanel_unlock.py ./dpanel-pe-gnu-amd64 -o dpanel-pe
```

先看会改什么、不落盘：

```bash
python3 tools/dpanel_unlock.py ./dpanel-pe-gnu-amd64 --dry-run
```

## 运行

```bash
chmod +x dpanel-pe
APP_FAMILY=pe ./dpanel-pe server:start
```

`APP_FAMILY=pe` 决定加载 professional provider（默认 `ce`，加载社区版 provider，专业版路由不会注册）。

首次使用重置管理员：

```bash
APP_FAMILY=pe ./dpanel-pe user:reset --username admin --password 'YourPassword'
```

## 授权链（v1.11.1 / linux amd64 实测）

```
Process                       # gin 中间件，所有专业版路由前置
  ├─ os.ReadFile(dpanel.lic)              # 授权文件
  ├─ os.ReadFile(w7_opensoftware.enc)     # 备用授权文件
  ├─ base64 -> AES -> json.Unmarshal       # 解析为 LicenseInfo 副本
  ├─ OpenSoftwareLicenseInit
  │    └─ OpenSoftwareLicenseVerify         # 在线校验（HTTP + 本地 cache）
  ├─ zuakDQ4                                # 授权有效期窗口比较（3 次）
  └─ c.Set("license", info) -> c.Next()
```

任一环节失败即 `dhLg4iC53e` → `JsonResponse(500, ".proLicenseFileIsCorrect")` + `AbortWithStatus(500)`。

## 补丁点

| # | 位置 | 改动 | 作用 |
|---|---|---|---|
| 1 | `OpenSoftwareLicenseVerify` 入口 | `sub rsp,8; lea rax,[LicenseInfo]; call runtime.newobject; mov byte [rax],1; xor ebx,ebx; xor ecx,ecx; add rsp,8; ret` | 恒返回 `LicenseInfo{Valid:true}, nil`，不联网 |
| 2 | `OpenSoftwareLicenseInit` 入口 | `call Verify; ret` | 参数校验短路，直接透传（1） |
| 3 | `Process` 内「授权文件不可读」条件跳转 | `0F 85 rel32` → 6×`NOP` | 文件缺失不再中止，继续走到对象分配 |
| 4 | `Process` 内解密失败分支 | `75 0A` → `E9 rel32`（跳到 `call Init` 前） | 跳过 base64/AES 解析 |
| 5 | `zuakDQ4` 三处有效期比较 | `7C`→`90`、`7D`→`EB`（两处） | 强制走成功分支，`c.Set` + `c.Next` 正常执行 |

补丁 1/2 必须成对：`Process` 依赖 `Verify` 返回**非 nil** 的 `*LicenseInfo`，直接 `c.Next()` 放行会因为下游 `c.Get("license")` 拿到 nil 而 `sigpanic`。

## 定位方式（跨版本复用）

PE 二进制被 **garble** 混淆：包名随机（`cJ2GWc.JTnSd9fw8Z`、`aAU0AeKzXf`），但标识符后缀保留。且 pclntab magic 被改为 `0x34034664`（非标准 `0xFFFFFFF1`），`go tool nm` 完全失效。

工具链因此不使用任何硬编码偏移：

1. `tools/gopclntab.py` 直接读 `.gopclntab` 段（不依赖 magic），用 `textStart + entryoff` 换算虚拟地址，导出 `{函数名: (vaddr, size)}`。
2. 按**后缀**解析符号：`*.OpenSoftwareLicenseVerify`、`*.OpenSoftwareLicenseInit`。
3. `Process` 有多个同名方法，用「函数体内是否 `call Init`」唯一确定授权中间件。
4. `LicenseInfo` 类型描述符由 `Process` 内 `lea rax,[type]` + `call runtime.newobject` 指令对反推。
5. 其余补丁点在函数体内按指令模式匹配（`48 85 d2 0f 85`、`48 85 db 75 0a ...`、`48 85 c0 7c/7d`）。
6. 任何一处匹配失败即整体报错退出，不产出半成品二进制。

## 验证

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8086/dpanel/api/common/user/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YourPassword"}' | jq -r .data.accessToken)

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8086/dpanel/api/pro/home/get-license-info
```

未解锁：

```json
{"code":500,"error":"...\"title\":\".proLicenseFileIsCorrect\"..."}
```

解锁后：

```json
{"code":200,"data":{"expireTime":"2125-10-19T22:24:10+08:00"}}
```

`/pro/passkey/get-list`、`/pro/home/login-info`、`/pro/registry/repository/list` 等同类接口同步恢复 200（个别接口在数据库为空时返回业务错误 `record not found`，属正常）。

> 认证注意：JWT 的 `iat` 必须晚于服务启动时间，否则返回 401 `"JWT was issued before server start"`。重装或重启后重新登录一次。

## 支持范围

- 架构：**x86-64 / linux（gnu）**，已实测 `v1.11.1`。
- 其它架构（`arm64`、`musl`、`darwin`、`windows`）脚本会明确拒绝，需按同一思路重做 `arm64` 指令序列（`b.cond` 而非 `jcc`）。
- 版本升级后若 `zuakDQ4` 被改名或有效期比较增至 3 处以上，`zuakDQ4` 解析失败会显式报错——按 `expiry check` 一行的思路重新定位即可，其余补丁仍基于稳定后缀。

## 排错

| 现象 | 原因 |
|---|---|
| `symbol not found: *.zuakDQ4` | 版本改名，`--dry-run` 看已解析到的符号，改用新的有效期检查函数后缀 |
| `Process: license-file abort jump not found` | 授权文件读取逻辑重写，需重新识别 `Process` 内的中止分支 |
| patch 后 `500` 依旧 | 未加 `APP_FAMILY=pe`，实际加载的是 CE provider |
| 启动即 `sigpanic` | 补丁 1/2 未成对生效，或 `Process` 的对象分配被跳过 |
