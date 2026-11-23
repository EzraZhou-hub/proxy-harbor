# P0：现有客户端的本地入口与公网检查

日期：2026-11-13。用户已明确恢复 P0；仅验证普通权限协议连接，未在开发机安装规则或运行透明拦截候选，未操作 Claude。

## 查到的入口

只读查询 Windows 当前用户的 Internet Settings 和对应端口监听记录：系统代理启用，地址为 `127.0.0.1:10808`，无 PAC；该地址确实由 `xray` 进程监听。没有读取客户端的节点配置、密钥或账号，没有改动全局代理、DNS、证书或网络接口。

本项目本轮连接的是 **HTTP `127.0.0.1:10808`**。用户已有客户端负责远端 VLESS/XHTTP/REALITY 协议；不把公网地址或 `60415` 填成本地 HTTP 入口，不据此声称项目原生支持 VLESS。

## 项目传输实测

新增 `app/proxy-harbor/cmd/p0-upstream-check`，直接复用 `engine.Upstream`。只接受明确的 `127.0.0.1:port`，不使用环境或 Windows 系统代理作为回退。固定查询 `https://api.ipify.org?format=json`，目标域名原样交给代理；目标 TLS 使用系统信任根校验证书，拒绝重定向，限制超时与响应大小。未发起用于比较的公网直连请求。

该程序以普通权限运行，结果为：

| 检查 | 结果 |
| --- | --- |
| HTTP CONNECT 经本地客户端 | 通过 |
| 目标 HTTPS 证书校验 | 通过 |
| 此次请求观测到的 IPv4 出口 | `131.103.130.202`，与用户提供地址一致 |
| 入口不可用 | 临时分配后关闭的回环端口返回“入口连接”失败，程序退出码 1；未改用仍可用的系统代理 |

正向记录：`.local/p0/public-upstream-http.json`。反向记录：`.local/p0/public-upstream-unavailable.json`。后者退出码 1 是预期结果，不能将它记为出口检查通过。

构建后可复现正向检查：

```powershell
& .local/p0/bin/p0-upstream-check.exe -protocol http -upstream 127.0.0.1:10808
```

这是单一 HTTPS 目标、单一本地 HTTP 入口在检查时刻的出口证据。没有测试该真实客户端的 SOCKS5/HTTPS 入口、其他分流目标或真实应用。`applicationProtectionVerified` 明确为 `false`；不等于真实应用已被透明保护、系统 DNS 已接管、IPv6/UDP 已在公网阻断或重启恢复已通过。离线规则与透明接管回归另见 [当前进度](p0-transparent-progress.md)。
