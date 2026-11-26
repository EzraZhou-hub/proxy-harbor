# Claude 候选域名代理与 DNS 验证

2026-11-18。按项目内原始清单检查六组共 24 个完整主机名。使用 Windows Sandbox 的新临时账户和受管 HTTPS 探针，沿用通过官方安装版 Claude 测试的 PH4 守护二进制。来宾运行 TUN，经限时文件通道使用宿主既有 HTTP 代理。测试请求不带账号信息，保留证书和主机名校验，记录重定向目标而不跟随。本轮未启动宿主或来宾的 Claude 客户端。[清单](../app/proxy-harbor/frontend/src/data/claude-code-domains.json) · [守护此前的 Claude Desktop 验证](p0-claude-sandbox-validation.md)

## 代理与泄露对照

- 24 个目标的 TCP 对端均为 `127.0.0.1:10808`。独立代理日志按本地源端口及目标主机名匹配全部 24 个 CONNECT。测试期间代理公网 IP 探测与预设 `131.103.130.202` 匹配。原始报告（`.local/p0/sandbox/20261118-024538-67bed9/results/claude-domain-audit.json`）
- 合成 DNS 名在防护前和撤除规则后都到达来宾观察端，防护期间的合成查询未到达。观察端未收到这 24 个名称的本地 DNS 查询，探针也没有触发针对这些域名的本地解析。受管探针主动尝试无代理 TCP 连接时，观察端未接到连接，守护记录出站阻断并终止进程。共 11 项保护检查及 5 项清理检查通过。DNS 与直连观察日志（`.local/p0/sandbox/20261118-024538-67bed9/results/domain-observer.log`）
- `claude.ai`、`claude.com` 和 `anthropic.com` 的 Cloudflare 公开诊断均经 TLS 验证，并报告来访 IP 与 `131.103.130.202` 一致。其余域名已核对来宾到指定代理这一段，缺少目标端看到的源 IP 证据。原始报告 `targetExitSamples`（`.local/p0/sandbox/20261118-024538-67bed9/results/claude-domain-audit.json`） · [Cloudflare 诊断端点说明](https://developers.cloudflare.com/support/troubleshooting/general-troubleshooting/geographic-traffic-routing/)

## 逐域名结果

18 个主机名通过 TLS 校验，其中 16 个返回了根路径的 HTTP 状态。根路径的 `301`、`302`、`403`、`404` 均表示已收到目标站点的加密 HTTP 响应。访问控制、重定向后的站点与具体业务接口需要各自的证据。首轮 8 个根路径没有 HTTP 响应的域名，使用相同守护和固定出口在新沙盒中以 GET 复测。对仍未建立 TLS 的 6 个域名，额外经指定代理向 Google 公共 DoH 查询 A/AAAA。两轮保护及清理检查均通过。GET 复测及 DNS 原始报告（`.local/p0/sandbox/20261118-025046-959e0b/results/claude-domain-audit.json`） · [Google DoH 响应说明](https://developers.google.com/speed/public-dns/docs/doh/json)

| 主机名 | TLS | 观测结果 |
| --- | --- | --- |
| `anthropic.com` | 通过 | 根路径在两轮中均断开，公开诊断返回 200 且来访 IP 匹配 |
| `claude.ai` | 通过 | 根路径在两轮中均断开，公开诊断返回 200 且来访 IP 匹配 |
| `claude.com` | 通过 | 根路径 200，公开诊断来访 IP 匹配 |
| `clau.de` | 通过 | 302 至 `claude.ai` |
| `claudemcpclient.com` | 未通过 | TLS 握手未完成，公共 DNS 回应 NOERROR，A/AAAA 均无地址 |
| `claudemcpcontent.com` | 未通过 | TLS 握手未完成，公共 DNS 回应 NOERROR，A/AAAA 均无地址 |
| `claudeusercontent.com` | 通过 | 301 至 `claude.com` |
| `cdn.anthropic.com` | 未通过 | TLS 握手未完成，公共 DNS 对 A/AAAA 均返回 NXDOMAIN |
| `anthropic.com.cdn.cloudflare.net` | 未通过 | 公共 DNS 有 A 和 AAAA，两次均收到对端 TLS 握手失败 |
| `servd-anthropic-website.b-cdn.net` | 通过 | 根路径 403 |
| `anthropic.auth0.com` | 通过 | 302 至 `auth0.com` |
| `anthropic-com.ghost.io` | 通过 | 根路径 404 |
| `mcp.anthropic.com` | 未通过 | TLS 握手未完成，公共 DNS 对 A/AAAA 均返回 NXDOMAIN |
| `console.anthropic.com` | 通过 | 301 至 `platform.claude.com` |
| `workbench.anthropic.com` | 未通过 | TLS 握手未完成，公共 DNS 对 A/AAAA 均返回 NXDOMAIN |
| `maps.googleapis.com` | 通过 | 302 至 `developers.google.com` |
| `withpersona.com` | 通过 | 根路径 403 |
| `frompersona.com` | 通过 | 301 至 `withpersona.com` |
| `sentry.io` | 通过 | 302 至 `sentry.io` |
| `statsigapi.net` | 通过 | 根路径 403 |
| `browser-intake-us5-datadoghq.com` | 通过 | 根路径 403 |
| `intercom.io` | 通过 | 301 至 `www.intercom.com` |
| `intercomcdn.com` | 通过 | 301 至 `www.intercom.com` |
| `cdn.usefathom.com` | 通过 | 301 至 `usefathom.com` |

清单在项目中用于展示。`api.anthropic.com` 见 Anthropic 官方网络文档，`assets-proxy.anthropic.com` 在前次真实 Claude 桌面端测试中已观察，两者均未在这 24 个完整主机名中单列。本轮统计按这 24 个主机名计算。[Anthropic 网络端点](https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions) · [真实 Claude 连接证据](p0-claude-sandbox-validation.md)

本轮验证未覆盖登录后的真实 Claude 请求、未列出的子域名和各第三方目的端的公网源地址。沙盒和限时中转已停止。宿主 Claude、DNS、代理设置和域名清单均未改动，桌面准入仍关闭。沙盒及通道清理（`.local/p0/sandbox/20261118-025046-959e0b/results/host-bridge-cleanup.json`）

## 免登录联合复验中的六域名补测

包 `20261118-032029-5ba094` 使用与 Claude 崩溃恢复和 TUN 退出补测一致的守护二进制，单独重测未通过 TLS 的六项。结果与上表一致。六项均独立观察到代理入口连接，未见来宾本地 DNS 查询，合成 DNS 正负对照和故意直连阻断通过。守护结束直连测试进程，核验出口仍为 `131.103.130.202`。11 项保护检查及 5 项独立清理通过，来宾和限时中转已停止。六域名补测（`.local/p0/sandbox/20261118-032029-5ba094/results/claude-domain-audit.json`） · 通道清理（`.local/p0/sandbox/20261118-032029-5ba094/results/host-bridge-cleanup.json`）
