# P0：借鉴 Claude Cage 的转发许可与撤销

日期：2026-11-13。仅优化 P0 实验传输；桌面保护仍不可开启。

## 参考与落点

参考项目为 [Lee-xeo/Claude-Cage](https://github.com/Lee-xeo/Claude-Cage)，固定提交 `61e63f922cb85cc4d100215546a00ed5aeded2ff`。已阅读其 [gate.go](https://github.com/Lee-xeo/Claude-Cage/blob/61e63f922cb85cc4d100215546a00ed5aeded2ff/internal/cage/gate.go)、[egress.go](https://github.com/Lee-xeo/Claude-Cage/blob/61e63f922cb85cc4d100215546a00ed5aeded2ff/internal/cage/egress.go) 和 [safety.go](https://github.com/Lee-xeo/Claude-Cage/blob/61e63f922cb85cc4d100215546a00ed5aeded2ff/internal/cage/safety.go)。

| 借鉴的行为 | 本项目的独立实现 |
| --- | --- |
| 默认关闭、限时许可 | `TransportGate` 默认拒绝拨号；显式开放需要有效上下文与不超过五分钟的时长，没有自动续期 |
| 撤销已有流量 | 手动关闭、父上下文取消、到期、替换许可均先使旧许可失效，再取消握手并关闭已建立连接 |
| 拒绝上一轮迟到结果 | 每次开放绑定独立许可对象；旧握手不能注册到新许可，已经读到但尚未交付的旧数据也不返回成功 |
| 资源有界 | 等待握手与已建连接共同计入上限；重开期间尚未退出的旧握手也占用额度 |
| TCP 与 DNS 同一路径 | `Relay` 与 `DNSForwarder` 共用 `ProxyTransport`；缺失传输明确失败，普通 `net.Dialer` 不满足该接口 |

这是按行为设计重新实现，没有引入 Cage 源码、商业 SDK 或任何新增依赖。既有 HTTP/HTTPS/SOCKS5 认证、远端域名、证书验证和无直连回退行为继续由 `Upstream` 提供。

## 实验入口行为

`cmd/p0-relay` 已使用该控制层，默认许可五分钟；可通过 `-lease 30s` 缩短。启动 JSON 额外返回 `transportExpiresAt`（UTC）。到期后仍可监听实验端口，但新 SOCKS 请求失败，旧隧道关闭；不会自动续期、切换上游或恢复直连。重启实验转发器会创建新的显式实验许可。

`Open` 只是实验调用者给代理传输的限时许可，**不等于安全检查通过或应用受保护**。本轮没有实现 Cage 的完整安全报告准入、后台健康监测或桌面保护流程。`engine.Unavailable` 和 `StartProtection` 的禁用边界保持有效。WFP 持久限制仍承担独立阻断，许可关闭不会删除规则。

## 验证

新增八个顶层测试，覆盖默认关闭、无效许可、手动撤销、替换、上下文取消、到期、卡住的 TCP 拨号与 CONNECT 握手、握手成功与撤销竞争、连接额度回收、待响应 DNS 取消，以及读完成与撤销竞争。

已有六组协议与认证的转发/DNS 测试已经过控制层，真实回环测试验证 HTTP、HTTPS、SOCKS5 与 TCP 半关闭。宿主机只执行普通权限协议/回环验证、构建与静态检查；Windows WFP 回归仅在离线来宾执行。不启动或操作 Claude，不读取真实节点凭据，不改变系统代理，不执行重启。

最终离线包为 `.local/p0/sandbox/20261113-095651-34a3b5/`：27 个协议/组件顶层测试通过，其中新增 8 个许可/撤销测试；受控转发与独立阻断六组共 168 条观测、透明接管六组共 282 条观测均通过，所有来宾规则清理结果为 `verified`。来宾已停止；宿主机三组只读检查均成功，规则数均为 0。

普通 Go 全量测试、`go vet ./...`、系统测试构建与 `go vet -tags p0system ./internal/engine` 也通过。汇总见 `.local/p0/cage-transport-validation.json`，完整上下文见 [当前恢复点](p0-transparent-progress.md)。原有完整系统 DNS/共享服务、真实应用组件、跨架构、公网 IPv6/UDP 与最早自启动覆盖缺口仍然存在；本轮不把 P0 标记为验收完成。
