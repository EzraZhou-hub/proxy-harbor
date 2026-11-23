# 指定应用的代理、DNS 和 WebRTC 设计核对

## 2026-11-17 系统 DNS 会话集成

已用持久 WFP 规则与独立恢复监督替换仅动态原型的退出顺序。基础和故障恢复来宾检查通过，双重崩溃需要显式恢复，真实 v2rayN／TUN 联合验收仍未通过。详见[系统 DNS 限制与恢复](p0-system-dns-session.md)。以下记录保留研究过程。

## 2026-11-17 本机进程方案研究

用户选择继续本机应用路线，最终运行环境不以虚拟机为依赖，系统实验仍在来宾进行。最新授权允许保护运行期间临时限制系统 DNS，退出后须恢复。由此可以直接在共享服务发包路径上施加临时限制，无需依靠已经失败的按用户 RPC_UM 过滤。

新增 native/p0/dns_block_lab.c 和 scripts/p0/build-dns-block-lab.ps1，原型只接受来宾固定路径与环境标记。动态 WFP 会话创建四条 ALE 出站规则，覆盖 IPv4／IPv6 的 53／853 目标端口。原型退出或被强制终止后，会话关闭并释放规则。35 项基础检查和 16 项真实 Chrome／受控 TLS 代理组合检查通过。依据微软[对象生命周期说明](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)，此类动态对象随其会话终止而删除。该行为也带来下一步必须解决的顺序要求：受管应用应先停止，随后解除 DNS 限制。

该实验核对了共享系统 DNS 和本地 TCP／UDP 双栈端点，未覆盖任意 443／非标准端口 DoH。需要继续研究 Windows DNS 服务的专门限制，或在保护期间禁用对应自动加密解析并精确恢复原值。代理本身的必要解析也须保持可用，不能把全部 DNS 阻断后的可控实验代理成功直接推广到现有 v2rayN。[本轮原始证据和源码摘要](../.local/p0/sandbox/20261117-063027-9afd75/validation.json)

另核对了 Windows 原生进程隔离路线。普通 AppContainer 的历史 Chrome 失败为 Crashpad CreateNamedPipe 拒绝访问，与微软文档中 AppContainer 命名管道的 LOCAL 命名空间限制相符，尚不能断言这是唯一兼容问题。Win32 app isolation 支持 appSilo，但微软仍标为预览，要求 Windows 11 build 26100 及以上和重新打包。开发机只读版本号为 26300，已有 SDK 26100，因此具备继续做隔离打包实验的基础。该路线尚未执行 Chrome 打包或运行测试，也未改动宿主包注册。[命名管道约束](https://learn.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-getnamedpipeserverprocessid)、[隔离打包说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-packaging-with-vs)

本次按用户要求仅对项目新启动的 Chrome 及其会话组件做增强。代码已编译并通过 Go 回归，新增 Windows 配置路径尚未执行。既有 370 条来宾证据对应修改前版本。P0 仍未验收，桌面入口关闭。

## 当前实现

临时普通用户 SID 及 WFP 限制仍在浏览器执行首条指令前建立。新增代码只加载这个新账户的用户配置，向其 Chrome 用户策略写入固定代理、无绕过列表、禁止网络预取、关闭独立浏览器 DoH、限制非代理 WebRTC UDP、关闭 QUIC 和设备发现。写入后逐项读回，失败时停止启动。策略键访问控制允许普通用户读取，管理员和 SYSTEM 写入。启动前及监控周期继续核对策略值。目标进程全部退出后先卸载本次加载的用户配置，再继续原有身份删除流程，失败则保留待恢复状态。

HTTP 代理承接网页 URL 的名称解析。浏览器自身还保留拒绝本地名称解析的 host-resolver-rules，避免隐式预取路径。关闭独立浏览器 DoH 的目的是统一到指定代理承担的解析路径。它需要代理端自身的 DNS 也经远程节点才能形成完整保证。Chrome 的 HTTP 代理会在代理侧解析名称。[Chromium 代理文档](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md)

WebRtcIPHandling 设置为 disable_non_proxied_udp。WFP 继续阻断该会话的 UDP、IPv6 和指定入口之外的 TCP。WebRTC 走其他 TCP 目标同样会被阻断。涉及通话、投屏或本地设备发现的网站可能无法工作。该设计仍需验证实际 Chrome 生效策略、全部 ICE 候选、TURN/TCP 及断网后的回退行为。[Chromium WebRTC 策略定义](https://chromium.googlesource.com/chromium/src/components/policy/+/c2d823006122fdaf9947de020737c04391a3ada5/resources/templates/policy_definitions/WebRtc/WebRtcIPHandlingUrl.yaml)

NetworkPredictionOptions=2 禁止浏览器网络预取。Windows 机器级策略可能覆盖用户策略，需要在 chrome://policy 核对实际生效项。新账户用户策略的读回仅证明注册表内容，不能替代 Chrome 运行时的生效证明。[Chromium 网络预取策略](https://raw.githubusercontent.com/chromium/chromium/main/components/policy/resources/templates/policy_definitions/Miscellaneous/NetworkPredictionOptions.yaml)

## 代理内部路由仍需实际配置依据

本地监听进程身份和出口网站的 IP，无法确定代理对任意目标的出站路径。反例是代理将 api.ipify.org 发到远程节点，同时把另一个站点发到 DIRECT。两种配置对现有出口探测的响应完全相同。增加有限个探测站点仍存在相同反例。

新增 routing-audit 工具检查用户提供的脱敏拓扑摘要。它要求默认出站和所有路由指向选定远程节点，拒绝其他出站、负载均衡、链式路径和本地 DNS 回退。DNS 模型使用字面公网 IPv4 的 HTTPS 解析器以避开解析器域名的引导查询。示例选择 Cloudflare 1.1.1.1，仅用于模型检查，代码未更改现有 v2rayN 的解析器或路由。

工具读取标准输入，拒绝未知字段，适用格式见 p0-routing-topology.example.json。请只提供路由目标、出站协议及 DNS 拓扑摘要。节点地址、密码、UUID、私钥和订阅内容不属于该格式。

```powershell
# 在 app/proxy-harbor 中执行，检查示例模型。
Get-Content ../../docs/p0-routing-topology.example.json -Raw | go run ./cmd/routing-audit
```

modelPassed=true 仅表示输入模型满足这些必要条件；runtimeVerified 始终为 false。摘要与实际运行配置的一致性、所选出站的真实远程端点及内核热更新仍待核对。工具的通过结果不能用于开放桌面准入。

## 理论保证和本机验证边界

理论路径为 Chrome → 固定回环入口 → 已核对且没有 DIRECT 路由的 v2rayN 内核 → 远程节点 → 目标。当前代码能够限制前一段，对后半段还缺实际运行的脱敏路由依据。普通子程序即使继承 SID，仍可能委托系统共享 Dnscache 服务查询；该服务的网络身份不同，现有 SID 规则不覆盖其代发流量。Chrome 用户策略不能证明任意子程序均无法调用共享服务。完整 DNS 和 WebRTC 的理论保证因此尚未闭合。

手动验证时需要核对策略生效、独立 DNS 观察端、所有 ICE 候选及 TCP/UDP 对照、目标专用 DIRECT 反例、代理故障和临时账户恢复。这些检查只涉及指定会话。当前项目后台按现有 AGENTS 约束保持桌面关闭，需要另行完成桌面准入条件后才能从普通 UI 开始本机系统测试。

