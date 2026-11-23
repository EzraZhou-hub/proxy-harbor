# 本机网络环境诊断：开源调研与首版方案

> 后续需求已确定为 Windows 桌面应用与指定应用的严格代理保护。实施技术与顺序以 [开发计划](development-plan.md) 为准；本文保留初期调研内容。

调研日期：2026-11-09。当前目录为空；本文是调研与设计，尚未实现检测程序，也未执行本机联网探测。

## 建议

做一个 Windows 优先的本机诊断工具，检测引擎在用户电脑上执行，界面可采用本地网页或桌面窗口。优先独立实现判定规则，参考已有项目的功能与模块组织，复用适合的协议库。

检测必须明确区分：应用未显式配置代理的路径、显式 HTTP/SOCKS5 代理路径、浏览器实际使用的路径。未显式配置代理仍然可能经过 VPN、TUN 或透明代理，不能直接叫“真实直连”。

## 已核对的开源项目

| 项目 | 已核对能力 | 值得参考 | 边界 | 许可证标识 |
| --- | --- | --- | --- | --- |
| [jason5ng32/MyIP](https://github.com/jason5ng32/MyIP) | 多来源 IPv4/IPv6、WebRTC、DNS 泄露、连通性、代理规则测试 | 检测面板、多个检测服务的重试和回退机制 | 浏览器视角不能覆盖所有本机网络状态；自托管不等于所有探测均由客户端发出 | AGPL-3.0-only（package.json） |
| [francomano/ProxyDoctor](https://github.com/francomano/ProxyDoctor) | Go CLI、本地 Web GUI、代理适配器、直连/代理对比、结构化报告 | Checker 接口、依赖编排、报告中的证据与建议 | 已核对的 DNS、IPv6、WebRTC 判定存在推断过度的问题，不能照搬 | GPL-3.0（README）；LICENSE 允许 v3 或后续版本 |
| [macvk/dnsleaktest](https://github.com/macvk/dnsleaktest) | DNS 泄露检测客户端，包含 Python、Shell、Windows 批处理和 Go 实现 | 会话 ID → 唯一子域名探测 → 获取递归解析器观测结果 | 客户端依赖 bash.ws；第三方服务可用性和结论需单独验证 | MIT |
| [pion/stun](https://github.com/pion/stun) | Go STUN 协议与客户端、映射地址、重传、NAT 行为发现示例 | UDP 出口地址与 STUN 探测的基础库 | 协议库，不是完整诊断产品；NAT 行为发现需要服务器支持 | MIT |
| [tailscale/tailscale：netcheck](https://github.com/tailscale/tailscale/tree/main/net/netcheck) | UDP STUN 往返、IPv4/IPv6、映射随目标变化、区域时延等 | 区分“能发包”和“收到响应”，超时与多节点探测设计 | 与 Tailscale 的运行环境及 DERP 等组件耦合，优先参考方法 | 已查看源码文件标记 BSD-3-Clause |

以上结论来自仓库 README 和相关源码阅读，不代表已经运行并验证这些项目。

### 直接可读的实现入口

- MyIP：[DNS 服务调度与回退](https://github.com/jason5ng32/MyIP/blob/main/frontend/utils/dnsleaks/index.js)、[bash.ws 会话式探测](https://github.com/jason5ng32/MyIP/blob/main/frontend/utils/dnsleaks/bashws.js)、[依赖与许可证标识](https://github.com/jason5ng32/MyIP/blob/main/package.json)。
- ProxyDoctor：[DNS 判定](https://github.com/francomano/ProxyDoctor/blob/master/core/checks/dns_leak/check.go)、[SOCKS 适配器](https://github.com/francomano/ProxyDoctor/blob/master/core/adapters/socks.go)、[IPv6 判定](https://github.com/francomano/ProxyDoctor/blob/master/core/checks/ipv6_leak/check.go)、[原生 STUN 探测](https://github.com/francomano/ProxyDoctor/blob/master/core/checks/webrtc_leak/check.go)。
- dnsleaktest：[Python 客户端](https://github.com/macvk/dnsleaktest/blob/master/dnsleaktest.py)、[许可证](https://github.com/macvk/dnsleaktest/blob/master/LICENSE)。
- Pion：[STUN 用法与 NAT 行为发现入口](https://github.com/pion/stun/blob/main/README.md)、[许可证](https://github.com/pion/stun/blob/main/LICENSE)。
- Tailscale：[netcheck.go](https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go)。

### 阅读源码发现的判定问题

1. ProxyDoctor 的 DNS 判定把相同的目标解析记录作为泄露依据之一。相同 A/AAAA 记录并不能说明查询走了相同路径；不同记录也不能证明没有泄露。其 SOCKS4/5 适配器的 ResolveDNS 使用 net.LookupIP，不能作为远端代理 DNS 已实际工作的证据。
2. ProxyDoctor 的 WebRTC 项目通过原生 UDP STUN 和本地网卡收集地址。它可提示本机 UDP 出口风险，但没有执行浏览器 RTCPeerConnection，无法据此确认某个浏览器实际暴露了哪些 ICE 候选地址。
3. ProxyDoctor 的 IPv6 判定依据包括本机 IPv6 可用性和代理能否转发 IPv6 目标。两者都不直接证明应用请求绕过代理；失败时也可能是阻断。需要实际请求与路径证据。
4. Tailscale 的 Report 分开记录 UDP 往返成功、IPv4/IPv6 往返、是否可以发送数据包，适合借鉴这种证据粒度。

这些是对已查看版本代码的分析，后续版本可能改变。

## 首版检测范围

| 模块 | 检测内容 | 结果中必须保留的信息 |
| --- | --- | --- |
| 本地环境 | 操作系统、活动网卡、IPv4/IPv6 地址、网关、默认路由、DNS 配置 | 接口来源；虚拟网卡只是线索，不能单独证明 VPN/TUN 生效 |
| 代理配置 | Windows 用户代理、WinHTTP、环境变量、PAC 地址、手动输入的 HTTP/SOCKS5 代理 | 配置来源、端口连通性；PAC 地址存在不等于已经执行 PAC |
| HTTP 出口 | 未显式代理、指定代理、浏览器分别请求多个 IP 回显服务 | IP、地址族、服务、时间、耗时、选用路径与观测限制 |
| IPv4/IPv6 | 本机地址、可发包、真实往返、代理连接 IPv6 目标的能力 | 客户端到代理的地址族与代理到目标的地址族分开记录 |
| DNS 配置与解析 | 本机 DNS、A/AAAA、必要时 DoH 对照 | 配置地址与外部观测到的递归解析器分开记录 |
| DNS 泄露 | 使用唯一子域名触发实际解析，查询外部观测结果 | 观测到的递归器出口 IP、服务、探测上下文、预期策略 |
| UDP | 原生 UDP STUN；SOCKS5 UDP ASSOCIATE 后的 STUN 往返 | 服务、端口、成功次数、映射地址、RTT、是否经过代理 |
| 浏览器 WebRTC | 浏览器实际收集 ICE 候选并与对应路径基线对照 | host/srflx/relay、地址族、浏览器策略或权限造成的限制 |
| 连通性 | DNS、TCP、TLS、HTTP 分层探测常用目标 | 区分解析失败、连接超时、证书错误、HTTP 状态错误 |
| 报告 | 检测过程、单项证据、解释、建议、JSON/HTML 导出 | 原始错误、能力边界、不可判定的原因；代理密码不进入报告 |

第二阶段再加入：QUIC/HTTP3 握手、持续时延/丢包/抖动、完整 NAT 行为测试、MTU、路由追踪、代理分流规则、断线保护验证、多次报告对比。

## 关键实现原则

### 出口 IP 与 IPv6

- 同一设备可能因地址族、协议、目标域名、分流规则而具有多个出口，应展示矩阵而非一个“本机公网 IP”。
- 显式代理请求不得在失败时静默回退到直连。
- 直连基线必须写成“未显式使用应用代理”，除非已有独立证据证明绕过了系统隧道。
- 代理到目标 IPv6 可达，不代表本机到代理用了 IPv6；HTTP CONNECT 到 IPv6 目标时尤其要分别报告。
- 未获取独立基线或没有预期代理策略时，只展示观测与疑点，避免直接给出泄露结论。

### DNS 泄露

建议流程：创建会话 → 生成不可复用的随机域名 → 在指定上下文触发解析 → 轮询权威侧观测 API → 展示看到的递归解析器出口 → 结合用户预期策略判断。

原生系统解析器、浏览器安全 DNS、代理远端解析可能走不同路径，需要分别测试。显式 HTTP 代理请求通常不要求客户端解析目标域名，因此不能把本机 DNS 查询结果标成代理远端解析结果。

权威侧通常看到最后一跳递归解析器，不一定是电脑配置的 DNS 地址；若有转发链，也不能从该地址重建整条路径。DNS 服务商与代理出口的国家或 ASN 不同，只能作为提示。

没有 DNS 观测服务时应显示“无法验证”，不能用公共 DoH 查询替代本机 DNS 泄露检测。接入第三方服务时将其封装为可替换 provider；后续可用自己的域名、权威 DNS 与结果 API 替换。

MyIP 的 bash.ws 实现与 macvk 客户端提供了可参考的会话式流程，见上方源码链接。

### UDP、STUN 与 WebRTC

- UDP 成功需要收到并校验响应，send 成功不足以说明连通。单节点超时也不足以证明整台电脑的 UDP 都被阻断。
- 直连 STUN、代理 UDP、DNS/UDP、QUIC 必须分别测试；一项成功不能推导其他端口或协议也可用。
- SOCKS5 定义 UDP ASSOCIATE，但实际代理端可能未实现。传统 HTTP CONNECT 只提供 TCP 隧道，不能拿它声称已检测代理 UDP。
- NAT 映射行为测试需要多目标观测；更完整的行为发现要求服务器支持相关扩展。
- 原生 STUN 结果和浏览器实际 WebRTC 结果分别展示。没有 ICE 候选也可能源于浏览器策略、超时或服务不可用，不能直接判定“绝无泄露”。

协议依据：[SOCKS5 RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)、[WebRTC IP 处理 RFC 8828](https://www.rfc-editor.org/rfc/rfc8828)、[NAT 行为发现 RFC 5780](https://www.rfc-editor.org/rfc/rfc5780)。

## 建议架构

以下是针对需求提出的设计建议，并非现有实现。

```text
本地网页 / 桌面窗口
  ├─ 浏览器探测：HTTP 出口、WebRTC、浏览器 DNS 上下文
  └─ 本机检测 API（仅绑定 loopback）
       ├─ 系统采集：网卡、路由、代理与 DNS 配置
       ├─ 调度器：并发限制、超时、取消、任务进度
       ├─ 传输：无显式代理 / HTTP CONNECT / SOCKS5 TCP / SOCKS5 UDP
       ├─ 探测器：IP / DNS / UDP STUN / IPv6 / TCP TLS HTTP
       ├─ 证据与规则：观测值、预期策略、结论、限制
       └─ 报告：JSON / HTML / 本地历史
外部观测服务：IPv4/IPv6 回显、DNS 权威观测、STUN、可选 QUIC 端点
```

建议 Go 实现本机检测引擎，Vue 或 React 实现界面；网页方案可将界面嵌入可执行程序。后续如需桌面安装体验，可以保留引擎并接入桌面壳。

浏览器端 WebRTC 检测必须确实在目标浏览器中运行。桌面 WebView 的结果只代表该 WebView，不能代表已经打开的 Chrome、Edge 或 Firefox。

本机 API 应校验 Origin/Host 并使用会话令牌，避免任意网页调用检测接口。所有第三方端点集中配置，记录调用来源；报告默认保存在本地。

### 结果模型

每项结果同时保存执行状态与诊断结论，避免把“无法检测”合并成通过或失败。

- 执行状态：completed / timeout / unsupported / skipped / error。
- 诊断结论：expected / risk / inconclusive / not_applicable。
- 上下文：native_default / explicit_proxy / browser；指定接口、地址族、协议和目标。
- 证据：观测 IP、递归解析器、STUN 映射地址、响应次数、耗时、原始错误。
- 限制：基线是否独立、是否可能经过 TUN、第三方探测是否可用。
- 策略：仅 HTTP 代理、全流量隧道或用户自定义预期。普通 HTTP 代理下的原生 UDP 直连与“全流量保护”下的 UDP 直连含义不同。

## 开发顺序与验收

1. 环境采集、代理输入、多来源 IPv4/IPv6 出口、分层连通性与 JSON 报告。
2. DNS 会话式观测、原生 STUN、SOCKS5 UDP，接入超时、取消和端点回退。
3. 浏览器 WebRTC、DNS 上下文对照、检测面板与 HTML 报告。
4. 按需增加桌面安装包、自有观测服务、持续监测与高级诊断。

核心验收场景：无代理、有效/失效 HTTP 代理、有效 SOCKS5、SOCKS5 不支持 UDP、IPv4 单栈、IPv6 不可达、DNS 服务超时、TUN 已开启、浏览器 DoH 开关、浏览器禁止候选暴露。

尤其需要验证：DNS 记录相同不直接报泄露；代理失败不回退；没有观测数据不显示安全；HTTP 出口相同不证明所有协议出口相同；DNS 服务不可用不导致整份报告失败。
