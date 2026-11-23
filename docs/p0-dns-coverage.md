# P0：系统 DNS 覆盖盘点与受控观测

日期：2026-11-13。范围为 P0 DNS 拦截边界、查询语义和隔离来宾观测。桌面保护继续不可开启。

2026-11-14 后续已补默认系统解析与实际冷热缓存对照，并在无调试回环例外的零能力 SID/WFP 隔离下验证已知共享服务调用被拒绝、指定代理可用。仅有 EXE 规则的服务代发缺口仍保留为对照事实。详见 [集中验证记录](p0-batch-progress.md)，不扩大到所有共享服务或真实应用。

## 已修复的语义问题

此前 `DnsQuery_W/A/UTF8` 忽略查询选项，`DnsQueryEx` 忽略自定义服务器与接口约束，非 A/AAAA 类型返回“没有记录”。这些行为可能让应用把不支持的请求当成有效 DNS 结果，盘点时已改为明确拒绝：

- 原生拦截首版只提供 A 类型的合成 IPv4 地址映射。AAAA、TXT、HTTPS 等尚无对应实现，返回 `ERROR_NOT_SUPPORTED`（50），不伪装成上游返回空记录。
- 允许标准查询，以及 BYPASS_CACHE、NO_LOCAL_NAME、NO_HOSTS_FILE、NO_NETBT、NO_MULTICAST、TREAT_AS_FQDN 的组合；它们只进入受控映射路径。缓存专用、完整 DNS 报文、TCP 专用、组播、未知选项等返回不支持，不忽略语义继续执行。
- DnsQueryEx v1 请求的自定义服务器或非零接口索引尚无实现，返回 50；不支持的请求版本返回 `ERROR_INVALID_PARAMETER`（87）。这些同步错误不排队回调、不返回记录。
- DnsQuery 的保留参数非空返回 87。原有受支持的 DnsQueryEx v1 回调与取消逻辑保留。

依据微软 [DnsQuery 参数约定](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsquery_w)、[DNS 查询选项](https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants)、[DNS_QUERY_REQUEST](https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_request) 和 [DnsQueryEx 完成规则](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryex)。

这里的 FakeIP 是临时映射令牌：只有随后连接携带原始域名经过代理并完成回显，才记录为“映射及代理连接成功”。它不是权威 DNS 返回的真实地址，也不证明系统 DNS 缓存已经受控。独立的 `DNSForwarder` 消息传输能力与原生 API 拦截支持范围分别记录。

## 覆盖矩阵

| 路径 | 当前行为与证据边界 |
| --- | --- |
| 普通 Winsock 域名、同步 GetAddrInfoEx W/A | 既有受控代理回显通过；未验证所有 hints、namespace/provider 与扩展模式 |
| DnsQuery W/A/UTF8，受支持的 A 查询 | 受控映射，再以原始域名完成代理回显；观察指定回环 DNS 端点 |
| DnsQueryEx v1 同步/回调 A 查询 | 同上；回调次数单独核对，原有取消竞争回归保留 |
| 同进程重复域名 | 连续两次映射与连接；不把它称为 Windows DNS 缓存冷热验收 |
| 缓存专用、完整报文、自定义服务器/接口、未知选项 | 明确拒绝，无记录/回调，不计入代理成功 |
| AAAA、TXT、HTTPS 等记录 | 原生首版明确拒绝；不计作 IPv6/其他记录类型转发成功 |
| GetAddrInfoEx overlapped 异步 | 既有路径明确拒绝；尚无可用异步实现 |
| DnsQueryRaw | 若导出存在则在入口拒绝；现有探针只测入口拒绝，不宣称完整合法原始请求兼容 |
| 共享 DNS 服务、RPC/ALPC 与绕过钩子路径 | 单独记录未注入探针的服务请求与端点进程归属；全覆盖未通过 |
| 系统缓存冷热、默认网卡解析器、公网 DNS/DoH/DoT、多播与双栈 | 尚未完成相应外部观测或兼容性验收 |

## 隔离测试方式

新增 `TestP0DNSCoverage`，只有固定 `C:\P0Lab` 和来宾环境标记可执行。探针的审计模式还校验自己的固定临时路径，以及严格限定的随机十六进制标签加 `.p0-dns-audit.invalid`；不能用它探测任意主机或真实应用。

离线来宾只在 `127.0.0.1:53` 启动 UDP/TCP 测试 DNS 端点，不修改 Windows 的 DNS 设置。端点仅应答审计域名，返回测试地址 `198.51.100.77`，并记录请求域名和协议。UDP 应答前通过 [GetExtendedUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable) 读取源端口拥有者 PID，并与来宾 Dnscache 服务 PID、探针 PID 比较；查询失败或 TCP 连接未归属时记录 PID 0，不推断服务归属。

未限制的对照程序先后验证系统查询到达端点的能力；有四条独立限制但未注入的探针用于测量共享服务边界。两类观测独立于已注入的 20 个语义场景，保留 API 状态和实际流量，不把未观测当作共享服务覆盖成功。未注入路径如果出现服务代发流量，会明确保留为已观察到的覆盖缺口。

不增加全局 DNS/IPv6 开关，不阻断共享系统服务，不加载宿主候选或添加宿主测试规则，不重启，不操作 Claude，不读取节点凭据；全部依赖沿用现有免费开源组件。

## 本轮结果

最终包为 `.local/p0/sandbox/20261113-101848-2718cc/`，其 `dnsCoverageChecks: passed`、`dnsCoverageCleanup: verified`。20 个已注入场景的 89 条行为检查通过：6 个场景完成映射及原始域名代理回显（重复域名场景包含两次连接），14 个场景明确拒绝；它们都没有在受控 DNS 端点产生查询。UDP/TCP 两条观测路径自身校验均通过。

**确认了共享服务覆盖缺口。** 未注入但已安装四条应用级限制的探针 PID 为 `5532`，DnsQueryEx 自定义服务器请求仍成功返回测试地址；端点收到相应唯一域名，UDP 源端点拥有者为 `2644`，与当时 Dnscache 服务 PID 一致。限制前后两个未限制的对照程序也得到正常应答。这证明本实验范围内的应用身份规则不能阻止共享 DNS 服务代发查询；不等于已注入场景出现了相同流量，也不等于验证了所有 RPC/ALPC 绕过方式。

第一轮对照探针因自定义服务器数组设置不符合 Windows 接口要求返回 87，没有可用流量证据，保留在 `.local/p0/sandbox/20261113-101429-2fa1ee/`，不用于声称共享服务覆盖。最终探针按微软 [DNSAsyncQuery 示例](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/DNSAsyncQuery/cpp/DnsQueryEx.cpp) 将服务器数组的 Family 和 socket 端口留零，交由 DNS API 使用标准端口；服务状态查询改为只申请查询权限。

完整回归同时通过 27 个协议/组件顶层测试、6 组/168 条转发阻断观测、6 组/282 条透明接管观测。普通 Go 全量测试、`go vet ./...`、系统测试构建及 `go vet -tags p0system ./internal/engine` 通过。相关来宾均已停止；宿主机三组实验规则数均为 0，检查 `windowsError` 均为 0。

汇总为 `.local/p0/dns-coverage-validation.json`，原始专项结果为最终包的 `results/dns-coverage-report.json`。**查询语义验收通过不等于系统 DNS 保护验收通过**，整体 P0 继续 `not_accepted`。后续须解决或可靠约束共享服务代发路径，并继续验证缓存、特殊 Winsock 参数和其他未覆盖入口；本轮到此交付，不推进其他优化项。

后续独立约束实验见 [AppContainer/LPAC 候选](p0-dns-isolation.md)。该后续证据包含“已知请求被拒绝且指定代理可用”的限定结果，不改变本篇对完整系统 DNS 覆盖的未通过结论。
