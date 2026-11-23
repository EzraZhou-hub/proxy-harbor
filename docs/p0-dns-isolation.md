# P0：共享 DNS 服务的独立约束候选

日期：2026-11-13。针对 [DNS 覆盖盘点](p0-dns-coverage.md) 中已观察到的服务代发路径，继续验证免费开源路线。本轮不接入桌面保护，不运行真实应用。

2026-11-14 后续：已完成隔离与透明钩子、固定子孙程序的组合，并新增按临时 SID 的六条精确 WFP 规则；最终候选不依赖本篇旧实验的调试回环例外。默认 DNS/冷热缓存、未配置 EXE 规则组件和真实 HTTPS 的对照通过，详见 [集中记录](p0-batch-progress.md)。本篇旧包及 LPAC 排除结论保持原范围，不作为实际应用兼容声明。

## 为什么需要独立边界

已安装应用路径 WFP 限制、但未注入钩子的测试程序，仍能通过 Dnscache 服务向受控 DNS 端点发送查询。继续补充 DNS API 钩子可以改善正常调用兼容性，但不能把它当成共享服务的独立强制边界。

微软的 [WFP 条件列表](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-) 将 `ALE_ORIGINAL_APP_ID` 定义在重定向连接的语境中；它不能仅凭名称就被解释成任意 RPC 服务代发请求的原始调用程序。各 [过滤层允许的条件](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer) 也不同。本轮不通过全局阻断 DNS 服务、关闭系统 DNS 或修改其他应用规则来补缺口。

## 临时应用隔离实验

候选为 Windows 原生 AppContainer 与 LPAC。按微软 [AppContainer 实施说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)，使用固定测试程序、独立临时包身份和零能力列表，检查未注入的 DNS 调用是否仍能触发服务代发。

实验代码为 `native/p0/dns_isolation_lab.c`，只能从隔离来宾的固定路径、工作目录和环境标记运行。它只接受两种模式及限定长度的十六进制域名标签；不能指定任意 EXE、域名、能力或 ACL 目标。来宾暂时给测试目录及探针文件增加该身份的读取/执行权限，结束后恢复并逐字节核对原 DACL，再删除自行创建的容器身份。不修改宿主机权限、身份或网络设置。

测试程序先以挂起状态创建，核对 `TokenIsAppContainer` 和零能力列表。LPAC 专用令牌信息查询在第一轮返回 87，未执行子程序，该轮不计为 DNS 阻断证据。后续改用 [DuplicateToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken) 和 [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck) 进行两组权限对照：特定包 SID 的正向授权，以及 ALL_APPLICATION_PACKAGES 授权。它记录实际权限语义，不将查询 API 失败解释成 LPAC 或拒绝访问。

第二组场景通过 [NetworkIsolationSetAppContainerConfig](https://learn.microsoft.com/en-us/windows/win32/api/networkisolation/nf-networkisolation-networkisolationsetappcontainerconfig) 仅为新建身份临时启用回环例外，保留其他身份；四条应用 WFP 限制仍只允许探针连接实验代理端口。随后在同一身份下分别执行 DNS 请求和显式 SOCKS5 代理回显，核对原始域名送到测试上游。结束时只移除自身例外，重新读取并核对配置，再恢复 DACL、删除身份。该回环 API 文档标记为调试用途，本轮仅在离线实验中使用，未作为正式产品部署方案。

只有探针本身正常启动、完成调用并返回结构化结果，才分析 DNS 状态。进程加载失败、权限验证失败、超时或被终止均不能计为保护成功。受控 DNS 观察端点仍分别通过 UDP/TCP 自身校验，并与未限制对照程序比较。

## 产品边界

这些实验先回答隔离身份是否约束共享服务；即使 DNS 被拒绝，仍须进一步证明指定代理可用、真实应用组件兼容、子进程继承和退出恢复可靠。AppContainer/LPAC 会改变应用的资源权限，不能把测试程序结果直接推广到已安装桌面应用。

没有引入商业 SDK、第三方闭源内核或新 Go/npm 依赖。正式内核选型与 P0 总体验收仍保持未通过。

## 初步结果与最终验收范围

普通 AppContainer 在受控场景中将原先可由 Dnscache 代发的 `DnsQueryEx` 自定义服务器请求拒绝为 5（访问被拒绝），回环观察端点没有收到该域名。临时开启该身份回环例外后，指定 SOCKS5 入口经 HTTP 无认证实验上游完成域名回显，该 DNS 请求仍被拒绝。

零能力 LPAC 返回 DNS 参数错误 87，不能计作成功阻断；其 Winsock 无法初始化，代理回显也失败。因此当前 LPAC 配置被排除，保留失败原因与无上游连接的负向回归；不通过增加未经评估的权限来声称它已可用。

这仅验证了一条已知自定义服务器调用与一个实验代理工作流。**不能据此认定默认系统解析器、全部共享服务/RPC/ALPC、跨架构、透明注入、子进程或真实应用已获保护。** AppContainer 与现有透明钩子的组合、必要文件/配置访问、完整 DNS 覆盖及正式部署方式仍待后续 P0 验证。

## 最终包与清理

最终完整离线包为 `.local/p0/sandbox/20261113-105143-22cf59/`。原有 27 个协议/组件测试、6 组/168 条转发阻断观测、6 组/282 条透明接管观测，以及 DNS 20 个场景/89 条检查继续通过。新增四组隔离场景、37 条检查通过，其中包括明确保留零能力 LPAC 的代理不可用结果；“检查通过”不表示这个被排除配置可用于保护。

四组均验证临时 DACL 恢复和容器身份删除；两组开启回环的场景均验证自身例外已移除、其他条目保留。来宾规则清理为 `verified`，最终来宾已停止，宿主机三组只读规则检查均成功且规则数为 0。普通 Go 全量测试、`go vet ./...`、系统测试构建与 `go vet -tags p0system ./internal/engine` 通过。

汇总为 `.local/p0/dns-isolation-validation.json`；原始观测为最终包的 `results/dns-coverage-report.json`。实验启动器源文件、构建脚本和二进制均包含在包的摘要清单中。

历史包 `20261113-103612-38483a` 保留令牌查询不支持、未执行探针的失败结果；`20261113-104024-483fe6` 只验证无回环例外的身份语义与 DNS 调用，不含代理可用性；`20261113-104702-91087e` 保留 LPAC 代理失败的发现结果。最终包把该已确认不兼容配置作为负向对照，继续严格要求普通 AppContainer 候选完成代理回显和 DNS 拒绝，不将 LPAC 的失败当成防护成功。
