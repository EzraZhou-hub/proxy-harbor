# P0：代理传输与独立阻断验证

日期：2026-11-11。状态：**进行中，尚未通过 P0 验收**。本轮只推进第一项；后台服务、应用适配等后续项须等待用户确认后再开始。

最新进展（2026-11-13）：完整离线回归中，19 个协议顶层测试、6 组受控入口/阻断的 168 条观测、6 组透明接管的 282 条观测均通过，包括入口身份及退出后端口重占用拒绝；来宾已停止，宿主机三组实验规则均为 0。项目传输经现有本地 HTTP 入口也已完成一次真实 HTTPS 出口检查。详见 [透明接管进度与边界](p0-transparent-progress.md)、[真实入口检查](p0-public-validation.md)及[受控转发验证](p0-relay-validation.md)。固定不同路径辅助程序及 DnsQueryEx v1 回调/取消也通过，另一次来宾重启与显式恢复的 26 条观测通过，见 [机制验证](p0-helper-dns-recovery.md)。这仍不是任意程序透明接管或完整系统 DNS 接管验收。

用户要求 Claude 留到项目最后再测试。当前没有启动、探测或操作 Claude；普通配置回归仅操作 Codex 条目，P0 使用项目自建的隔离测试程序。用户已选择在**可恢复的 Windows 测试环境**中执行系统层实验，当前开发机不安装测试阻断规则。

## 已验证

| 内容 | 证据与范围 |
| --- | --- |
| 前三处基础修复 | Go 测试、静态检查、4 项草稿回归、5 项 Go/Edge 集成测试重新通过 |
| HTTP CONNECT | 本机模拟代理，分别无认证与用户名/密码；目标以域名交给代理 |
| HTTPS 上游 | 本机 TLS 模拟代理，两种认证；显式引导 IPv4，保留代理域名的 SNI 和证书验证 |
| SOCKS5 CONNECT | 两种认证，目标采用域名地址类型；拒绝认证降级和错误认证 |
| 错误处理 | HTTP 407/502、入口不可达、无效目标、缺少引导 IPv4、不可信证书、握手取消、过大响应头；不尝试直连目标 |
| 流式隧道 | CONNECT 响应与首批隧道字节合并到同一读取时不丢数据，后续双向字节流可用 |
| 真实套接字 | 三种协议 × 两种认证，共 6 组本机 TCP/TLS 测试通过；另有入口不可达时目标监听器未收到直连的观测 |
| 隔离程序通信基线 | 项目编译的测试程序及同名、不同路径对照程序，在 TCP4/TCP6/UDP4/UDP6 的 8 次回环通信中均成功 |
| WFP 工具编译 | MSVC x64，`/W4 /WX /MT`，使用 Windows SDK 与系统 Fwpuclnt；未链接或加载第三方驱动 |
| 开发机只读规则核查 | 沙箱外普通用户可读取测试 GUID；规则数为 0，未作规则修改。受限执行沙箱内查询曾返回访问拒绝，不将其等同于 Windows 管理员权限结论 |
| 来宾管理员阻断实测 | 离线 Windows Sandbox 中先验证两份测试程序的四种回环通信基线，再添加两条按应用身份匹配的持久过滤器；策略命令退出后，目标 TCP4/TCP6/UDP4/UDP6 均失败，同名但不同路径的对照程序均成功 |
| 来宾清理与宿主机复核 | 来宾删除本实验过滤器和 sublayer 后规则数为 0；本次 Sandbox 已停止且不再列出。宿主机只读核查测试规则数为 0、systemChanged=false |

普通协议测试使用内存管道；带 `p0integration` 标记的用例使用真实回环 TCP/TLS。域名传递测试只能证明这个上游传输实现不在本机解析目标，**不能证明任意桌面应用的系统 DNS 已被接管**。

原始记录位于项目 `.local/p0/upstream-tests.jsonl`、`.local/p0/policy-report.json`。这些文件包含检查状态，未观测的项目明确标为 `not_run`，总体为 `not_accepted`。

2026-11-11 10:23（北京时间）的来宾结果位于 `.local/p0/sandbox/20261111-022137-d2324f/results/`：`upstream-tests.log` 中 10 个顶层测试均通过（包括三种协议 × 两种认证的真实回环测试），`policy-report.json` 有 4 项基线和 4 项阻断通过、cleanup=verified。`sandbox-summary.json` 的 overall 继续为 `not_accepted`，避免将本轮局部实验算作 P0 整体验收。宿主机收尾核查位于 `.local/p0/host-cleanup-check.json`。

## 候选内核核查

固定 ProxyBridge 提交 [`cb897b017a88a142ec803c3af138b0ad75c2ae12`](https://github.com/InterceptSuite/ProxyBridge/tree/cb897b017a88a142ec803c3af138b0ad75c2ae12)。10 份审计输入已逐一核对 Git blob 与 SHA-256，见 [锁定清单](p0-candidate-lock.json)。源码仅缓存在 `.cache/p0/ProxyBridge/` 用于审计，未链接到桌面程序。

1. 上游枚举只有 HTTP、SOCKS5，没有入口本身使用 TLS 的 HTTPS 类型。参考固定版本 [ProxyBridge.h](https://github.com/InterceptSuite/ProxyBridge/blob/cb897b017a88a142ec803c3af138b0ad75c2ae12/Windows/src/ProxyBridge.h)。本轮独立上游传输提供 HTTPS 协议，但尚未连接到原生转发器。
2. 域名缓存通过观察已经返回的明文 DNS 响应建立。该过程不能代替查询外发前的 DNS 接管。见 [pb_dns.c](https://github.com/InterceptSuite/ProxyBridge/blob/cb897b017a88a142ec803c3af138b0ad75c2ae12/Windows/src/pb_dns.c) 和 [官方原理说明](https://proxybridge.interceptsuite.com/docs/windows-how-it-works/)。
3. 官方说明明确指出 HTTP 代理下 UDP 会直连，缺少代理配置时也可能直连，不能直接满足严格模式。见 [官方限制](https://proxybridge.interceptsuite.com/docs/windows-troubleshooting/)。
4. 固定源码还在激活域名规则时刷新系统 DNS 缓存，并通过独立线程维护中继防火墙规则。当前不执行其启动函数，避免把这些系统修改混入普通协议测试。
5. 尚未实测独立 WFP 阻断与 NETWORK 层重写是否相容。不能用“分别成功”推定组合后能代理，更不能只封 EXE 的 53 端口来声称系统解析器请求已受保护。[微软 ALE 说明](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)也要求考虑 IPv6 双栈及 IPv4 映射地址。

结论：当前固定候选不能原样作为严格模式内核发布；P0 的 DNS 接管和转发/阻断相容性仍是必须验证的前置条件。

## 可恢复测试包

构建命令：

```powershell
.\scripts\p0\build-lab.ps1
.\scripts\p0\prepare-sandbox.ps1
.\scripts\p0\sandbox-lab.ps1 -Action Start
# 读取本次结果后，显式停止本项目拥有的来宾：
.\scripts\p0\sandbox-lab.ps1 -Action Stop
.\scripts\p0\sandbox-lab.ps1 -Action Inspect
```

生成 `.local/p0/proxy-harbor-p0.wsb`，指向本次独立的输入包和结果目录。包中只含 Node 运行时及其许可、原生 WFP 实验工具、Go 测试二进制、通用探测及转发程序、实验脚本，不含宿主机应用、账号或配置。

Windows Sandbox 配置关闭外部联网、剪贴板、音视频、打印机和 GPU 共享。输入映射为只读，仅结果目录可回写；实验在来宾 `C:\P0Lab` 的副本中运行。来宾先验证文件摘要，再运行独立协议测试和规则实验，输出 `sandbox-summary.json`。[微软 Sandbox 配置说明](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)规定了映射、联网和来宾登录命令的行为。

首次检查没有检测到可启动的 Windows Sandbox 入口或 Hyper-V VM 管理命令；`vmcompute` 服务在运行，但这不能证明已有 Windows 测试虚拟机。用户随后明确授权检查并启用 Windows Sandbox，禁止自动重启。

管理员检查和启用已完成：`Containers-DisposableClientVM` 从 `Disabled` 变为 `Enabled`，最初返回 `RestartNeeded=true`；其他 Windows 功能没有检测到状态变化。设置记录在 `.local/p0/sandbox-setup.json`，启用前功能清单在 `.local/p0/windows-features-before.json`。用户随后手动重启 Windows，`.local/p0/resume-check.json` 已核实重启发生在启用之后、待重启标记已清除。没有自动重启。

### 本次启动故障与处理

Windows 首次启动自动安装了 Sandbox 应用 `0.8.114.0`，随后显示“Windows 沙盒无法初始化 / System.Exception”。官方 `wsb list --raw` 提供了更具体的管理连接错误：请求要求 HTTP/2，但无法建立 HTTP/2 连接。宿主用户代理已启用、没有回环绕过项；只为子进程设置显式代理与 `NO_PROXY=localhost,127.0.0.1,::1` 后，同一只读命令恢复，返回空的来宾列表。此为本机对照验证出的原因，不能仅凭通用异常推断所有同类弹窗原因。[.NET 代理说明](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy)列出了环境代理和 NO_PROXY 行为；[微软问题记录](https://github.com/microsoft/Windows-Sandbox/issues/117)也有相同通用弹窗，但不作为本机根因证据。

`sandbox-lab.ps1` 用进程级环境处理本地管理连接；只让回环地址直接访问，其他 HTTP 目标指向不可用的回环代理端口。脚本退出时还原本进程原有环境，不修改注册表、用户/机器环境变量或系统代理。Start 要求没有已有来宾，Stop 仅处理本项目记录的来宾 ID，避免采用或终止其他环境。使用 CLI 创建的本次来宾在报告取得后执行了显式 `wsb stop`，并非只关闭连接窗口。[微软 CLI 文档](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)说明了管理命令行为。

首次来宾运行还暴露了 Windows PowerShell 5.1 对未引号包围的 `-test.v` 参数的拆分，协议检查未开始，规则实验也未运行。已用仅列出测试名的命令复现，并改为 `Start-Process` 传入固定参数、分开记录 stdout/stderr 和检查退出码。重新生成的独立包内全部协议及上述阻断实验通过；失败包报告单独保留，没有被成功结果覆盖。

### 测试结束后的保留内容

本次来宾内已清理实验规则，随后停止并丢弃来宾，列表核查无运行实例。宿主机测试规则数为 0；没有安装候选驱动、服务，没有更改代理、DNS 或 IPv6 配置。Windows Sandbox 功能及其首次启动安装的应用仍保留，项目 `.local/p0/` 内的测试包、日志及报告也保留，未执行卸载或删除。

### 规则实验的准确影响范围

- 仅针对 WFP 工具同目录的 `proxy-harbor-p0-probe.exe`；工具不接受任意目标 EXE 路径。
- 只在来宾中创建一个项目专用 sublayer 和两条按完整应用身份匹配的 IPv4/IPv6 出站阻断过滤器；不修改全局 DNS、IPv6、系统代理，不安装服务或 WinDivert。
- 过滤器保留到实验清理，以验证策略命令退出后阻断仍存在。安装前写恢复记录，安装/清理使用事务。
- 清理前校验规则 GUID、所有者标记、作用路径、过滤层、动作和应用条件；只删除本实验对象。
- 校验被阻断程序不能通信，同时同名、不同路径对照程序仍能通信；最后核查规则数恢复为 0。
- 中断后可在同一来宾工作目录执行 `node.exe scripts/p0/policy-lab.mjs --cleanup`；关闭一次性测试环境会丢弃来宾状态。结果目录中的报告保留在宿主机。

## 尚未满足的 P0 条件

独立阻断及指定通用测试程序的 API 透明接管已取得离线来宾管理员回环实测证据；真实本地 HTTP 上游也已完成一次出口检查。任意应用透明接管、完整系统 DNS/辅助进程覆盖、真实公网 IPv4 保护/IPv6 与 UDP 阻断、IPv4 映射双栈、完整服务故障、其他既有连接类型和完整开机自启动顺序仍待验收。离线回环实验和一次出口查询不能替代这些验收，具体边界见 [当前进度](p0-transparent-progress.md)。

桌面程序继续保持内核不可用、保护不可开启；没有把协议测试结果写成“应用已受保护”。在 P0 获得证据并经用户确认前，不进入下一项。
