# P0：受控转发、DNS 传输与持续阻断

日期：2026-11-11。**本轮实验通过，P0 整体仍未验收。** 桌面程序继续使用不可用内核适配器，尚不能开启应用保护。

系统规则实验全部在离线 Windows Sandbox 内使用项目自建测试程序执行。没有启动、探测或操作 Claude，没有加载第三方驱动，没有在开发机添加实验规则。

## 实现与路径

`internal/engine/relay.go` 提供只绑定 `127.0.0.1` 的 SOCKS5 CONNECT 入口，后接 HTTP、HTTPS 或 SOCKS5 上游。目标域名原样交给上游，没有系统解析或直连补救分支。拒绝 BIND、UDP ASSOCIATE、IPv6 目标和无效请求；提供握手超时、连接数量上限及取消清理。TCP 半关闭后仍保留反方向响应。

`internal/engine/dns.go` 把 DNS 消息经指定代理发给指定 TCP 解析器。校验长度、事务 ID、问题及响应类型，保留 NXDOMAIN 等否定答复，拒绝截断或不匹配的响应；超时或上游失败直接报错。它不接管 Windows DNS Client，也没有修改系统 DNS。

实验实际路径为：通用测试程序 → 指定回环 SOCKS5 入口 → HTTP/HTTPS/SOCKS5 模拟上游 → TCP 或 DNS 模拟服务。

域名与 DNS 消息采用 `.invalid` 测试名称。TLS 证书只在来宾临时目录生成、仅被测试进程信任，没有安装到 Windows 证书存储。认证使用内存及子进程环境中的固定测试值，不写入配置或命令行。

## 独立限制

`native/p0/wfp_lab.c` 增加编译目标 `p0-relay-guard.exe`，只能操作同目录 `proxy-harbor-p0-probe.exe` 的完整应用身份。安装参数只接受实验入口端口。

在 ALE_AUTH_CONNECT 层对该身份建立四条持久阻断过滤器：

| 条件 | 动作 |
| --- | --- |
| IPv4，目标不是 `127.0.0.1` | 阻断 |
| IPv4，协议不是 TCP | 阻断 |
| IPv4，端口不是本次入口端口 | 阻断 |
| IPv6 | 全部阻断 |

只有指定 IPv4 回环 TCP 入口不匹配本项目的阻断条件。没有添加可覆盖其他策略的强制允许规则，也没有笼统排除所有回环或局域网通信。

专用 sublayer 为 `78c0ad13-2bd0-47bd-b5ec-0132d73b3e8c`，过滤器为 `c7abcf41` 至 `c7abcf44`，完整 GUID 写入恢复记录。修改使用事务；清理前校验所有者、路径标记、过滤层、动作、持久标记及各项条件，并逐字节比对真实应用身份。不只凭名称删除规则，不重置防火墙。

## 实测结果

最终包：`.local/p0/sandbox/20261111-030521-5adcf8/`。输入 11 个文件均有 SHA-256 清单。系统测试还要求 `p0system` 构建标签、来宾环境标记及工作目录恰为 `C:\P0Lab`，防止误运行到开发机。

| 验证 | 结果及边界 |
| --- | --- |
| 完整代理链路 | 三种上游各无认证/有认证，共 6 组通过；目标程序始终处于持久限制之下 |
| DNS 消息链路 | 同样 6 组通过；消息字节完整，解析器域名传至上游；不代表系统 DNS 已接管 |
| 其他连接阻断 | TCP4/TCP6/UDP4/UDP6 回环端点均被阻断，无法绕过本地入口直接连接上游 |
| 协议例外边界 | UDP 即使使用与入口相同的端口，也仍被阻断 |
| 已有连接 | 规则安装前建立的 TCP4 回环直连，安装后发送失败；其他已有连接类型仍待验证 |
| 其他程序 | 同名、不同完整路径的对照程序继续正常通信 |
| 上游故障 | 关闭模拟上游后代理请求失败，目标直连继续被阻断 |
| 转发进程故障 | 强制终止测试转发进程后，四类新建直连继续被阻断 |
| 清理与恢复 | 每组删除规则并核查为 0，随后目标四类回环通信恢复 |
| 流式完整性 | HTTP/HTTPS 实际套接字中，客户端发送 64 KiB 并半关闭后仍完整接收尾部响应 |

`relay-policy-report.json` 有 **6 组场景、168 条具名观测**，全部通过；不是 168 种独立应用兼容性测试。协议日志有 **19 个顶层测试通过**。原有两条全阻断过滤器的实验也重新通过。

证据文件均在该包的 `results/`：

- `upstream-tests.log`：协议、DNS 边界、握手与流式测试。
- `relay-policy-tests.log`、`relay-policy-report.json`：完整链路、已有连接及故障观测。
- `policy-report.json`：原有四种回环全阻断实验。
- `recovery.json`、`relay-recovery.json`：规则归属、二进制摘要及恢复命令。
- `sandbox-summary.json`：各检查通过，总体继续为 `not_accepted`。

普通 Go 全量测试及 `go vet ./...` 通过，前端未修改。来宾已显式停止、沙盒列表为空，宿主机两组专用规则均为 0，记录在 `.local/p0/host-cleanup-check.json`。Windows Sandbox 功能和项目报告继续保留。

## 透明转发与第二候选

本轮需要测试客户端明确连接本地入口，不能声称任意程序已被透明接管。[WinDivert 文档](https://reqrypt.org/windivert-doc.html)列明：NETWORK 层有包数据但没有进程 ID，SOCKET 层能识别进程并阻断，却不能注入修改后的连接事件。微软的[连接重定向接口](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)涉及相应 callout 驱动，当前没有开发或加载它。

对照候选 ProxiFyre 固定为 `5e3bc845d73a47a0931b1233c745580cb916f4ba`（2.6.4），4 个审计输入的 Git blob 和 SHA-256 均已核对，见 [锁定清单](p0-alternative-lock.json)。只缓存源码用于审计，没有集成、编译或运行：

- [该版 README](https://github.com/wiresock/proxifyre/blob/5e3bc845d73a47a0931b1233c745580cb916f4ba/README.md)仍说明 IPv6 分片可能直接通过；普通权限模式下归属不明流量保持直连。
- [路由策略源码](https://github.com/wiresock/proxifyre/blob/5e3bc845d73a47a0931b1233c745580cb916f4ba/netlib/src/proxy/process_routing_policy.h)保留相应兼容模式分支。
- [LICENSE](https://github.com/wiresock/proxifyre/blob/5e3bc845d73a47a0931b1233c745580cb916f4ba/LICENSE)为 AGPL-3.0，未将该代码复制到本应用实现，未改变本项目许可。

这些证据不足以把第二候选原样作为严格模式发布，仍需解决其与持续阻断及 DNS 的组合。

## 尚未完成

任意受管程序的透明重定向及其与独立阻断的组合、系统解析器及辅助进程 DNS 覆盖、公网 IPv4/IPv6/UDP、IPv4 映射双栈、完整服务故障、启动/重启顺序、真实代理出口仍未验收。

入口进程身份绑定、端口被其他程序重新占用、登录回调和必要本地通信也未验证。当前只限制一个入口端口，不把“端口相同”当作“进程可信”。上述条件通过前，桌面保护保持不可开启，只继续推进 P0。
