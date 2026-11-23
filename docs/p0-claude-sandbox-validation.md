# Claude Desktop 沙盒验证

2026-11-18。测试对象为 Anthropic 官方 x64 MSIX 5.11492.5.0，以及由该签名包解出的同版本应用文件。Windows Sandbox 全新安装和卸载均有记录。宿主只通过现有 `127.0.0.1:10808` 提供限时文件中转。临时账户、sing-box TUN、应用和系统 DNS 规则均在来宾内使用。[Anthropic 下载页](https://claude.com/download) · [MSIX 部署文档](https://support.claude.com/en/articles/12622703-deploy-claude-desktop-for-windows)

| 启动方式 | 结果 | 证据 |
| --- | --- | --- |
| 已安装 MSIX，从 `WindowsApps` 启动 | Windows 安装成功。代理出口核验成功后，守护启动失败，错误为访问被拒绝（5），没有产生受管应用 PID。 | [安装版报告](../.local/p0/sandbox/20261118-012351-c1d25f/results/claude-validation.json) |
| 按官方文档预配 MSIX，从 `WindowsApps` 启动 | 预配成功。代理出口核验成功后，同样收到访问被拒绝（5）。8 项独立清理通过，包括移除预配。 | [预配版报告](../.local/p0/sandbox/20261118-012932-83e16c/results/claude-validation.json) |
| 使用同一签名 MSIX 的应用文件 | 正常启动及主动停止、代理中断、TUN 退出均通过。27 项会话检查和 7 项独立清理通过。 | [应用文件对照报告](../.local/p0/sandbox/20261118-012613-d91e73/results/claude-validation.json) |

最初使用 PowerShell 直接启动守护，被正式父进程身份校验拒绝。修正后的来宾测试启动器使用约定的 `proxy-harbor.exe` 名称及 Windows 原始进程创建时间，沿用同一冻结守护程序和 PH4 `client-user` 协议。[首轮失败报告](../.local/p0/sandbox/20261118-012112-811e9b/results/claude-validation.json)

对照组三次均看到 Claude 窗口，采样到的 6 个 Claude 进程均使用同一临时账户 SID。代理隧道记录与来宾 TCP 本地端口匹配，确认受管进程连接 `claude.ai:443` 和 `assets-proxy.anthropic.com:443`，代理返回了 CONNECT 200，随后有加密数据返回。守护程序独立核验固定 IPv4 `131.103.130.202` 和 TUN 状态。固定 IPv4 是代理探测的观测值，Claude 各目的站点看到的公网源地址未直接测量。

三个场景均核对了受管进程退出、会话规则归零和临时身份移除。代理中断的停止原因是 `exit_unverified`，从注入故障到测试启动器退出耗时 1.385 秒。来宾 TUN 退出的停止原因是 `tun_route_changed`，本轮耗时 3.115 秒。两个时间测量均包含守护收尾。

应用文件对照覆盖登录前的启动和联网。安装版的受管启动仍未通过，登录、对话、更新、Cowork 服务以及外部浏览器回调均未验证。宿主 Claude 安装和账号数据未访问，宿主规则、DNS 和代理设置未改动。各轮来宾和中转均已关闭。桌面准入保持关闭，候选 `accepted=false`，P0 未整体验收。

## 官方安装版的启动方式复核

在独立断网沙盒中，管理员安装了相同 MSIX。新建普通用户初始没有 Claude 包注册。该用户执行 `Add-AppxPackage -RegisterByFamilyName -MainPackage Claude_pzs8sxrjxfjjc` 成功。注册前后直接执行 `WindowsApps` 下的 `Claude.exe` 都返回访问被拒绝（5）。注册后从该账户通过包清单声明的 `claude-desktop.exe` 执行别名启动成功，有可见窗口，且 Windows 返回的进程包全名匹配 `Claude_5.11492.5.0_x64__pzs8sxrjxfjjc`。[离线复核结果](../.local/p0/sandbox/20261118-013737-2498fd/results/registration-probe.json) · [Microsoft 应用执行别名文档](https://learn.microsoft.com/en-us/windows/uwp/schemas/appxpackage/uapmanifestschema/element-uap5-executionalias)

该实验确认了官方安装版的 Windows 启动入口。接入守护时需要先安装本次防护规则，再从受管账户调用执行别名，核对实际应用进程的包标识和账户 SID，并验证进程及联网组件可被持续监督和终止。离线复核没有执行 PH4 联网、代理故障、登录或 Cowork 验收，桌面准入继续关闭。

## 官方安装版接入 PH4 的沙盒候选

用 `scripts/p0/prepare-claude-sandbox.ps1 -MSIXCandidate` 将待验收守护构建在本轮沙盒包内。`PH_CLAUDE_MSIX_GUEST` 仅参与独立沙盒构建，正式桌面候选及准入记录仍沿用原配置。候选在 WFP 和系统 DNS 规则就位后启动临时账户下的辅助进程，注册已安装的官方包，再通过执行别名创建挂起进程。守护核对进程及线程归属、进程创建时间、正式安装映像、包全名和账户 SID，完成 Job 归属及保护状态复核后才恢复应用线程。AppX 启动产生的进程需要时加入一个空的专用 Job。

早期集成轮次保留失败证据，包含别名路径解析失败、复用已有 Job 失败、应用最初进入监控但未完成联网，以及正式出口预检超时。补齐临时账户目录环境后，官方安装版取得了受管窗口、进程与 Job 归属、实际 HTTPS 代理隧道的证据。主动停止后，早期清理用包查询是否返回对象作判断，守护进入 `package_cleanup_pending` 并保留规则。后续改为按临时 SID 的 `Installed` 状态确认注册移除，当前来宾的原始安装注册需在每次会话结束后保留。[启动及早期清理证据](../.local/p0/sandbox/20261118-021341-01d2ce/results/claude-validation.json) · [早期清理诊断](../.local/p0/sandbox/20261118-021341-01d2ce/results/guardian-normal.stderr.log)

Windows 把管理员代为移除的临时注册标记为 `Installed(pending removal)`，并保留该账户的应用配置。候选改用本次生成的临时账户在自己的登录上下文中注销包。临时口令仅保存在守护进程内存中，清理登录后擦除。守护再次核对并结束该 SID 的剩余进程，然后退役其配置和账户，最后解除规则。来宾独立检查同时核对没有已安装或待移除的临时注册，以及来宾原有注册仍存在。[待移除失败证据](../.local/p0/sandbox/20261118-021859-a1b8cd/results/claude-validation.json)

最终冻结包 `20261118-022819-37eaac` 的三个场景各通过 13 项检查，另有 7 项独立清理通过。每次均打开官方安装版窗口，6 个采样到的 Claude 进程属于本次临时 SID，实际代理隧道同这些进程的连接端口匹配。守护确认固定出口 `131.103.130.202`。正常停止、代理中断和来宾 TUN 退出到测试启动器退出分别耗时 6.755、5.565、5.494 秒，均包含收尾。生产配置下的原生编译与 Go 回归也通过。[最终报告](../.local/p0/sandbox/20261118-022819-37eaac/results/claude-validation.json) · [冻结源码摘要](../.local/p0/sandbox/20261118-022819-37eaac/guardian-sources.json)

本轮验收范围为沙盒中的登录前窗口、代理路径和三种会话生命周期。登录、对话、Cowork 及守护崩溃后的 MSIX 注册恢复仍未验收。沙盒和限时中转均已关闭。宿主 Claude 安装、配置、账户数据和宿主系统设置均未改动。新功能仅编入沙盒候选，原正式守护文件指纹保持匹配，桌面准入继续关闭，`accepted=false`。

## 守护崩溃与免登录联合复验

旧候选的崩溃对照先确认官方安装版窗口和 HTTPS 连接，再按已核对路径、PID 及创建时间结束来宾守护程序。Claude 进程随之退出，独立监督解除了临时 DNS 规则，应用和代理入口规则仍保留 14 条。显式恢复时，临时 Claude 注册仍为 `Installed`，恢复拒绝解除规则，整轮保留失败。[崩溃基线报告](../.local/p0/sandbox/20261118-030715-c79c9c/results/claude-validation.json)

修复后的沙盒候选在明确发起恢复时核对临时账户记录、SID 和会话规则。确认该 SID 无存活进程、且注册仍存在后，先加装临时身份的出站全阻断，再为该临时账户签发新的随机口令以移除其自身 MSIX 注册。口令只用于该次清理，不落盘。恢复路径不启动 Claude。移除注册后复查该 SID 的进程并退役配置和账户，最后解除会话规则。无法确认归属或清理状态时保留阻断。该路径只编入沙盒候选。[Windows 本地账户口令操作文档](https://learn.microsoft.com/windows/win32/netmgmt/changing-elements-of-user-information)

修复后使用同一守护二进制取得 56 项通过检查。正常停止与代理中断各 13 项，守护崩溃及显式恢复 17 项，TUN 退出补测 13 项。崩溃轮次从结束守护到已采样的应用进程全部退出为 292 毫秒。守护退出后剩余 14 条会话规则，独立恢复成功后归零，临时 MSIX 注册和账户消失，来宾原有注册保留。代理中断和 TUN 退出到启动器结束分别为 5.453 和 6.812 秒，包含清理。[正常、代理与崩溃恢复证据](../.local/p0/sandbox/20261118-031426-3b713b/results/claude-validation.json) · [TUN 独立补测](../.local/p0/sandbox/20261118-031833-909602/results/claude-validation.json)

原联合批次第四项在启动前发生固定出口探测超时，守护拒绝启动，批次仍记失败。TUN 补测使用相同二进制，并通过 7 项独立清理。更早一次联合尝试因来宾共享报告被读取占用而提前结束。已为测试报告加上限时写入重试。[联合批次原始记录](../.local/p0/sandbox/20261118-031426-3b713b/results/claude-validation.json) · [报告写入中断记录](../.local/p0/sandbox/20261118-031135-6c131d/results/claude-validation.json)

本轮覆盖单个守护进程崩溃和之后的显式恢复。登录、对话、Cowork 与守护和独立监督同时中断的场景未纳入本轮。常规原生构建和 Go 回归通过，桌面准入仍关闭。
