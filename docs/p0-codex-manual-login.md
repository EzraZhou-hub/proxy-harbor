# P0 Codex 人工登录会话

2026-11-13：人工登录专用包为 `.local/p0/sandbox/20261113-141653-a9073b/`，来宾 ID `7be5f592-90ef-4de4-ab5f-ac45d94875ba`。本阶段使用显式代理验证登录和基本对话，不计作透明接管或独立阻断验收，桌面保护仍不可开启。

## 已完成的前置检查

来宾网卡仍关闭，宿主通道只连接 `127.0.0.1:10808`，没有对外监听或修改宿主网络。来宾浏览器通过真实代理获取固定 HTTPS 出口响应，观测 IPv4 为 `131.103.130.202`；同一浏览器还能绕过代理访问来宾随机回环端口上的固定测试页面。后者只证明浏览器回环可达，不代表实际 OAuth 回调已成功。

仅在来宾用户下配置了 Internet Settings 和 Edge 的固定代理/回环例外。配置依据 [Edge ProxySettings 官方说明](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/proxysettings) 与 [代理回环规则](https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge-proxy-support)。[OpenAI 官方登录说明](https://learn.chatgpt.com/docs/auth) 指出桌面客户端由浏览器完成登录；本轮让用户在来宾浏览器操作，没有复制宿主认证文件或改用 API 密钥。

原始检查文件位于 `results/manual/`：`state.json`、`public-preflight.html`、`loopback-preflight.html`、`callback-fixture.jsonl`。HTML 仅来自登录前固定公网 IP/回环测试页面，不包含登录页面。

## 等待用户操作

程序已使用新建的来宾私有数据目录启动，专用沙盒查看窗口已经打开。请只在这个 Windows 沙盒中点击“Continue to sign in／继续登录”，手动登录现有账号，返回客户端选择 Codex，再发送“只回复：测试成功”。完成后在当前聊天中报告结果；不发送密码或验证码。

本轮没有安装系统阻断规则。宿主和来宾通道的活动许可为 300 秒，使用单调时钟，到期关闭，不自动续期；来宾窗口和私有数据保留，等待用户报告，不因到期推断登录成功或失败。原始当前状态以 `results/manual/state.json` 为准，主进度汇总为 `.local/p0/codex-login-session.json`。

从人工登录阶段开始不采集截图、UI 文本、应用 stdout/stderr 或认证文件。应用自己的正常数据和日志留在来宾私有目录，没有映射回宿主。后续只根据用户报告与明确授权范围继续验证。测试完成后再停止项目来宾；不要把此前已停止的实验包记录当成本会话的清理证明。

## 登录页打不开后的恢复

用户报告登录页无法打开。只读检查确认 Edge 已由测试程序启动，后台在来宾 `127.0.0.1:1455` 监听，代理设置仍指向测试端口。没有读取命令行中的授权网址、浏览器页面或账户文件。

首次宿主通道记录 `reason: byte_limit`，总计 69,721,580 字节，低于全局 256 MiB 上限；触发的是单连接 32 MiB 限额，旧实现错误地关闭了整个通道。现改为只关闭超限连接，全局限额仍保留。没有根据字节数推断下载对象或登录是否完成。

显式恢复轮次为 `c104f689`，新通道目录 `results/proxy-bridge-c104f689/`，复用来宾端口 49670，保留现有应用/浏览器窗口，单次 300 秒，不自动续期。版本化脚本及摘要保存在 `results/updates/bridge-c104f689/` 与包根 `bridge-recovery.json`；原始输入和首次失败日志保留。恢复后固定 HTTPS/证书检查再次通过，见 `results/manual/recovery-https-check.json`。

已请用户取消原登录后重新发起，并只报告错误文字；实际登录页和账户认证结果继续等待用户反馈。原始 `state.json` 的 network_permission_expired 只对应第一轮许可，不代表恢复轮次的网络状态；恢复轮次以对应 host-bridge-c104f689.jsonl 与元数据为准。

## 人工时长调整

用户随后报告登录页曾打开，稍后又无法访问。`c104f689` 的日志明确为 `lease_expired`，107 条连接、15,504,502 字节；本次没有触发字节上限。此前把五分钟自动检查许可用于人工流程，造成中断。

已显式恢复 `f1ff11e1` 轮，人工临时通道改为单次 900 秒、不自动续期，复用原回环端口和当前窗口；正式 `TransportGate` 的最大许可未改。活动并发和队列/字节限制保留，人工轮的累计连接上限限定为 1,024。就绪超时仅用于等待阶段，活动许可单独计时。

新增 `scripts/p0/recover-codex-login.ps1`，验证项目来宾、映射与人工包标记，保留每轮脚本摘要和诊断文件，拒绝覆盖仍活跃的通道。首次恢复检查早于监听就绪，保留入口拒绝失败；补齐就绪等待后，已在同一轮监听建立后重试，固定 HTTPS/证书检查通过，见 `results/manual/recovery-f1ff11e1-https-retry.json`。没有额外重开许可，也未更改账户/浏览器窗口。

当前最新轮次以 `host-bridge-f1ff11e1.jsonl`、`bridge-recovery-f1ff11e1.json` 及 `.local/p0/codex-login-session.json` 为准。已请用户取消旧登录后从程序重新开始，实际认证与对话仍等待用户报告；人工期间继续不采集页面、截图、应用日志或账户文件。
