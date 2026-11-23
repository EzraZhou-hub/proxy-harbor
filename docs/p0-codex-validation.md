# P0 Codex 桌面程序首轮验证

2026-11-13：按用户要求先使用 Codex，未接触 Claude。真实 Codex 程序副本的主进程、网络服务及后台程序已经运行，部分启动请求经透明候选到达离线观察端。完整界面、登录、对话及独立防直连均未验收，桌面保护继续不可开启。

## 范围与证据

测试对象为本机已安装的 `OpenAI.Codex_26.1106.6628.0_x64__2p2nqsd0c76g0` 的程序文件副本。只读取安装产物，完整复制 `app` 目录的 3,677 个文件，没有复制账户、配置、聊天记录或其他用户数据。没有启动或改变宿主 Codex 会话。

专用实验包为 `.local/p0/sandbox/20261113-111504-81a4a8/`。输入清单包含程序和实验工具摘要，来宾逐文件核对后复制到 `C:\P0Lab`。两个映射仅为输入只读、结果可写；网络、剪贴板、音视频、打印和 vGPU 均关闭。该包是 Codex 专项包，不能替代 `.local/p0/sandbox/20261113-105143-22cf59/` 的完整协议/系统回归。

最终原始观测为 `results/window-check/codex-report.json`，汇总为 `.local/p0/codex-validation.json`。`observed` 表示完成采集，不表示应用兼容性或保护验收通过。

| 对照 | 30 秒采集结果 | 观察端请求数 |
| --- | --- | --- |
| 普通启动 | 桌面进程、窗口及 bundled `resources/codex.exe` 出现；未注入钩子 | 0（没有为本组指定代理） |
| 显式代理 | 通过进程环境及 Chromium 代理参数指定观察端；进程与窗口出现 | 35 |
| 透明候选 | 未指定应用显式代理；候选 → 项目 SOCKS5 relay/限时许可 → HTTP 观察端 | 43 |

请求数受启动重试影响，不用于比较性能或覆盖率。观察端只接收回环连接，记录方法与目标 authority，始终返回 HTTP 502，不向公网建立连接、不解密 TLS、不安装根证书。另用两个受控请求自检，确认拒绝返回且不记录测试用户名、密码、查询参数、Authorization 或 Proxy-Authorization。

透明组观察到 `chatgpt.com:443`、`api.github.com:443` 等目标。末次采集中，主进程、`network.mojom.NetworkService`、`node.mojom.NodeService` 及 `resources/codex.exe` 均加载了固定候选 DLL；GPU、renderer、storage、audio 等进程未观察到该模块。未把后者计为受保护进程，也未把模块存在当成所有接口都被接管的证明。没有逐连接的客户端 PID 归属证明；请求统计只用于这组隔离对照中的入口观测。

## 真实运行发现的限制

三组的窗口快照均只显示 OpenAI 加载图标，UI Automation 未取得可用的完整 Codex 界面。因此仅记录程序和部分联网路径能够启动，不记录“桌面正常使用”。未登录、未发送任务、未验证流式响应、工具调用或真实公网 TLS。

只读安装清单与 ASAR 均指向 `ChatGPT.exe` 桌面运行时及 Codex bootstrap。约 20 KB 的 `Codex.exe` 是依赖包身份的更新/激活 trampoline，静态检查未发现它为运行时补充产品模式参数；不能将其替换运行当作修复。未在来宾注册 MSIX、安装其服务，未改动宿主安装。

静态代码会调用 `app.setPath(userData, CODEX_ELECTRON_USER_DATA_PATH)`，但运行日志明确报告 Owl 原生阶段拒绝迟到的路径修改，实际选择各组新建的 `APPDATA\Codex\web\Codex`，对应 `Local State` 存在。不能认为该变量单独完成数据隔离。本轮同时隔离 `APPDATA`、`LOCALAPPDATA`、`CODEX_HOME`、`TEMP`、`TMP`，且整个来宾没有导入真实账户数据。

REA 的 ASAR 检查发现 8 个 unpacked native 文件与包内声明摘要不一致，原因未确定；只读证据保留了 `record-and-continue` 限制，没有修改原始文件。实验清单摘要只证明输入一致，不代表发行产物完整性审计通过。

本轮没有为 Codex 安装 WFP 规则或 AppContainer 身份，没有验证共享 Dnscache、代理退出后的独立阻断、IPv6/UDP、所有辅助程序或启动恢复。来宾断网不能代替这些验证。此前固定探针上的通过结果不能转算为 Codex 通过。

## 采集修订与清理

初次采集遇到 PowerShell 5.1 不支持 `[uint]` 别名；第一轮修订又遇到 `CopyFromScreen` 在当前来宾会话返回句柄无效。失败记录及原始输入均保留。最终改用 `[uint32]`、目标窗口 `PrintWindow` 和独立 UI 元数据采集，三组完成观测，逐组副本进程清理通过。版本化修订位于 `results/updates/window-check/`，摘要可追溯。

来宾 `286ca40e-87c4-427b-95e4-ac06c1b1ad87` 已显式停止并核对不再列出；宿主三组项目实验规则只读检查均为 `windowsError: 0`、`rulesPresent: 0`、`systemChanged: false`。没有重启宿主或来宾，没有加载候选驱动，没有增加商业依赖。

下一轮 P0 仍需先解决真实桌面完整启动/网络条件与进程覆盖，再把明确的应用身份接入来宾内独立阻断并验证入口故障；完整 DNS 共享服务覆盖依旧未验收。不进入下一项。
