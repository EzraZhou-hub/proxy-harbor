# Proxy Harbor

Proxy Harbor 1.1.2 为官方 Claude Desktop x64 安装版提供固定代理出口和会话保护。Claude 在当前 Windows 账户下接管并重启，Chrome 验证入口用于排查本机代理和 TUN。

## 安装和使用

1. 运行 `app\proxy-harbor\bin\release-1.1.2\Proxy-Harbor-1.1.2-win-x64-setup.exe`，然后从开始菜单以普通权限打开 Proxy Harbor。
2. 开启 v2rayN 全局模式和 TUN，确认本地 HTTP 代理监听 `127.0.0.1:10808`。在「连接概览」保存该节点的公网 IPv4。
3. 保存 Claude 中的工作，点击「接管并重启 Claude」，接受守护程序的管理员授权。网络限制就绪后，程序会退出已有 Claude 进程，再用当前 Windows 账户打开同一安装并沿用原有配置。
4. 点击「结束 Claude 会话」，等待自动清理。如果显示「需要恢复」，点击「核对并恢复限制」。升级或卸载前结束并清理会话。

保护覆盖 Proxy Harbor 启动的 Claude 窗口及其受管进程。会话期间系统传统 DNS 会受到临时限制，其他应用可能也会受影响。1.1.2 起，Claude 启动的同用户子程序（Code 模式的 Claude Code CLI、git、wsl、终端等）不再按镜像终止，这些进程沿用 v2rayN 全局/TUN；WFP 逐镜像固定出口只覆盖 Claude.exe 客户端本身，身份不符或组件数量超限仍会结束会话。已验证官方安装版的同账户重启、正常停止、代理和 TUN 中断以及守护崩溃恢复。按用户决定跳过了沙盒登录验证，现有 Claude 登录是否能跨重启保留仍待确认。Code 模式修复已编译并通过单元回归，真实 Code 模式待用户本机确认；外部浏览器和 Cowork 未纳入验收。

安装器未签名，发行目录提供同名 `.sha256` 校验文件。在 Windows x64 上用现有 Go、Wails、Node、MSVC 工具链及开源 NSIS 执行 `scripts\release.ps1` 可重新打包。脚本会核对守护程序 SHA-256，并生成安装包校验文件。

## Chrome 本机试用

1. 打开 Proxy Harbor，进入「本机验证」。
2. 确认 v2rayN 的全局模式和 TUN 已开启，HTTP 代理入口为 `127.0.0.1:10808`。在「连接概览」保存该节点的公网 IPv4，在「应用管理」核对 Google Chrome 程序路径。
3. 保存工作并完全退出已有 Chrome。在「本机验证」点击「启动隔离应用并保护」，接受 Windows 管理员授权，等状态显示「会话保护中」。新窗口使用临时配置。会话期间全机传统 DNS 查询会被临时限制，可能影响其他程序解析域名。
4. 试用结束时点击「结束本次应用」，等状态显示「已停止」。如显示「需要恢复」，点击「核对并恢复限制」，按提示授权并等待清理完成。

以下带日期的条目记录当时的开发与验收状态。

2026-11-16 固定出口流程已接入配置与界面，支持保存预期 IPv4，并用于启动前和运行中比对。用户管理 v2rayN 全局/TUN。当前核验代理入口的出口，逐目标路径和新增策略仍待实测，桌面保护入口关闭。见[当前需求](docs/current-requirements.md)。

2026-11-16 指定应用增强正在开发：新增临时 Chrome 用户策略配置和脱敏路由模型检查工具。原生编译及 Go 回归通过，新增 Windows 策略路径未运行，370 条记录对应此前版本。完整保证范围和剩余缺口见[指定应用设计核对](docs/p0-selected-application-design.md)。

2026-11-16 重新验收：包 `20261116-005349-93581a` 的 31 个协议顶层测试及 370 条限定来宾检查通过，包含安装版 Chrome、进程身份、真实 HTTPS、异常终止、恢复及独立清理。修复了设备发现导致启动后终止的问题。**P0 总体仍未验收，桌面保护关闭**；Defender 检测原因仍待复核。详见[最新验收记录](docs/p0-session-acceptance.md)。

2026-11-16 重测前的历史阻塞：Windows Defender 隔离原生守护候选，上一轮停在来宾输入校验阶段。原始隔离与单项复核记录保留，后续完整重测见上方最新记录。

2026-11-15 最新补测：独立普通用户身份的 Chrome 会话候选取得 31 个协议顶层测试和 320 条检查通过的限定证据，包含未登记子程序首包约束、12 个守护场景、真实 HTTPS、可见窗口、正式 Runtime 启动/停止和独立清理。按替换后的 AGENTS 约束，**P0 仍未验收，两个桌面入口保持禁用，不进入 P1**。详见 [本轮候选验证与边界](docs/p0-session-acceptance.md)。此前 98/19 原型和无身份继承的缺口记录保留为历史，见 [旧原型记录](docs/managed-session-progress.md)。

当前产品范围以 [最新需求](docs/current-requirements.md) 为准：复用 v2rayN，监控指定应用代理路径并在异常时阻断和终止；DNS/WebRTC 为可选增强，本轮使用 Chrome，暂不测试 Claude。候选已接线验证，但桌面保护未开放。

最新 P0 补测：2026-11-14 第 1、2 项的限定连接变化与异常恢复验证通过，新增 87 条检查及 382 条原有组合回归通过。仍有双网络切换、睡眠、最终 SID 重启/最早启动等未验收项，桌面保护仍不可开启。见 [本轮记录](docs/p0-lifecycle-validation.md)。

Windows 桌面应用专属代理启动器。技术栈：Go + Wails 3.1.0 + Vue 3 / TypeScript / Vite。

当前桌面交付是可运行的配置和诊断界面，**不能开启网络保护**。它不会自动启动受管应用或安装系统策略。原生候选的网络保护能力仅按限定来宾证据记录，不能视作生产验收。

## 已实现

- 连接概览、应用管理、代理配置、本机验证、诊断与日志五个页面。
- HTTP / HTTPS / SOCKS5 代理入口的新增、编辑、选择、删除及本地持久化。
- Claude、Codex 的 EXE 路径登记、文件选择和存在性检查，不执行程序。
- 读取本机平台、主机名称及活动网卡地址；不请求外部网络。
- JSON 报告导出，明确标记尚未运行的出口、DNS、IPv6、UDP 检测。
- 传输无关的控制接口、可替换内核接口、配置校验、替换写入和拒绝保护启动的后台边界。
- 桌面重复启动切回同一数据目录的已有窗口；存储层检查配置是否被其他进程更改，拒绝旧快照覆盖。
- 未保存的应用路径草稿在其他配置保存、本机信息刷新时保留。
- 配置加载失败时进入恢复页，可重新读取或打开配置目录；损坏/不兼容配置只有在用户确认并成功备份后才重置。

密码/认证、SQLite 历史、Windows 服务及 Named Pipe、托盘驻留、原生代理内核、实际泄露检测与阻断尚未接入。当前使用进程内控制实现，不冒充已经部署的独立守护服务。

## 直接运行

构建后的文件位于 `app\proxy-harbor\bin\proxy-harbor.exe`，双击即可。当前为普通权限桌面程序。

首次保存时配置写入 `%APPDATA%\ProxyHarbor\config.json`。可以在启动前通过 `PROXY_HARBOR_DATA_DIR` 指定其他目录；测试使用项目 `.local` 下的独立数据，不触碰正式配置。此位置与 Go 的 D 盘工具/依赖缓存配置相互独立。

恢复配置时，原始文件逐字节备份到同目录的 `config.backup-*.json`，界面显示具体位置。备份或重置失败时保留原配置；读取权限错误不提供重置。正常配置被外部修改后，可在“诊断与日志”重新读取配置，再继续保存。

开发阶段暂不对 Claude 做任何测试，也不启动、探测或操作其安装及用户数据。应用相关回归使用 Codex 和隔离的通用测试数据；Claude 验收留到项目最后，等待用户明确通知。约束记录于 [AGENTS.md](AGENTS.md)。

## 开发与构建

在本仓库目录使用 PowerShell：

```powershell
# 开发模式
.\scripts\dev.ps1

# 构建桌面程序
.\scripts\build.ps1

# 构建并运行核心和真实前后端集成测试
.\scripts\build.ps1 -Check -E2E
```

需 Go 1.26+、Wails CLI 3.1.0、Node.js/npm、WebView2。界面集成测试使用已安装的 Microsoft Edge（无头模式），不自动下载浏览器。未安装 Edge 时，核心测试与桌面构建仍可执行。

`-Check` 同时执行 Go 测试和前端草稿回归。草稿测试使用 Node 原生 TypeScript 加载能力，本次验证环境为 Node 24.12.0。

如果 Go 默认模块源不可达，可以在当前终端临时设置：

```powershell
$env:GOPROXY = 'https://goproxy.cn'
```

构建/测试不会自动安装驱动或注册服务。Go 缓存沿用已配置的 D 盘路径，根目录构建脚本把 npm 缓存放到项目 `.cache\npm`。

## 代码结构

```text
app/proxy-harbor/
  main.go                  桌面入口与依赖装配
  internal/domain/         配置、能力、状态及校验
  internal/control/        与传输方式无关的后台接口
  internal/core/           配置操作与启动保护边界
  internal/store/          配置读写，Windows 替换写入
  internal/engine/         内核适配接口及明确不可用的默认实现
  internal/diagnostics/    本机只读信息、待验证检测项
  internal/desktop/        Wails 绑定与原生文件选择
  frontend/src/            Vue 界面与生成绑定入口
  frontend/bindings/       自动生成的 Go/TypeScript 类型绑定
  frontend/tests/          真实 Go 后台集成测试
  build/                   Wails 构建资源，当前只验证 Windows
scripts/                   开发、构建与环境维护脚本
docs/                      计划、调研与本次交付说明
```

开源内核当前仅调研，尚未复制或链接 ProxyBridge / ProxiFyre / proxybox 代码。后续采用任何代码或二进制时逐项记录版本与许可。

下一步是 [开发计划](docs/development-plan.md) 中的 P0：在可恢复环境验证真实内核与独立防绕过策略。当前基础框架不代表 P0 已通过。详见 [基础框架交付记录](docs/scaffold-status.md)。

P0 进行中：2026-11-14 已按用户要求集中推进，限定 IPv4 批次的协议、无调试例外的 SID/WFP 隔离、DNS 缓存边界、UDP/双栈阻断、入口身份及指定真实 HTTPS 出口等阶段通过；实际公网 UDP 另取得项目过滤器丢包事件，12 条基础规则的授权来宾重启恢复检查通过。用户已选择现有 v2rayN 全局路由。最早开机、完整网络切换等 P0 边界及真实应用兼容尚未完整验收，桌面保护继续不可开启，不进入下一阶段。见 [本轮统一记录](docs/p0-batch-progress.md)、[进度与恢复点](docs/p0-transparent-progress.md)。候选审计和历史包见 [P0 验证记录](docs/p0-validation.md)。
