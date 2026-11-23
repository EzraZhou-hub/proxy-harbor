# 本机开发环境检查

## 2026-11-11：可恢复 P0 测试环境准备

用户选择在可恢复的 Windows 环境中执行系统层实验，并随后授权检查和启用 Windows Sandbox，明确禁止自动重启。

- 已通过管理员 PowerShell 查询并启用 `Containers-DisposableClientVM`，状态 `Disabled → Enabled`，系统报告需要重启。
- 启用前后没有检测到其他 Windows 功能状态变化。没有自动重启，未在宿主机添加 P0 阻断规则或加载候选驱动。
- 用户手动重启后已核实启动时间晚于功能启用，待重启标记清除，Sandbox 启动入口可用。首次启动由 Windows 自动安装 Sandbox 应用，观测版本为 `0.8.114.0`。
- Sandbox 起初因系统代理未绕过回环管理连接而初始化失败；单次子进程环境绕过后恢复。启动脚本 `scripts/p0/sandbox-lab.ps1` 不写入用户或机器代理配置。
- 离线来宾内协议测试和四种回环阻断实验通过，规则清理已核实，来宾已停止。宿主机只读核查实验规则数仍为 0，详见 [P0 验证记录](p0-validation.md)。Windows Sandbox 功能与应用仍保留，项目测试包和报告也保留；P0 整体验收尚未完成。
- 设置结果、启用前功能清单、DISM 日志保存在项目 `.local/p0/`。

## 2026-11-10 后续更新：Go 路径迁移完成

用户随后安装了 Go 1.27.3，并授权将 Go 相关目录调整至 D 盘。已完成目录准备、原配置备份、用户环境变量与用户 Path 更新，Go 配置读取验证通过。

| 配置 | 当前路径 |
| --- | --- |
| GOROOT | D:\develop\Go（原安装位置不变） |
| GOPATH | D:\develop\go-workspace |
| GOBIN | D:\develop\go-workspace\bin |
| GOMODCACHE | D:\develop\go-workspace\pkg\mod |
| GOCACHE | D:\develop\go-cache\build |
| GOTMPDIR | D:\develop\go-cache\tmp |
| GOENV | D:\develop\go-config\env |

备份：`D:\develop\go-config\backups\20261110-223140-105`。备份目录限制为当前用户、SYSTEM 和管理员访问；记录原用户环境，原 Go 配置存在时也保留副本。迁移脚本为 [migrate-go-paths.ps1](../scripts/migrate-go-paths.ps1)。

已复制的工作区/工具/模块文件采取保留源文件、避免覆盖不同目标文件的方式处理；构建缓存改为在 D 盘重新生成，不复制 Codex 的临时沙盒缓存。未清空 C 盘旧文件，未安装 Wails，未修改 Go 网络代理、Windows DNS 或 IPv6。已经运行的 Codex、终端与其他父进程不会自动获得新环境，需要重启。

以下保留的是迁移前首次检查记录，其中“Go 未检测到”等结论已由本节更新。

---

检查日期：2026-11-10。只读检查；没有安装软件、启动抓包、加载驱动或修改网络配置。

## 结论

现有 Node.js、Git、Visual Studio C++ 工具链、Windows SDK 和 WebView2 可以继续使用。准备开发主要需补 Go 和 Wails 3 CLI；NSIS 到打包阶段再补。Vue/TypeScript 等通过项目依赖安装，不需要全局安装。

## 已检测到

| 项目 | 结果 |
| --- | --- |
| 系统架构 | X64 |
| 注册表系统版本 | DisplayVersion 26H2，Build 26300.9550 |
| Node.js | v24.12.0，D:\develop\Node\node.exe |
| npm | 11.19.0，可通过 npm.cmd 调用 |
| Git | 2.49.0.windows.1 |
| Visual Studio | Community 2022，17.12.2，D:\develop\vs2022\Community |
| MSVC x64/x86 工作负载 | 已检测到，编译器目录 14.42.34433 |
| MSBuild | 可启动，17.12.6.51805 |
| CMake | Visual Studio 自带，可启动，3.29.5-msvc4 |
| Windows SDK | 10.0.22621.0、10.0.26100.0；后者 Windows.h、x64 kernel32.lib、ucrt.lib 均存在 |
| WebView2 Runtime | 157.0.4341.42 |
| Visual C++ v14 Runtime | x64/x86 14.51.36247 |
| Pktmon | 系统自带，命令存在；未运行捕获 |
| winget | 命令入口存在；未运行安装 |

MSVC、MSBuild、CMake 没在当前普通 PowerShell PATH 中，但不代表未安装。构建脚本应调用 Visual Studio 开发环境或明确路径，不必为此重装 Visual Studio，也不必把所有编译器路径写入全局 PATH。

这里验证了部分工具可启动和 SDK 文件存在，尚未执行项目编译或链接验收。

系统 CIM 查询在当前执行环境不可用。注册表 ProductName 仍显示 Windows 10 Pro，与新 Build/DisplayVersion 的命名不一致；不据此断言准确 Windows 市场名称或正式/预览通道。实际系统兼容性需在 P0 核对。

## 待添加与添加时机

| 组件 | 时机 | 说明 |
| --- | --- | --- |
| Go SDK | 开始 Go 核心开发前 | 当前 PATH、常见路径及所查安装项未检测到；Wails 3 要求 Go 1.26+，锁定的 v3.1.0 go.mod 声明 toolchain go1.26.10，安装时选择兼容工具链 |
| Wails 3 CLI | 桌面框架验证前 | 未检测到 wails3；按计划固定 v3.1.0，不使用未经锁定的 latest |
| 前端/Go 项目依赖 | 创建项目时 | 本地安装并锁定；包括 Vue、TypeScript、Vite、SQLite 的 Go 依赖等，不另装数据库服务器 |
| 原生内核与 WinDivert 文件 | P0 内核验证 | 随固定源码/构建依赖准备；加载驱动和测试规则与下载源码分开执行 |
| 本项目后台服务 | 生命周期与原生核心测试时 | 需要明确安装与清理范围，不能仅为准备开发环境就提前注册 |
| NSIS | 制作安装包时 | PATH、常见路径及所查安装项未检测到；不阻塞早期核心验证 |
| Wireshark/TShark | 可选 | 未检测到 tshark 或所查 Wireshark 安装项；可先用内置 Pktmon 留存证据，按需再补分析工具 |

常见 WinDivert、ProxyBridge、ProxiFyre、Npcap 等服务名模式未查到匹配项。这不是全盘驱动审计，不能据此推断不存在其他网络过滤组件。

无需因为本项目先安装完整新 Visual Studio、额外 Windows SDK、Docker、数据库服务、WDK 或内核驱动开发环境。若候选内核的真实构建发现额外需求，再补充对应组件。

## 依据

- [Wails 安装要求](https://wails.io/quick-start/installation/)。
- [Wails v3.1.0 的 go.mod](https://github.com/wailsapp/wails/blob/v3.1.0/v3/go.mod)。
- [WebView2 运行时检测与分发](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)。
- [Windows 内置 Pktmon](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon)。
- [ProxyBridge Windows 构建流程](https://github.com/InterceptSuite/ProxyBridge/blob/master/.github/workflows/build-windows.yml)。
