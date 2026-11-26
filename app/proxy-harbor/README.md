# Proxy Harbor 桌面项目

面向 Windows x64 的 Wails 3 桌面程序。用户安装、使用和保护范围见[项目首页](../../README.md)，技术和验证记录见[文档索引](../../docs/README.md)。

## 代码入口

| 路径 | 职责 |
| --- | --- |
| [main.go](main.go)、[tray_desktop.go](tray_desktop.go) | 创建窗口、处理单实例和托盘、管理桌面进程生命周期 |
| [internal/desktop](internal/desktop/) | 暴露桌面绑定，调用配置与受管会话接口 |
| [internal/session](internal/session/) | 定位 Claude 安装、确认 v2rayN 监听者、发起守护程序以及读取会话状态 |
| [internal/core](internal/core/)、[internal/store](internal/store/) | 代理和固定出口配置、并发保存与损坏恢复 |
| [frontend](frontend/) | Vue 3 界面和 Playwright 回归 |
| [native/session](../../native/session/) | 原生守护、进程树监管、WFP 和系统 DNS 规则 |
| [build/windows/nsis](build/windows/nsis/) | Windows 安装器、会话和托盘进程检查 |

正式会话经 `DesktopService` 和 `session.Runtime` 启动，网络阻断由原生守护程序执行。`internal/engine` 还保留早期传输实验与测试。

## 开发环境

Go 版本以 [go.mod](go.mod) 为准，当前至少为 1.26。使用 Wails CLI 3.1.0、npm，以及 Node.js 20.19 或更新的 20.x 版本，或者 22.12 及以上版本。Windows 桌面需要 WebView2 Runtime。本机界面集成测试使用 Microsoft Edge。编译 C 守护程序需要 MSVC 2022 x64 工具和 Windows SDK。打包需要 NSIS。

从仓库根目录启动开发窗口。

```powershell
.\scripts\dev.ps1
```

只构建桌面界面和 Go 程序时，可以从本目录执行 `wails3 build`。桌面程序产出到 `bin\proxy-harbor.exe`。启用会话保护需要同目录内有与构建记录匹配的 `proxy-harbor-guardian.exe`。

## 构建守护与桌面

守护程序的 SHA-256 和原生源文件摘要记录在 [approved_guardian.json](internal/session/approved_guardian.json)。守护 EXE 随安装包分发。使用已有的同版发行件时，先核对守护程序 SHA-256，再将其放到本次构建的输出目录。默认是 `app\proxy-harbor\bin\`，可通过 `-BinDir` 选择其他项目内目录。

开发原生代码时，可在仓库根目录用本机 Visual Studio 的路径单独生成候选守护程序。

```powershell
.\scripts\build-guardian.ps1 -BuildClaudeDesktop -VcVars $vcVarsPath -BinDir 'bin\candidate'
```

将 `$vcVarsPath` 设为本机 `vcvars64.bat` 的完整路径。工具链或源文件变化可能产生不同的二进制指纹。通过与改动相关的验证后再更新准入记录、重建桌面程序；正式安装包需使用彼此匹配的组件。

要把 Wails 桌面程序也生成在候选目录，可从本目录执行 `wails3 build BIN_DIR=bin/candidate`。

使用匹配守护件的维护环境可从仓库根目录运行以下命令。

```powershell
.\scripts\build.ps1 -Check
.\scripts\build.ps1 -Check -E2E
```

`-Check` 执行 Go 测试和前端类型检查。`-E2E` 额外构建测试后端并执行本机回环界面测试。测试后端使用隔离数据目录，真实系统策略实验和应用测试按[开发与测试约束](../../AGENTS.md)执行。

## 打包和发布资产

`release.ps1` 从 [Windows 版本信息](build/windows/info.json) 读取版本号，核对守护指纹和原生源码摘要，再生成 NSIS 安装包。先将匹配的守护程序放到 `app\proxy-harbor\bin\release-<版本>\`，或使用脚本识别的本地配套缓存。构建脚本使用 `build-guardian.ps1` 中配置的 MSVC 路径构建会话清单程序。

```powershell
.\scripts\release.ps1
```

如果 `makensis.exe` 不在 PATH 中，可以通过 `-MakeNsis` 传指定路径。输出目录中的 `Proxy-Harbor-<版本>-win-x64-setup.exe` 与同名 `.sha256` 是 GitHub Release 的配套资产。源码提交保留源码、锁文件、生成的 Wails 绑定和验证说明；运行日志、个人配置、`bin/`、`.local/`、`.cache/` 按本地数据处理。
