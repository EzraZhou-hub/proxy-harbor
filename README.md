# Proxy Harbor

Windows x64 桌面工具，为官方 Claude Desktop 提供**固定代理出口**和**会话保护**。

它在当前 Windows 账户下接管并重启 Claude Desktop，启动前核对 v2rayN 的本地代理入口、TUN 和公网 IPv4 出口，运行中持续核验；一旦代理、TUN、出口或守护程序异常，先阻断网络再结束受管进程树。

当前版本：**1.1.2** · [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 功能特性

- **固定出口接管**：自动识别当前账户注册的官方 Claude Desktop x64（MSIX），退出已有进程后用同一账户重新启动，沿用原有配置和登录状态。
- **启动前核验**：确认 `127.0.0.1:10808` 由 v2rayN 内核监听、TUN 默认路由生效、经代理观测的公网 IPv4 与保存值一致，任一不符则拒绝启动。
- **运行中核验**：约每 10 秒经指定代理查询公网 IPv4；出口变化、查询失败、代理进程退出、TUN 路由改变、WFP 规则被修改都会触发断开。
- **进程约束**：受管 Claude 的客户端镜像由 WFP 限定为仅允许 TCP 连接 `127.0.0.1:10808`，阻断 IPv6、UDP、其他地址/端口及非回环入站。
- **可恢复**：异常结束后保留会话记录，可在界面执行「核对并恢复限制」，逐项清理规则、DNS 限制和临时记录。
- **Chrome 本机验证**：用独立临时配置启动 Chrome，快速验证当前代理、TUN 和固定出口是否可用。
- **诊断**：会话目录记录状态、出口观测、被放行/阻断的子程序镜像，便于排查兼容性问题。

## 工作原理

```text
Proxy Harbor（普通权限）
   └─ 管理员授权 ──> proxy-harbor-guardian.exe（守护程序）
                        ├─ 核对 v2rayN 监听进程、TUN、公网 IPv4
                        ├─ 安装 WFP 规则 + 临时限制系统传统 DNS
                        ├─ 退出已有 Claude，用当前用户重启 MSIX 版
                        ├─ 周期核验出口 / 规则 / TUN / 代理进程
                        └─ 异常：紧急阻断 → 结束进程树 → 保留恢复记录
```

Claude 的流量路径：`Claude.exe → 127.0.0.1:10808（v2rayN）→ 远程节点 → 目标`。

## 系统要求

- Windows 10 / 11 x64
- 官方 Claude Desktop x64 安装版（MSIX，安装到 `C:\Program Files\WindowsApps`）
- v2rayN，开启**全局模式**和 **TUN**，本地 HTTP 代理监听 `127.0.0.1:10808`
- 启动和恢复时需要 Windows 管理员授权（UAC）
- 安装程序自带 WebView2 引导；系统缺少时会自动安装

## 安装

1. 运行 `app\proxy-harbor\bin\release-1.1.2\Proxy-Harbor-1.1.2-win-x64-setup.exe`。
2. 安装到 `C:\Program Files\Proxy Harbor`，从开始菜单以**普通权限**打开 Proxy Harbor。
3. 安装器未签名；发行目录提供同名 `.sha256`，可用 `Get-FileHash` 校验：

```powershell
Get-FileHash .\Proxy-Harbor-1.1.2-win-x64-setup.exe -Algorithm SHA256
Get-Content .\Proxy-Harbor-1.1.2-win-x64-setup.exe.sha256
```

## 使用方法

### 1. 准备

1. 启动 v2rayN，切到**全局模式**并开启 **TUN**，确认 HTTP 代理为 `127.0.0.1:10808`。
2. 打开 Proxy Harbor，进入「连接概览」。
3. 点击「配置固定出口」，填写该节点的**公网 IPv4**（在 v2rayN 或 IP 查询网站确认），点「保存出口 IP」。

### 2. 启动保护

1. 在 Claude 中保存工作并退出正在运行的对话（程序会强制退出已有 Claude 进程）。
2. 在「连接概览」点击「接管并重启 Claude」。
3. 在 UAC 提示中允许守护程序运行。
4. 等待状态变为「会话保护中」；Claude 会以当前账户重新打开，沿用原有配置，登录状态通常保留（如被登出需重新登录）。

启动失败的常见原因会直接显示在状态区，例如代理入口不符、TUN 未就绪、固定出口不一致、管理员授权被取消。

### 3. 结束与恢复

- 正常结束：点击「结束 Claude 会话」，等待状态显示「已停止」，规则和 DNS 限制会自动清理。
- 异常或残留：状态显示「需要恢复」时，点击「核对并恢复限制」并按提示授权。

### 4. Chrome 本机验证（可选）

1. 在「应用管理」核对 Google Chrome 路径。
2. 保存工作并完全退出已有 Chrome。
3. 在「本机验证」点击「启动隔离应用并保护」，等状态变为「会话保护中」。
4. 结束用「结束本次应用」。

Chrome 使用临时配置目录，不读取或修改日常浏览数据；会话期间全机传统 DNS 查询会被临时限制。

## Code 模式说明（1.1.2 起）

Claude Desktop 的 Code / Cowork 会启动不同镜像的子程序（`cowork-svc.exe`、`claude-ssh-*.exe`、Claude Code CLI、`git.exe`、`wsl.exe`、终端等）。1.1.2 起：

- 与 Claude 同属当前 Windows 账户的子进程不再按镜像终止，镜像会记录到会话目录的 `takeover-components.log`。
- 逐镜像的 WFP 固定出口仍只覆盖 `Claude.exe` 客户端本身；Code 模式的后代进程沿用 v2rayN 全局/TUN。
- 子进程身份无法核对（不同账户）或组件数量超限时，会话仍会结束。
- **使用 Code 模式时必须保持 TUN 开启**；两次出口核验之间（约 10 秒）后代进程的直连不会被单独的 WFP 规则拦截。

## 保护范围与已知限制

- 保护对象是 Proxy Harbor 启动的 Claude 窗口及其受管进程，不覆盖系统中其他程序。
- 会话期间全机传统 DNS 查询会被临时限制，其他应用解析域名可能受影响。
- 外部浏览器回调（OAuth 等）和 Cowork 未纳入本轮验收。
- 守护程序以管理员权限运行，但只操作本会话拥有的 WFP 规则、临时 DNS 限制和会话记录；不读取 v2rayN 节点配置或凭据，不修改系统代理设置。
- 固定出口核验针对指定代理入口，不能据此宣称每条连接的公网源 IP 都已逐条观测。

## 配置与数据位置

| 内容 | 位置 |
| --- | --- |
| 配置（代理、应用路径、固定出口） | `%APPDATA%\ProxyHarbor\config.json` |
| 会话记录与诊断 | `%APPDATA%\ProxyHarbor\sessions\<会话ID>\` |
| 自定义数据目录 | 启动前设置环境变量 `PROXY_HARBOR_DATA_DIR` |

会话目录中常用文件：`status.json`（状态与原因）、`exit-check.json`（最近出口观测）、`takeover-components.log`（被放行的子程序镜像）、`takeover-component.json`（最后一次阻断记录）、`component-check.json`（组件核对失败详情）。

配置损坏时可从恢复页重新读取；重置前会逐字节备份为 `config.backup-*.json`。

## 升级与卸载

- **升级**：先「结束 Claude 会话」并完全退出 Proxy Harbor，再运行新版本安装包原地覆盖；配置和历史记录保留。
- **卸载**：同样要求没有进行中的会话；卸载不会删除 `%APPDATA%\ProxyHarbor` 中的配置。
- 覆盖安装或卸载前若有遗留会话，安装程序会拒绝并提示先停止或恢复。

## 从源码构建

需要 Go 1.26+、Wails CLI 3.1.0、Node.js、WebView2、MSVC 2022（原生守护程序）；打包还需要 NSIS。

```powershell
# 开发模式
.\scripts\dev.ps1

# 构建桌面程序（bin\proxy-harbor.exe）
.\scripts\build.ps1

# 构建并运行 Go 测试、前端回归和界面集成测试
.\scripts\build.ps1 -Check -E2E

# 生成安装包（校验守护程序指纹并输出 SHA-256）
.\scripts\release.ps1
```

模块代理不可达时可临时设置：

```powershell
$env:GOPROXY = 'https://goproxy.cn'
```

原生守护程序由 `scripts\build-guardian.ps1` 编译，其 SHA-256 与源码哈希固定在 `app\proxy-harbor\internal\session\approved_guardian.json`。修改 `native\session\*.c` 后必须重新编译并更新该文件，否则桌面程序会以“缺少匹配的守护程序”拒绝启动。

## 目录结构

```text
app/proxy-harbor/
  main.go                    桌面入口与依赖装配
  internal/domain/           配置、状态、校验
  internal/core/             配置操作与启动保护边界
  internal/session/          会话生命周期、守护指纹准入
  internal/store/            配置读写与恢复
  internal/engine/           内核适配与诊断
  internal/desktop/          Wails 绑定与文件选择
  frontend/src/              Vue 3 界面（连接概览、应用管理、代理配置、本机验证、诊断）
native/session/              守护程序、Claude 接管、DNS/TCP 核验（C）
native/p0/                   P0 阶段系统实验代码
scripts/                     开发、构建、发布与 P0 实验脚本
docs/                        需求、设计与验收记录
```

## 常见问题

**「缺少匹配的守护程序，请核对桌面构建」**
`proxy-harbor.exe` 内嵌的守护指纹与实际 `proxy-harbor-guardian.exe` 不一致。通常是只替换了其中一个文件，或用了不同版本的文件，重装同一版本安装包即可。

**「请先结束或恢复当前会话」**
存在未清理的会话记录。回到「连接概览」结束会话；显示「需要恢复」时先执行「核对并恢复限制」。

**启动时提示出口不一致 / 无法核对**
节点公网 IP 变了或代理不可用。确认 v2rayN 全局 + TUN 正常、IP 查询可用后，重新保存固定出口。

**Code 模式打不开或子程序报权限错误**
先确认使用的是 1.1.2 及以上版本，再查看会话目录的 `takeover-components.log` 是否记录了对应镜像；若仍失败，把该日志和 `%LOCALAPPDATA%\Claude\logs\main.log` 的相关片段一并留存。

**会话结束后其他程序短暂无法解析域名**
系统传统 DNS 限制正在恢复。等待状态变为「已停止」；若长时间未恢复，执行「核对并恢复限制」。

## 文档

- [当前需求与实现范围](docs/current-requirements.md)
- [Code 模式子进程问题定位与修复](docs/claude-code-mode-fix.md)
- [守护程序会话验收记录](docs/p0-session-acceptance.md)
- [指定应用设计与边界](docs/p0-selected-application-design.md)
- [开发约束与历次实验记录](AGENTS.md)

## 状态说明

1.1.2 的安装、Claude 同账户接管、正常停止、代理/TUN 中断和守护崩溃恢复已在受控环境验证；Code 模式子进程策略已编译并通过单元回归，真实 Code 模式使用需在本机确认。更早的 P0 系统实验范围（完整 DNS/WebRTC、全部组件、跨重启等）未整体验收，相关结论以 `docs/` 中的记录为准。

## 许可证

本项目采用 [MIT 许可证](LICENSE)。可以自由使用、修改、分发和商用，只需保留版权声明与许可文本。

第三方依赖（Go、Wails、Vue、Node.js、NSIS 等）仍遵循各自的开源许可证。安装包未签名，分发时请附带同名校验文件。

