# Proxy Harbor

Proxy Harbor 是面向官方 Claude Desktop 的 Windows x64 会话保护工具。它复用已有的 v2rayN，在启动前核对指定代理的公网 IPv4，运行中通过 Windows Filtering Platform（WFP）限制 Claude 主程序的联网路径并持续核验出口。

**当前版本 1.2.3** · [GitHub Releases](https://github.com/EzraZhou-hub/proxy-harbor/releases) · [开发与构建](app/proxy-harbor/README.md) · [文档索引](docs/README.md) · [MIT 许可证](LICENSE)

## 安装条件

- Windows 10 或 11 x64，当前 Windows 用户已安装官方 Claude Desktop x64（MSIX）。
- v2rayN 已配置可用节点。启动会话前切到**全局模式**、开启 **TUN**，并确认本机 HTTP 入口为 `127.0.0.1:10808`。
- 桌面界面以普通权限运行。启动受保护会话或恢复残留限制时，守护程序会请求管理员授权。
- 桌面界面需要 WebView2 Runtime。安装包附带引导程序，可在系统缺少运行时的情况下尝试安装。

## 安装、升级与卸载

在 [GitHub Releases](https://github.com/EzraZhou-hub/proxy-harbor/releases) 查看已发布的资产。1.2.3 的 Windows x64 安装包名为 `Proxy-Harbor-1.2.3-win-x64-setup.exe`。从源码打包时，安装包与同名 `.sha256` 生成在 `app/proxy-harbor/bin/release-1.2.3/`。

安装包未签名。下载安装包和校验文件后，可以用 PowerShell 对比两条命令输出的 SHA-256。

```powershell
Get-FileHash .\Proxy-Harbor-1.2.3-win-x64-setup.exe -Algorithm SHA256
Get-Content .\Proxy-Harbor-1.2.3-win-x64-setup.exe.sha256
```

运行安装包后，从开始菜单打开 Proxy Harbor。默认安装路径为 `C:\Program Files\Proxy Harbor`。

升级或卸载前，先结束受管会话，完成界面提示的恢复操作，再从托盘退出 Proxy Harbor。升级可覆盖安装。卸载会移除登录启动项，配置和历史会话记录留在数据目录。

## 开始保护会话

1. 打开 Proxy Harbor，在「连接概览」填写并保存节点的**固定公网 IPv4**。填写的是节点的出口地址，代理入口仍是界面上的本机地址 `127.0.0.1:10808`。
2. 保存 Claude 中的工作，点击「接管并重启 Claude」，允许守护程序运行。守护程序先核对代理入口、TUN 和固定出口，通过后才会关闭并用当前 Windows 用户重启 Claude。Claude 使用该账户原有的配置和登录数据。
3. 等「会话保护中」出现后继续工作。关闭 Proxy Harbor 窗口会收起到通知区域，保护继续运行。从开始菜单或托盘可以再打开窗口。
4. 使用「结束 Claude 会话」主动停止。遇到「需要恢复」时，选择「核对并恢复限制」，按提示授权，并等待清理完成。

托盘菜单提供「登录时启动（最小化到托盘）」和「退出 Proxy Harbor」。退出时若会话仍在保护，程序会要求确认，退出将结束该会话。

「代理配置」页面用于管理保存的入口。Claude 会话固定使用上面的 v2rayN 本机 HTTP 入口。

## 网络保护的范围

| 对象 | 1.2.3 的行为 |
| --- | --- |
| Claude 主程序 | WFP 阻断非回环 IPv4 TCP 直连、IPv4 UDP 和非回环 IPv6 出站。公网连接经指定的本机代理入口。 |
| 本机预览和进程间通信 | 出站规则为 `127.0.0.1`、`::1` 和 `::ffff:127.0.0.1` 保留回环例外。紧急阻断规则覆盖回环。 |
| Claude Code 子进程 | 子进程联网由 v2rayN 全局模式和 TUN 承载。守护程序优先通过 Windows Job 管理受管进程树。逐镜像的 WFP 规则覆盖 Claude 主程序。 |
| 系统 DNS | 会话期间临时限制 Windows DNS 服务的出站和传统 DNS 端口。其他应用的域名解析可能受影响，正常结束或恢复会话时会清理临时规则。 |

启动前必须通过一次完整核验，实测 IPv4 要与保存值一致。运行中约每 10 秒核验一次，每轮最多尝试两个 HTTPS 站点。首轮失败后约 1 秒补测；连续两轮失败或距上次成功核验达到 30 秒，以先发生的为准断开。测到的出口与固定值不符时立即触发阻断。

这套核验观测的是**指定代理入口的公网出口**。Claude 主程序的路径约束由 WFP 执行，出口探测按周期进行。完整 DNS/WebRTC 防泄露、实际公网 IPv6、外部浏览器回调和 Cowork 的覆盖情况仍需对应场景验证。

## 诊断与恢复

| 界面提示 | 如何处理 |
| --- | --- |
| 出口不一致 | 确认 v2rayN 使用的是预定节点。计划更换固定出口时，核实新地址后再修改保存值。 |
| 出口无法核对或核验过期 | 确认 v2rayN 的节点、全局模式、TUN 和本机 HTTP 入口正常。到「诊断与日志」查看上次通过核验的时间和停止原因。 |
| 需要恢复 | 回到「连接概览」，执行「核对并恢复限制」。 |
| 缺少匹配的守护程序 | 使用同一发行包的桌面程序和守护程序。安装版可用对应版本的安装包覆盖修复。 |

数据目录默认为 `%APPDATA%\ProxyHarbor`，启动前可通过 `PROXY_HARBOR_DATA_DIR` 指定。配置保存在 `config.json`，会话文件在 `sessions\<会话 ID>\` 下。

- `status.json` 记录会话状态、停止原因和上次通过核验的时间。
- `exit-check.json` 记录最近一轮的探测站点、耗时和错误阶段，`exit-failure.json` 保留最近一次失败。
- `takeover-containment.json` 记录进程树监管方式，`takeover-components.log` 记录采样到的子进程镜像。

「诊断与日志」可以导出报告。报告包含本机地址和应用路径，公开分享前可先删去与问题无关的本机信息。配置无法加载时，界面提供重新读取和「备份并重置配置」。

独立 Flash 数据清理也在「诊断与日志」中。关闭使用 Flash 的程序后，可按提示清除当前用户的独立 Flash 共享对象。

## 项目导航

| 位置 | 内容 |
| --- | --- |
| [桌面项目](app/proxy-harbor/README.md) | Go/Wails 桌面入口、托盘、配置、会话编排及构建说明 |
| [前端](app/proxy-harbor/frontend/README.md) | Vue 3 界面、Wails 绑定和界面回归 |
| [原生守护](native/session/) | Claude 接管、WFP 规则、固定出口核验、DNS 与恢复 |
| [构建脚本](scripts/) | 开发、编译、测试和 NSIS 打包 |
| [文档索引](docs/README.md) | 当前实现、版本记录与早期 P0 研究 |
| [开发与测试约束](AGENTS.md) | 实验授权范围和项目维护记录 |

1.2.3 通过守护规则结构、出口状态与回环超时检查，以及 Go、前端类型和 7 项隔离界面回归。开发机通过既有 v2rayN 做了一次只读探测，实测出口匹配保存值。该轮测试范围为隔离验证与只读探测，未执行本机安装或启动真实 Claude 会话。[出口核验与验证记录](docs/exit-probe-tolerance.md)

本项目采用 [MIT 许可证](LICENSE)。第三方依赖遵循各自许可证。
