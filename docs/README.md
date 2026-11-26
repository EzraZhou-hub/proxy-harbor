# 项目文档

[项目首页](../README.md)提供安装、固定出口设置和故障恢复步骤。[桌面开发说明](../app/proxy-harbor/README.md)提供代码入口、构建和打包流程。

## 当前实现与版本

| 主题 | 记录 |
| --- | --- |
| 现有功能与保护范围 | [当前需求与实现范围](current-requirements.md) |
| 1.2.3 / 1.2.2 固定出口与超时策略 | [出口核验、补测和验证结果](exit-probe-tolerance.md) |
| 1.2.1 本地预览 | [回环例外与 WFP 边界](loopback-preview-fix.md) |
| 1.2.0 托盘与窗口生命周期 | [托盘常驻和登录启动](tray-residency.md) |
| 1.1.3 Code 模式 | [Job 对象与子进程监管](claude-code-mode-supervision.md) |
| 1.1.2 Code 模式 | [子进程权限问题与修复](claude-code-mode-fix.md) |

## 早期研究与验证

下表保留 P0 各阶段使用的设计、证据和局限。版本状态以各文档的日期和验证环境为准。文中 `.local/`、`.cache/` 和 `bin/` 引用是本地证据或构建产物，GitHub 源码检出只包含 Markdown 汇总。

| 主题 | 记录 |
| --- | --- |
| 项目起步 | [开发计划](development-plan.md)、[环境检查](environment-check.md)、[桌面框架](scaffold-status.md)、[网络诊断调研](network-diagnostics-research.md) |
| 会话与 TUN | [守护原型](managed-session-progress.md)、[指定应用设计](p0-selected-application-design.md)、[Chrome 候选验收](p0-session-acceptance.md)、[真实代理 / TUN / DNS 联合验证](p0-tun-dns-validation.md) |
| 传输与独立阻断 | [P0 传输验证](p0-validation.md)、[透明接管进度](p0-transparent-progress.md)、[公网入口检查](p0-public-validation.md)、[受控转发](p0-relay-validation.md)、[转发许可与撤销调研](p0-cage-transport.md) |
| DNS 与辅助进程 | [系统 DNS 会话限制](p0-system-dns-session.md)、[DNS 覆盖](p0-dns-coverage.md)、[DNS 隔离](p0-dns-isolation.md)、[子孙进程与异步 DNS](p0-child-validation.md)、[辅助程序与重启恢复](p0-helper-dns-recovery.md) |
| 生命周期与集中回归 | [连接变化及异常恢复](p0-lifecycle-validation.md)、[集中实现与验证](p0-batch-progress.md) |
| Claude 专项 | [Claude 沙盒验证](p0-claude-sandbox-validation.md)、[Claude 域名与 DNS](p0-claude-domain-audit.md) |
| Codex 与 Edge 专项 | [Codex 首轮](p0-codex-validation.md)、[Codex 真实联网](p0-codex-real-proxy.md)、[Codex 人工登录阶段](p0-codex-manual-login.md)、[Edge 实际联网](p0-edge-validation.md) |
