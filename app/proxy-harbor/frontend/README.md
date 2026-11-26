# Proxy Harbor 前端

Vue 3、TypeScript 与 Vite 界面，通过 Wails 调用真实 Go 后端。主要入口是 [Workspace.vue](src/Workspace.vue)，涵盖连接概览、应用及域名参考、代理配置和诊断日志。

- [src/api.ts](src/api.ts) 导出 Wails 后端绑定与模型类型。
- [bindings](bindings/) 由 Wails 生成，并随源码提交。修改 Go 绑定方法或模型后运行桌面构建重生成。
- [tests](tests/) 包含 Playwright 回归。测试使用本机回环服务、隔离配置和受管状态模拟。

在当前目录可执行以下命令，Node.js 版本要求见[桌面开发说明](../README.md#开发环境)。

```powershell
npm.cmd ci
npm.cmd run check
npm.cmd run build
```

日常开发从仓库根目录运行 `scripts\dev.ps1`，由 Wails 同时启动桌面和前端。应用级回归从仓库根目录运行 `scripts\build.ps1 -Check -E2E`。Playwright 会用 Microsoft Edge 访问本机测试后端，测试主机固定在 `127.0.0.1:19345`，配置恢复用例还使用相邻的回环端口。
