# Proxy Harbor 桌面项目

完整使用说明见 [仓库 README](../../README.md) 与 [框架交付记录](../../docs/scaffold-status.md)。

当前为基础框架，网络保护尚未实现。`bin/proxy-harbor.exe` 是可直接运行的 Windows 程序。

```powershell
# 在当前目录进行开发
wails3 dev

# 构建 Windows 桌面程序
wails3 build
```

`main.go` 装配桌面窗口和后台接口，`internal` 中的控制及配置模块独立于 Wails。未来独立服务可替换当前进程内控制实现。`frontend/bindings` 通过 `wails3 generate bindings -ts -i` 生成，不手工维护。

`build` 保留 Wails 模板的资源；本项目 Taskfile 仅启用 Windows 构建，其他平台未进行适配。
