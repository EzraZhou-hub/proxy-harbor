# 托盘常驻（1.2.0）

## 目的

1.1.3 及更早版本中，关闭主窗口等于退出程序。守护程序把受管会话绑定在桌面进程上（`guardian.c` 每 200 毫秒检查 `parent` 句柄），桌面进程一退出就写入 `desktop_exited` 并结束受保护的 Claude 会话。用户想“关掉界面继续保护”时无法做到。

1.2.0 起，关闭窗口只把窗口隐藏到通知区域，进程继续运行，受管会话不受影响。

## 行为

| 操作 | 1.1.3 及更早 | 1.2.0 |
| --- | --- | --- |
| 点击窗口关闭按钮 | 退出程序，守护程序结束会话（`desktop_exited`） | 窗口隐藏，进程与受保护会话继续运行 |
| 任务栏 | 窗口按钮消失 | 无窗口按钮，改为通知区域图标 |
| 再次从开始菜单打开 | 新进程（旧进程已退出） | 单实例回调唤起已隐藏的窗口，第二个进程退出 |
| 托盘左键单击/双击 | — | 显示并聚焦主窗口 |
| 托盘右键 | — | 打开菜单 |
| 彻底退出 | 关闭窗口 | 托盘菜单「退出 Proxy Harbor」 |
| 升级/卸载 | 先关闭程序 | 安装程序提示并从托盘强制关闭（见下） |

托盘菜单项：

- 「打开主界面」
- 「状态：…」（只读，每 3 秒刷新；保护中显示当前出口 IPv4）
- 「登录时启动（最小化到托盘）」（可勾选，写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，值名 `proxy-harbor`，命令带 `--tray`）
- 「退出 Proxy Harbor」

## 实现要点

- **关闭拦截**：`tray_desktop.go` 用 `window.RegisterHook(events.Common.WindowClosing, …)` 取消销毁并调用 `window.Hide()`。Wails v3 在 Windows 上先把 `WM_CLOSE` 映射为 `Windows.WindowClosing`，再由事件映射转发为 `Common.WindowClosing`；取消发生在内部“销毁窗口”监听器之前，因此窗口对象保留，隐藏后可再次显示。
- **进程常驻**：窗口对象不再销毁，`app.Run()` 的消息循环继续。守护程序观察的 `parent` 句柄仍然有效，所以不会触发 `desktop_exited`。
- **退出**：托盘菜单先置 `quitting` 标志再调用 `app.Quit()`；此时关闭钩子放行，走 Wails 的正常清理流程，守护程序按原有流程收到 `desktop_exited` 并结束会话、清理规则。
- **会话进行中的退出确认**：若状态为 `preparing` / `monitoring` / `blocking`，先显示主窗口并弹出确认对话框，说明退出会结束受保护会话；默认按钮是「继续保护」。
- **状态读取**：托盘不复用桌面绑定里的 `session.Runtime`（它的会话目录在构造时选定），改用新增的 `session.Runtime.Refresh()`，每次先重新枚举会话目录再读状态，避免长时间驻留后显示过期状态。
- **前端轮询**：窗口隐藏时通过 `tray:visibility` 事件暂停每秒一次的状态轮询，重新显示时立即补读一次，并额外监听 `visibilitychange`；这样后台驻留时不会持续对守护程序做指纹校验和会话目录读取。
- **静默启动**：登录启动项带 `--tray`，窗口以 `Hidden: true` 创建，只出现在通知区域。
- **托盘图标**：`build/tray.ico`，16/20/24/32/40/48/64 多尺寸，盾牌加横杠，青色填充配白色描边，深浅任务栏都可辨认。已用 `w32.CreateSmallHIconFromImage` 验证可被 Windows 解析为 HICON。

## 安装程序

`build/windows/nsis/project.nsi` 新增 `CheckRunning` / `un.CheckRunning`：以追加方式打开 `$INSTDIR\proxy-harbor.exe` 探测占用，被占用时提示「Proxy Harbor 仍在后台托盘运行」，确认后 `taskkill /F` 再复制文件；取消则中止安装（`SetErrorLevel 5`）。卸载流程同样先关闭再删除，并在卸载时删除登录启动的 `Run` 值。

会话仍在运行时的保护不变：`PROXY_HARBOR_REQUIRE_IDLE` 先执行 `proxy-harbor-session-inventory.exe require-empty`，有活动会话时直接中止，不会强杀守护程序。

## 验证记录（2026-11-24，本机）

- `go vet ./...`、`go test ./...` 全部通过（含新增 `TestRefreshSeesSessionsCreatedAfterStartup`）。
- 前端 `vue-tsc --noEmit`、4 项草稿回归、7 项 Playwright 界面测试通过（用重新构建的 `-tags server` 宿主，已包含新前端）。
- `wails3 build` 产出 `bin/proxy-harbor.exe`（版本信息 1.2.0）。
- 真实二进制冒烟（隔离的 `PROXY_HARBOR_DATA_DIR`）：
  - 正常启动 → 得到主窗口句柄；
  - `taskkill`（不带 `/F`，即发送 `WM_CLOSE`）→ 进程存活，主窗口句柄变为 0（已隐藏）；
  - 3 秒后进程仍存活；
  - 再次启动同名实例 → 已隐藏窗口恢复为原句柄，第二个进程自动退出；
  - `--tray` 启动 → 6 秒内进程存活且没有可见主窗口。
- 发行包：`bin\release-1.2.0\Proxy-Harbor-1.2.0-win-x64-setup.exe`（6,970,573 字节，SHA-256 `229f36d7b0eefa1de9450b8d7f626dece8683cd376116809d5ce65be05ec1c0a`，附同名 `.sha256`）。发行目录内 `proxy-harbor.exe` 版本 1.2.0，同样通过上述关闭即隐藏冒烟。
- 打包方式：`scripts/release.ps1` 因 `vcvars64.bat` 触发被本机黑名单拦截的 `reg.exe` 而无法完成原生编译，改为手工装配；守护程序使用 SHA-256 与指纹一致的 1.1.3 发行件，清单程序复用 1.1.3 发行件（其源文件自构建后未修改），NSIS 使用 3.10 便携版并以 `release.ps1` 相同的 defines 编译。
- 未验证：通知区域图标的实际显示与菜单点击、登录启动项的实际开机行为、安装与卸载流程（`CheckRunning` 的弹窗与强制关闭路径）。

## 边界

- 托盘常驻不等于“开机自启”；只有勾选「登录时启动」才会写入 Run 项，默认不写。
- 驻留期间不启动受管会话，也不做任何网络限制；保护范围仍只在会话进行中。
- 进程被任务管理器强杀时仍等价于桌面进程退出，守护程序会按 `desktop_exited` 结束会话并清理。
