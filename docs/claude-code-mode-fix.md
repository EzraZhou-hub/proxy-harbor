# Claude Code 模式子进程权限问题的定位与修复（1.1.2）

2026-11-23。用户报告经 Proxy Harbor 接管打开 Claude 后，桌面端 Code 模式无法正常打开，表现为子程序权限错误。本轮改动只涉及本机接管后的子进程策略与一条入站规则，未修改代理内核、未自动启动 Claude。

## 现象与证据

- 正式会话目录 `%APPDATA%\ProxyHarbor\sessions\*` 的 `takeover-component.json` 在 11-19 至 11-23 的每一次接管中都只有一条记录：`{"image":"reg.exe","reason":"child_blocked"}`。
- 2026-11-23 受保护会话期间 `%LOCALAPPDATA%\Claude\logs\main.log` 反复出现：
  - `Claude Code process exited with code 5`（`errorClass: process_exited_nonzero`, `exitCode: 5`）；
  - `Git command failed: git --version { code: 5 }`、`[GitStatusService] Failed ... D:\Git\cmd\git.exe exited with code 5`；
  - `[cli-spawn-host] no job object for pid ...: AssignProcessToJobObject(...): 拒绝访问。(0x80070005)`。
- `ssh.log` 同时记录 `[wslDistros] wsl.exe --list exited 5`。
- 对照：同一天 09:38 结束保护后，09:39 直接启动的 Claude 记录 `[cli-spawn-host] started pid 13324 in 10ms, in a job`，随后 `[CCD start-wait] ... ended_by=init` 初始化成功。同一功能在保护会话内失败、在非保护会话内成功。

退出码 5 是 `ERROR_ACCESS_DENIED`，与监督程序终止子进程时使用的退出码一致。

## 根因

`native/session/claude_takeover.c` 以 `DEBUG_PROCESS` 启动 Claude，并在 `CREATE_PROCESS_DEBUG_EVENT` 中核对子进程镜像：只要原生镜像路径不等于 `...\app\Claude.exe`，就挂起初始线程并以 `ERROR_ACCESS_DENIED` 终止。

Claude Desktop 6.28899.x 的 Code/Cowork 需要启动不同镜像的组件，包括包内 `resources\cowork-svc.exe`、`claude-ssh-broker.exe`、`claude-ssh-proxy.exe`、`claude-ssh-askpass.exe`、`claude-make-data-folder.exe`、`chrome-native-host.exe`，以及 Claude Code CLI、`git.exe`、`wsl.exe`、控制台宿主等用户工具。它们全部被该策略在启动瞬间杀死，Claude 侧看到的即为子程序权限失败。

## 修改

1. `native/session/claude_takeover.c`
   - 同一会话用户 SID 的后代不再按镜像终止；其镜像记入会话目录的 `takeover-components.log`（上限 64 KiB，超出后停止追加）。
   - 仍要求子进程属于会话用户：无法读取令牌、用户 SID 不符，或 256 个跟踪槽位耗尽时结束会话。
   - 已退出的子进程不再按“无法核对身份”处理，避免短命程序（`reg.exe`、`git --version`）造成误判。
   - `takeover-component.json` 改为覆盖写入最后一次阻断记录；旧实现使用 `CREATE_NEW`，只能留下第一条。
2. `native/session/guardian.c`
   - 当前 Windows 用户接管模式下，入站阻断规则恢复 `127.0.0.1` 例外：外部入站仍阻断，本机回环可连接到客户端，供 Code 模式的本地桥和 MCP 辅助进程使用。
3. `internal/session/runtime.go` 更新 `unlisted_component` 的提示文案；版本号升至 1.1.2；`approved_guardian.json` 更新守护指纹与源码哈希。

## 保护边界

- WFP 逐镜像绑定到显式代理（仅允许 `127.0.0.1:10808` TCP）的仍然只有 Claude.exe 客户端本身。
- Code 模式的后代进程不再有各自的 WFP 规则，它们沿用用户已开启的 v2rayN 全局/TUN 出口。这是让 Code 模式可用的必要让步：终端里的 `git`、`npm`、`wsl` 等工具无法被逐镜像限制在单一 HTTP 入口。
- 代理入口消失、TUN 路由变化、出口 IPv4 变化或守护程序退出，仍会立即安装紧急阻断并结束整个进程树；后代进程随调试关系一起终止。
- 两次出口核验之间（约 10 秒）后代进程的直连不会被单独的 WFP 规则拦截；不要在没有 TUN 或全局代理的情况下使用 Code 模式。

## 验证范围

- 守护程序以 `/W4 /WX` 编译通过；`go test ./...`、前端 4 项单元回归通过。
- 安装包 `app\proxy-harbor\bin\release-1.1.2\Proxy-Harbor-1.1.2-win-x64-setup.exe`，SHA-256 记录在同名 `.sha256`。
- 本次未自动启动或操作 Claude。真实 Code 模式（新建会话、运行终端命令）需用户本机确认；确认前不要把它写成已验收。
