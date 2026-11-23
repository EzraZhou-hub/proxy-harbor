# Code 模式进程监管改造（1.1.3）

2026-11-23。1.1.2 放行了同用户子进程后，仍有部分 Code 模式终端命令失败。按用户要求只讨论并实施进程监管方式的替换，保留“必须经指定 IP 出口”的核心目标。本次没有启动或操作 Claude。

## 改了什么

`native/session/claude_takeover.c` 的接管 Worker：

| 项目 | 1.1.2 | 1.1.3 |
| --- | --- | --- |
| 启动标志 | `CREATE_SUSPENDED \| DEBUG_PROCESS` | `CREATE_SUSPENDED` |
| 子进程 | 全部成为调试对象，每个新进程先挂起等放行 | 由 Job 托管，原生运行 |
| 隔离容器 | 调试关系 + `DebugSetProcessKillOnExit` | `CreateJobObject` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + `AssignProcessToJobObject` |
| 结束会话 | 调试器退出即杀调试树 | `TerminateJobObject`，或关闭 Job 句柄触发整树终止 |
| 回退路径 | 无 | Job 创建/嵌套失败时终止根进程及关联后代，并写 `takeover-containment.json` |
| 组件记录 | 进程创建事件逐条记录 | 每 2 秒枚举 Job 进程，记录新镜像（短命进程可能漏记） |

启动顺序保持“先校验、后恢复”：创建挂起进程 → 校验 MSIX 镜像/包/用户 → 创建 Job 并分配 → 通过管道向守护报告 → 收到放行 → `ResumeThread`。

## 没有改的部分（核心目标）

- WFP 规则完全未动：`Claude.exe` 仍只允许 TCP 连接 `127.0.0.1:10808`，阻断 IPv6、UDP、其他地址/端口及非回环入站。
- 启动前核对保存的公网 IPv4；每约 10 秒经指定代理重新查询出口，不一致或失败即安装紧急阻断并结束会话。
- 代理进程、TUN 路由、WFP 规则的周期校验未动。
- 动态 DNS 限制、恢复流程、守护指纹机制未动。

出口核验位于守护程序，与进程监管方式无关；本次变更只影响“如何收尾”，不影响“如何发现出口异常”。

## 验证范围

- 守护程序 `/W4 /WX` 编译通过；`go test ./...` 与前端单元回归通过。
- 独立 Job 机制测试（`cmd.exe` + `ping`，不涉及 Claude）：分配成功、Job 内 2 个进程，关闭句柄后根进程与子进程全部退出。
- **未启动 Claude**。真实 Code 模式命令、Job 在 MSIX 进程上的分配结果（`takeover-containment.json` 的 `job` 字段）以及出口核验，需用户本机确认。

## 回退

1.1.2 安装包保留在 `app/proxy-harbor/bin/release-1.1.2/`，可随时覆盖安装回退。两个版本的会话目录格式兼容，升级前先结束会话即可。
