# 本地预览被误判为绕过代理（1.2.1）

## 现象

2026-11-24 16:54、16:56、16:57 连续三次受管 Claude 会话在运行中被结束。三个会话目录的 `status.json` 都是：

```json
{"state":"stopped","reason":"bypass_blocked","blockedAt":"2026-11-24T08:56:31Z",
 "blockDirection":"outbound","blockedProtocol":6,"blockedRemotePort":1420}
```

`exit-check.json` 三次均为 `expected=observed=131.103.130.202`、`matchesExpected=true`，代理本身和固定出口都正常。

## 触发链路

1. DevGraph 新增 `.claude/launch.json`，预览配置 `desktop-web` 用 `pnpm --filter @devgraph/desktop dev` 监听 `127.0.0.1:1420`。
2. Claude Code 调用 `mcp__Claude_Browser__preview_start {"name":"desktop-web"}`。
3. Claude 内置浏览器（同为 `claude.exe` 镜像）向 `127.0.0.1:1420` 发起 TCP 连接。
4. `rule 2` 只放行"远端端口等于代理端口 10808"的连接，回环目标没有例外，于是该连接被 WFP 阻断。
5. 守护程序每 200ms 读取 WFP 丢包事件，命中本会话过滤器后判 `bypass_blocked`，按设计 `TerminateJobObject` 结束整棵 Claude 进程树。

三次 `preview_start` 与三次阻断逐秒对齐（`08:54:28.400Z`、`08:56:30.721Z`、`08:57:29.080Z`），`.vite-temp/vite.config.ts.timestamp-1795510591875` 的生成时间也正好是 16:56:31。

## 为什么之前没出现

历史 45 个会话没有该 reason。以前受管会话没有用内置浏览器预览本地 dev server，第一次出现是 DevGraph 的 M2 开发。

## 修改

`native/session/guardian.c`：

- `rule 2`（`ALE_AUTH_CONNECT_V4`，远端端口 != 代理端口）增加 `IP_REMOTE_ADDRESS != 127.0.0.1`，回环目标不再要求走代理端口。
- `rule 3`（`ALE_AUTH_CONNECT_V6`，原本按镜像全拦）增加 `!= ::1` 和 `!= ::ffff:127.0.0.1`，因为 `localhost` 可能先解析到 `::1`。
- 条件数组从 3 扩到 4（`MAX_CONDITIONS`）。`rule 2`/`rule 3` 在桌面模式下是 3 个业务条件 + 1 个 SID 条件，不扩会越界。
- `emergency`（`rule 6`/`7`）**不加**任何回环例外，"发新密码前阻断全部出站"的语义保持不变。
- `blocked_event()` 记录 `blockedRemoteAddress`，写进 `status.json`，下次定位不用再靠端口反推。

非回环目标的行为完全没变：公网仍只允许代理端口，内网地址仍被 `rule 0` 拦，UDP 仍全禁，IPv6 非回环仍全拦。

## 验证

- 守护编译 `/W4 /WX` 通过（本机 `reg.exe` 被安全策略拦截，改用固定 `INCLUDE`/`LIB` 直接调用 `cl.exe`，不经过 `vcvars64.bat`）。
- 条件结构测试 16 项全部通过：桌面/来宾两种模式下 `rule 0..7` 的条件数量、`rule 2` 的端口与回环条件、`rule 3` 的 `::1`/mapped 条件、`rule 7` 不含地址例外。
- `go vet ./...`、`go test ./...` 通过。
- `wails3 build BIN_DIR=bin\release-1.2.1` 通过，产物版本 1.2.1，新指纹已嵌入、旧指纹无残留。

## 未验证

- 真实受管会话里的 `preview_start`：需要以管理员启动桌面程序并打开 Claude 登录态，待用户本机确认。
- WFP 引擎对 `FWP_BYTE_ARRAY16_TYPE` + `FWP_MATCH_NOT_EQUAL` 的实际匹配，同样依赖真实会话验证。

## 已知边界

WFP 规则仍只覆盖 `Claude.exe` 一个镜像。Claude Code 启动的 `bash`/`node`/`pnpm` 子进程不匹配 `APP_ID`，它们的出站不受这些规则约束，也不产生丢包事件。这是 1.1.3 以来的既有边界，本次未改变，也不因放行回环而扩大。回环连接不出网卡；本机没有通用"回环转发到公网"的服务，代理入口本身仍受 10808 约束。
