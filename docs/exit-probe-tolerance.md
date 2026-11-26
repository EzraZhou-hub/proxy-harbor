# 出口核验与超时复核

## 1.2.3

2026-11-26 的会话在 11:42:16 以 `exit_unverified` 停止，当时记录一次失败，第二轮探测到 11:42:25 才结束。1.2.2 每轮结束后再等 10 秒，其 WinHTTP 超时按操作设置，两轮探测可能撞到 30 秒失效期限。

- 每个 HTTPS 站点从开始到收到完整响应最多 3 秒，两站整轮最多 6 秒。所有请求经锁定的本机 HTTP 代理，使用 HTTPS 并禁止重定向。
- 正常按约 10 秒节奏探测。首轮失败后约 1 秒开始复核，连续两轮失败即断开。30 秒从上次成功匹配时起算，过期后的结果不能恢复会话。
- 测得出口与用户保存的 IP 不一致时立即通知主监控执行阻断。启动前整轮结果必须匹配，失败即拒绝启动。WFP、TUN 和代理监听者的校验沿用现有规则。
- `status.json` 的 `exitStopCause` 区分 `consecutive_failures`（连续两轮失败）与 `verification_expired`（核验过期）。`exit-check.json` 保留各站点阶段、耗时、错误、HTTP 状态和上次成功时间。一次失败后的恢复不会覆盖 `exit-failure.json` 中的最近失败详情。

验证通过 16 项 WFP 规则结构检查、9 项核验状态检查、2 项回环超时与取消检查，以及 Go 和 7 项界面回归。回环双站点故障实际耗时 6,000 毫秒。新版守护程序通过本机 v2rayN 只读探测一次，实测出口匹配保存值。安装包已生成，真实 Claude 会话和安装流程未在本轮运行。

## 1.2.2 的历史记录

## 现象

2026-11-25 连续三次受管会话结束，原因都是 `exit_unverified`：

| 会话 | 时间 | `exit-check.json` |
|---|---|---|
| `e242791e` | 12:19 | `proxyError=12002`，`observed=""` |
| `e46a1e1f` | 13:43 | `proxyError=12002`，`observed=""` |
| `61f34f4b` | 18:11 | `proxyError=12002`，`observed=""` |

`12002` 是 `ERROR_INTERNET_TIMEOUT`。这三次都不是回环问题（1.2.1 已生效，`filterCount=20`，没有 `bypass_blocked`），而是守护程序通过 `127.0.0.1:10808` 请求 `api.ipify.org` 时超时。

同期手工测试三次全部正常（`131.103.130.202`，0.6 秒），说明是代理链路的瞬时抖动。

## 根因

`exit_ok()` 在任一 `query_exit()` 失败时立即：

```c
InterlockedExchange(&exit_fault, EXIT_UNVERIFIED);
SetEvent(exit_alarm);
```

监控循环每 200ms 调一次 `exit_stop_reason()`，看到 fault 就 `break`，随后 `install(TRUE)` 全阻断并结束进程树。**单次 5 秒超时就足以终止会话**，不是 30 秒。`exit_stop_reason()` 里的 30 秒只是兜底（线程未更新 `last_exit_check` 时使用），不是容忍窗口。

## 修改

`native/session/guardian.c`：

- 新增 `exit_failures` 计数。运行期单次核验失败只记录，连续第 2 次才置 fault 并终止（约 10–20 秒窗口）。
- **出口地址不匹配（`mismatch`）仍然立即终止**，不等第二次；这是硬故障。
- **启动检查（`exit_ok(TRUE)`）仍然单次失败就拒绝启动**，不放宽。
- `query_exit()` 改为两个目标：`api.ipify.org` 与 `ifconfig.me/ip`，每次 3 秒超时，总时长不超过 6 秒；两个目标都失败才算一次失败。
- `status.json` 增加 `exitState`（`ok` / `retrying` / `failed` / `mismatch`）和 `exitFailures`。
- `exit-check.json` 增加 `failures`，保留最后一次探测详情。
- 30 秒兜底保留，用于兜住 `check_exits` 线程异常退出的情况。

`check_exits()` 线程在“单次失败但未达阈值”时继续运行（`exit_ok` 返回 TRUE），避免第一次超时后线程退出、只剩 30 秒兜底。

## 安全边界

WFP 规则没有改动。核验失败的那段时间里，Claude 的 `claude.exe` 仍然只能连 `10808`，非回环目标照旧被 `rule 0`/`rule 2` 拦，UDP 与 IPv6 非回环照旧全禁。核验的作用是“发现异常尽早收手”，不是防止直连的唯一防线；放宽的是重试次数，不是网络权限。

## 验证

- 守护 `/W4 /WX` 编译通过，新 SHA-256 `8bff933ce5193da8deb110979e0d62edcecc31b0af193e513dbf37fc543fdc54`。
- 22 项测试全部通过：16 项 WFP 条件结构、4 项 `exitState` 状态、1 项真实代理探测（`131.103.130.202`）、2 项容忍行为（首次失败继续、第二次失败终止；启动检查单次失败拒绝）。
- `go vet ./...`、`go test ./...` 通过。
- `wails3 build` 产出 1.2.2，新指纹已嵌入、旧指纹无残留。
- NSIS 打包产出 `Proxy-Harbor-1.2.2-win-x64-setup.exe`（6,971,356 字节，SHA-256 `a2253770855bd51acebd6089d5577a975624db35340277289349110c95ad6756`）。

## 未验证

- 真实会话中“单次抖动继续、第二次终止”的行为，需要等下一次实际超时观察。
- `ifconfig.me/ip` 在节点侧的可达性，只在本机实测过一次。

## 仍然存在的单点

`api.ipify.org` 和 `ifconfig.me` 都不可达时，仍会在两次失败后终止会话。这是有意的：连续两次拿不到出口，继续运行就无法证明出口仍然正确。
