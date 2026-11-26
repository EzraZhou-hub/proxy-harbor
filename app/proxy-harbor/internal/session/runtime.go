// Package session owns user-started application sessions, separate from the
// historical experimental engine adapter. It never automatically starts apps.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"proxyharbor/internal/domain"
	"sort"
	"strings"
	"sync"
	"time"
)

type Runtime struct {
	mu                    sync.Mutex
	root, helper, current string
	appID                 string
	components            int
	morePending           bool
	inventoryErr          error
}

func New(dataDirectory string) *Runtime {
	exe, _ := os.Executable()
	r := &Runtime{root: filepath.Join(dataDirectory, "sessions"), helper: filepath.Join(filepath.Dir(exe), "proxy-harbor-guardian.exe")}
	r.selectSession()
	return r
}

func (r *Runtime) selectSession() {
	entries, err := os.ReadDir(r.root)
	r.inventoryErr = nil
	if err != nil && !os.IsNotExist(err) {
		r.inventoryErr = err
		return
	}
	priority, pending := -1, 0
	var newest time.Time
	var selected string
	for _, entry := range entries {
		if !validSessionName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			r.inventoryErr = errors.New("无法核对会话目录")
			return
		}
		dir := filepath.Join(r.root, entry.Name())
		state := readSessionState(dir)
		rank := 0
		switch state.State {
		case "monitoring", "preparing", "blocking":
			rank = 2
		case "cleanup_required":
			rank = 1
		}
		if rank > 0 {
			pending++
		}
		if rank > priority || rank == priority && info.ModTime().After(newest) {
			priority, newest, selected = rank, info.ModTime(), dir
		}
	}
	r.morePending = pending > 1
	r.current, r.appID, r.components = selected, "", 0
	if r.current != "" {
		data, _ := os.ReadFile(filepath.Join(r.current, "session.json"))
		var meta struct {
			ID         string
			Components int
		}
		if json.Unmarshal(data, &meta) == nil {
			r.appID, r.components = meta.ID, meta.Components
		}
	}
}
func validSessionName(name string) bool {
	if len(name) != 36 {
		return false
	}
	for i, c := range name {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func readSessionState(dir string) domain.ManagedSession {
	s := domain.ManagedSession{State: "idle", Reason: "ready", DNS: "not_verified", UDP: "not_run", IPv6: "not_run"}
	if dir == "" {
		return s
	}
	file, err := os.Open(filepath.Join(dir, "status.json"))
	if err != nil {
		s.State, s.Reason = "cleanup_required", "incomplete_session"
		return s
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	file.Close()
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &s) != nil {
		return domain.ManagedSession{State: "cleanup_required", Reason: "invalid_status"}
	}
	switch s.State {
	case "monitoring", "blocking", "preparing":
		updated, err := time.Parse(time.RFC3339, s.UpdatedAt)
		alive := processMatches(s.GuardianPID, s.GuardianCreated)
		if s.State == "preparing" && s.GuardianPID == 0 && s.GuardianCreated == 0 {
			alive = true
		}
		if age := time.Since(updated); err != nil || age < -time.Second || age > 45*time.Second || !alive {
			s.State, s.Reason = "cleanup_required", "guardian_unavailable"
		}
	case "stopped", "failed":
		for _, leaf := range []string{"identity.txt", "proxy-identity.txt", "events.previous", "takeover.bin"} {
			if _, err := os.Lstat(filepath.Join(dir, leaf)); !os.IsNotExist(err) || s.FilterCount != 0 {
				s.State, s.Reason = "cleanup_required", "incomplete_session"
				break
			}
		}
	case "cleanup_required":
	default:
		s.State, s.Reason = "cleanup_required", "invalid_status"
	}
	return s
}

func (r *Runtime) statusLocked() domain.ManagedSession {
	s := readSessionState(r.current)
	if r.morePending && (s.State == "stopped" || s.State == "failed") {
		r.selectSession()
		s = readSessionState(r.current)
	}
	s.Directory, s.ApplicationID, s.ComponentCount = r.current, r.appID, r.components
	if r.current != "" {
		if file, err := os.Open(filepath.Join(r.current, "exit-check.json")); err == nil {
			var probe struct {
				Observed      string
				CheckedAt     string
				LastSuccessAt string
			}
			data, err := io.ReadAll(io.LimitReader(file, 8193))
			file.Close()
			if err == nil && len(data) <= 8192 && json.Unmarshal(data, &probe) == nil {
				s.LastObservedExit, s.ExitCheckedAt = probe.Observed, probe.CheckedAt
				if s.LastExitSuccessAt == "" {
					s.LastExitSuccessAt = probe.LastSuccessAt
				}
			}
		}
	}
	s.Available = helperApproved(r.helper)
	s.TakeoverAvailable = s.Available && takeoverAdmitted()
	s.Detail = reasonText[s.Reason]
	if s.State == "monitoring" && s.ExitState == "retrying" {
		s.Detail = "本轮出口核验失败，正在复核固定代理出口。"
	}
	if s.Reason == "exit_unverified" {
		switch s.ExitStopCause {
		case "consecutive_failures":
			s.Detail = "连续两轮无法核对代理出口，已触发断开。"
		case "verification_expired":
			s.Detail = "距上次成功核验已满 30 秒，已触发断开。"
		}
	}
	if s.State == "blocking" {
		s.Detail = "正在阻断并结束本次应用，等待进程退出确认。"
	} else if s.State == "cleanup_required" && s.Detail == "" {
		s.Detail = "无法确认会话已清理，请核对并恢复。"
	}
	if !s.Available {
		s.Detail = "缺少匹配的守护程序，请核对桌面构建。"
	}
	if r.inventoryErr != nil {
		s.Available, s.State, s.Reason, s.Detail = false, "cleanup_required", "inventory_unavailable", "无法读取完整会话目录，暂停启动与恢复。"
		s.TakeoverAvailable = false
	}
	return s
}
func (r *Runtime) Status() domain.ManagedSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusLocked()
}

// Refresh re-reads the session inventory before reporting. Long-lived callers
// such as the notification-area menu must not cache the directory chosen at
// construction time, because sessions are started by the desktop bindings.
func (r *Runtime) Refresh() domain.ManagedSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selectSession()
	return r.statusLocked()
}

func CollectImages(appID, executable string) ([]string, error) {
	expected := map[string]string{"chrome": "chrome.exe", "codex": "codex.exe"}[appID]
	if expected == "" || !strings.EqualFold(filepath.Base(executable), expected) {
		return nil, errors.New("请选择与登记应用匹配的主程序 EXE")
	}
	absolute, err := filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("应用路径必须是存在的普通 EXE 文件")
	}
	root := filepath.Dir(absolute)
	if root == filepath.VolumeName(root)+string(os.PathSeparator) {
		return nil, errors.New("请使用应用独立安装目录")
	}
	result := []string{absolute}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".exe") && !strings.EqualFold(path, absolute) {
			result = append(result, path)
			if len(result) > 64 {
				return errors.New("安装目录超过 64 个 EXE，请选用独立应用目录")
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("无法完整登记应用组件: %w", err)
	}
	sort.Strings(result[1:])
	return result, nil
}
func (r *Runtime) Start(id, executable string, endpoint ProxyEndpoint) (domain.ManagedSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selectSession()
	s := r.statusLocked()
	mode := "chrome-user"
	switch id {
	case "chrome":
	case "claude":
		if !DesktopAdmitted() {
			return s, errors.New("Claude 客户端保护尚待验收")
		}
		mode = "client-user"
		if s.TakeoverAvailable {
			mode = "claude-restart"
		}
	default:
		return s, errors.New("当前应用尚未接入固定出口守护")
	}
	if !s.Available {
		return s, errors.New(s.Detail)
	}
	if !endpoint.valid() {
		return s, errors.New("需要独立确认的代理出口 IPv4 和当前代理进程身份")
	}
	if s.State == "monitoring" || s.State == "preparing" || s.State == "blocking" || s.State == "cleanup_required" {
		return s, errors.New("请先结束或恢复当前会话")
	}
	var images []string
	var err error
	if id == "claude" {
		executable, err = r.claudeImage()
		images = []string{executable}
	} else {
		images, err = CollectImages(id, executable)
	}
	if err != nil {
		return s, err
	}
	var raw [16]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return s, err
	}
	h := hex.EncodeToString(raw[:])
	name := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	if err = os.MkdirAll(r.root, 0700); err != nil {
		return s, err
	}
	lock, err := startLock(filepath.Join(r.root, "launch.lock"))
	if err != nil {
		return s, fmt.Errorf("无法锁定会话启动记录: %w", err)
	}
	defer lock.Close()
	r.selectSession()
	s = r.statusLocked()
	if !s.Available || (s.State != "idle" && s.State != "stopped" && s.State != "failed") {
		return s, errors.New("请先核对或恢复其他会话")
	}
	folder := filepath.Join(r.root, name)
	stage, err := os.MkdirTemp(r.root, ".preparing-")
	if err != nil {
		return s, err
	}
	defer func() {
		for _, leaf := range []string{"status.json", "session.json", "request.txt"} {
			os.Remove(filepath.Join(stage, leaf))
		}
		os.Remove(stage)
	}()
	if err = privateDirectory(stage); err != nil {
		return s, fmt.Errorf("无法限制会话记录的访问权限: %w", err)
	}
	created, err := currentCreation()
	if err != nil {
		return s, err
	}
	request := fmt.Sprintf("PH4\n%s\n%d\n%d\n%d\n%s\n1\n%s %d %d\n%s\n", name, os.Getpid(), created, endpoint.Port, mode, endpoint.IPv4, endpoint.PID, endpoint.Created, images[0])
	if err = os.WriteFile(filepath.Join(stage, "request.txt"), []byte(request), 0600); err != nil {
		return s, err
	}
	metadata, _ := json.Marshal(map[string]any{"ID": id, "Components": len(images)})
	if err = os.WriteFile(filepath.Join(stage, "session.json"), metadata, 0600); err != nil {
		return s, err
	}
	initial := domain.ManagedSession{State: "preparing", Reason: "checking_proxy", UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		ExpectedProxyIPv4: endpoint.IPv4, V2rayNHTTPPort: endpoint.Port}
	data, _ := json.Marshal(initial)
	if err = os.WriteFile(filepath.Join(stage, "status.json"), data, 0600); err != nil {
		return s, err
	}
	if err = os.Rename(stage, folder); err != nil {
		return s, err
	}
	r.current, r.appID, r.components = folder, id, len(images)
	var worker *os.Process
	failureReason := "authorization_cancelled"
	if mode == "claude-restart" {
		var binary *os.File
		binary, err = verifiedHelper(r.helper)
		if err == nil {
			worker, err = startTakeoverWorker(r.helper, folder)
			binary.Close()
		}
		if err != nil {
			failureReason = "takeover_launch_failed"
		}
	}
	if err == nil {
		err = r.invoke("start", folder)
	}
	if err != nil {
		if worker != nil {
			worker.Kill()
		}
		initial.State = "failed"
		initial.Reason = failureReason
		failed, _ := json.Marshal(initial)
		writeErr := os.WriteFile(filepath.Join(folder, "status.json"), failed, 0600)
		return r.statusLocked(), errors.Join(err, writeErr)
	}
	return r.statusLocked(), nil
}
func (r *Runtime) Stop() (domain.ManagedSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.statusLocked()
	if s.State != "monitoring" && s.State != "preparing" && s.State != "blocking" {
		return s, errors.New("当前没有正在运行的受管会话")
	}
	err := os.WriteFile(filepath.Join(r.current, "stop"), []byte("stop\n"), 0600)
	return s, err
}
func (r *Runtime) Recover() (domain.ManagedSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.statusLocked()
	if !s.Available {
		return s, errors.New(s.Detail)
	}
	if s.State != "cleanup_required" && s.State != "failed" {
		return s, errors.New("当前会话不需要恢复")
	}
	if r.current == "" {
		return s, errors.New("缺少恢复目录")
	}
	return s, r.invoke("recover", r.current)
}

var reasonText = map[string]string{
	"dns_guard_failed":                   "系统 DNS 临时限制或恢复监督失效，正在结束受管应用并恢复 DNS。",
	"dns_restore_pending":                "尚未确认受管进程全部结束或 DNS 规则清理成功；保留限制，请执行恢复。",
	"package_cleanup_pending":            "Windows 尚未确认临时 Claude 注册已移除。保护规则继续生效，可执行恢复。",
	"browser_policy_changed":             "本次浏览器代理、DNS 或 WebRTC 策略无法核对，正在结束受管会话。",
	"proxy_owner_changed":                "代理监听进程与启动前核对的 v2rayN 内核不符，应用未启动。",
	"incomplete_session":                 "会话记录尚未完成清理，请核对并恢复。",
	"invalid_status":                     "无法验证原有会话状态，请核对并恢复。",
	"authorization_cancelled":            "管理员授权取消或守护程序未能启动，目标应用未启动。",
	"ready":                              "启动时将使用已保存的 v2rayN 本机 HTTP 入口，并请求管理员授权。",
	"checking_proxy":                     "正在核对代理和公网出口，并准备应用的独立限制。",
	"proxy_only":                         "正在监控本次会话使用的 v2rayN 本机 HTTP 入口和固定出口。",
	"bypass_blocked":                     "WFP 记录到本次应用的受限连接并已阻断。请查看会话状态和阻断记录。",
	"proxy_unavailable":                  "代理入口失效，已结束本次应用。",
	"tun_not_ready":                      "没有确认 TUN 默认路由，请先开启 v2rayN TUN＋全局。",
	"tun_route_changed":                  "TUN 路由改变，已结束本次应用。",
	"tun_process_exited":                 "TUN 内核退出，已结束本次应用。",
	"exit_not_verified":                  "无法经获准的代理入口核对公网 IPv4 出口；未启动应用。",
	"exit_mismatch_before_launch":        "代理入口的观测出口与会话固定 IP 不符，已取消启动。",
	"exit_mismatch":                      "代理入口的观测出口与会话固定 IP 不符，已触发断开。",
	"exit_unverified":                    "代理出口查询失败或上次核验已过期，已触发断开。",
	"unexpected_tcp_peer":                "发现受管进程的 TCP 连接使用了指定入口以外的地址或端口，已触发断开。",
	"tcp_audit_unavailable":              "无法核对受管进程的 TCP 连接，已触发断开。",
	"exit_changed_or_unavailable":        "出口改变或无法继续核验，已结束本次应用；此状态不等于已确认 IP 泄露。",
	"application_already_running":        "同一安装目录的程序仍在运行，请先保存工作并完整退出后重试。",
	"taking_over":                        "网络限制已安装，正在退出并重新打开 Claude。",
	"takeover_launch_failed":             "无法用当前 Windows 用户启动受保护的 Claude。请普通权限打开 Proxy Harbor 后重试。",
	"takeover_restart_failed":            "无法确认已有 Claude 已退出。请保存工作并从托盘完全退出 Claude 后重试。",
	"takeover_application_still_running": "当前账户仍有 Claude 进程，保护规则已保留。请完全退出 Claude 后执行恢复。",
	"user_stopped":                       "本次应用已关闭，会话规则已清理。",
	"application_exited":                 "本次应用已经退出，会话规则已清理。",
	"desktop_exited":                     "桌面管理程序退出，守护程序已结束本次应用。",
	"unlisted_component":                 "检测到不属于本次会话账户的子进程或组件数量超出上限，本次应用已结束。",
	"component_check_failed":             "Windows 未能核对受管进程，本次应用已结束。详情见会话目录中的 component-check.json。",
	"guardian_unavailable":               "守护程序失联；请显式恢复并核对残留限制。不要把此状态视作仍在保护。",
	"termination_not_confirmed":          "无法确认所有受管进程已退出，保留网络限制，需要恢复处理。",
	"recovered":                          "已核对并清理本次会话拥有的限制。",
	"another_session_active":             "已有会话运行，不能重复开启。",
	"policy_changed":                     "本次限制规则发生变化，已尝试终止受管应用。",
	"monitor_unavailable":                "无法继续读取阻断事件，已尝试终止受管应用。",
	"preflight_failed":                   "启动前检查失败，目标应用未获得保护；请查看本次错误记录。",
	"sid_termination_pending":            "仍无法确认本次身份下的进程全部退出，保留阻断限制，请显式恢复。",
	"identity_cleanup_pending":           "临时配置或身份尚未完成清理，限制仍然保留，请显式恢复。",
	"blocking_not_confirmed":             "完整阻断未能核对，已停止清理并保留现有约束，需要恢复处理。",
}
