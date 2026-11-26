//go:build p0system && windows

package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/session"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// Query only Chrome in the disposable guest. Never export command lines or
// profile contents. Hold process handles so exit checks cannot match reused PIDs.
func chromeComponentAudit(t *testing.T, state domain.ManagedSession, control uint32, report map[string]any, check func(string, bool)) map[string]windows.Handle {
	t.Helper()
	path := filepath.Join(state.Directory, "identity.txt")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(record), path)
	identity, err := io.ReadAll(io.LimitReader(file, 1024))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(identity), "\n")
	if len(lines) != 6 {
		t.Fatal("Invalid identity record")
	}
	expected := lines[3]
	raw, err := exec.Command("powershell.exe", "-NoProfile", "-Command", `$ErrorActionPreference='Stop'
$rows = @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" | ForEach-Object {
  $role = 'browser'
  if ($_.CommandLine -match '--utility-sub-type=network\.mojom\.NetworkService') {$role='network'}
  elseif ($_.CommandLine -match '--type=([a-z-]+)') {$role=$Matches[1]}
  [pscustomobject]@{pid=$_.ProcessId;parent=$_.ParentProcessId;role=$role}
})
ConvertTo-Json -InputObject $rows -Compress`).Output()
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		PID, Parent uint32
		Role        string
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	desc := map[uint32]bool{state.PID: true}
	for n := 0; n < len(rows); n++ {
		for _, row := range rows {
			if desc[row.Parent] {
				desc[row.PID] = true
			}
		}
	}
	handles := make(map[string]windows.Handle)
	roles := make(map[string]int)
	controlDistinct, allOwned := false, true
	for _, row := range rows {
		if !desc[row.PID] && row.PID != control {
			continue
		}
		h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, row.PID)
		if err != nil {
			if err != windows.ERROR_INVALID_PARAMETER {
				allOwned = false
			}
			continue
		}
		var token windows.Token
		if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
			windows.CloseHandle(h)
			allOwned = false
			continue
		}
		user, err := token.GetTokenUser()
		token.Close()
		if err != nil {
			windows.CloseHandle(h)
			allOwned = false
			continue
		}
		same := user.User.Sid.String() == expected
		if row.PID == control {
			controlDistinct = !same && !desc[row.PID]
			windows.CloseHandle(h)
			continue
		}
		allOwned = allOwned && same
		roles[row.Role]++
		handles[fmt.Sprintf("%s_%d", row.Role, roles[row.Role])] = h
	}
	report["observedChromeRoles"] = roles
	check("observed_chrome_descendants_share_session_sid", allOwned && len(handles) > 2)
	check("real_network_service_identified", roles["network"] > 0)
	check("real_renderer_identified", roles["renderer"] > 0)
	check("original_browser_has_different_sid", controlDistinct)
	return handles
}

// The guest has a file bridge instead of the host's v2rayN manager. Pin the
// exact bridge process launched by this test before calling the real Runtime.
func guestProxyEndpoint(t *testing.T, ip string, pid int) session.ProxyEndpoint {
	t.Helper()
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	var c, e, k, u windows.Filetime
	if err = windows.GetProcessTimes(handle, &c, &e, &k, &u); err != nil {
		t.Fatal(err)
	}
	return session.ProxyEndpoint{IPv4: ip, PID: uint32(pid), Created: uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), Port: 10808}
}
func TestManagedRuntimeChromeWindow(t *testing.T) {
	prepareCapsuleFixtures(t)
	copyCapsuleChrome(t)
	root := `C:\P0Lab\.local\p0`
	checks := map[string]bool{}
	report := map[string]any{"schemaVersion": 1, "scope": "Actual desktop session Runtime.Start/Stop, private records, UAC helper and visible Chrome window in disposable guest; existing host proxy on the fixed 10808 guest bridge", "checks": checks, "cleanup": "pending"}
	defer func() {
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "managed-runtime-report.json"), data, 0600)
	}()
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Runtime Chrome: %s", name)
		}
	}
	var manifest struct {
		Round    string `json:"publicBridgeRound"`
		Expected string `json:"expectedProxyIPv4"`
	}
	data, _ := os.ReadFile(`C:\P0Lab\manifest.json`)
	if json.Unmarshal(data, &manifest) != nil || manifest.Round == "" {
		t.Fatal("Explicit public package required")
	}
	log, _ := os.Create(filepath.Join(root, "runtime-bridge.jsonl"))
	defer log.Close()
	bridge := exec.Command(`C:\P0Lab\node.exe`, `scripts\p0\codex-file-bridge.mjs`, "guest", `C:\P0Results\proxy-bridge-`+manifest.Round, "900000", "10808")
	bridge.Stdout = log
	bridge.Stderr = log
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { bridge.Process.Kill(); bridge.Wait() }()
	ready := false
	for i := 0; i < 150; i++ {
		data, _ := os.ReadFile(log.Name())
		var row struct{ Address string }
		if json.Unmarshal(bytes.SplitN(data, []byte{'\n'}, 2)[0], &row) == nil && row.Address == "127.0.0.1:10808" {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Guest fixed HTTP entrance not ready")
	}
	t.Setenv("PH_GUEST_CHROME_MODE", "")
	t.Setenv("PH_GUEST_CHROME_DEBUG_PORT", "")
	runtime := session.New(t.TempDir())
	defer func() {
		s := runtime.Status()
		if s.State == "monitoring" || s.State == "preparing" || s.State == "blocking" {
			runtime.Stop()
			time.Sleep(2 * time.Second)
		}
		s = runtime.Status()
		if s.State == "cleanup_required" || s.State == "failed" {
			runtime.Recover()
		}
	}()
	chrome := filepath.Join(capsuleAppDir, "chrome", "chrome.exe")
	if os.Getenv("PH_GUEST_INSTALLED_CHROME") == "1" {
		chrome = `C:\Program Files\Google\Chrome\Application\chrome.exe`
	}
	report["testedExecutable"] = chrome
	// A second instance of the very same binary belongs to the original guest
	// user. Its private profile and process handle are owned only by this test.
	control := exec.Command(chrome, "--user-data-dir="+t.TempDir(), "--no-first-run", "--disable-background-networking", "--proxy-server=http://127.0.0.1:9", "--app=about:blank")
	if err := control.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { control.Process.Kill(); control.Wait() }()
	controlHandle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(control.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(controlHandle)
	initial, err := runtime.Start("chrome", chrome, guestProxyEndpoint(t, manifest.Expected, bridge.Process.Pid))
	check("runtime_launch_request_accepted", err == nil)
	if err != nil {
		t.Log(err)
		return
	}
	report["initial"] = initial
	until := time.Now().Add(45 * time.Second)
	state := runtime.Status()
	for time.Now().Before(until) {
		state = runtime.Status()
		if state.State == "monitoring" || state.State == "failed" || state.State == "cleanup_required" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	report["active"] = state
	check("runtime_reaches_monitoring", state.State == "monitoring")
	if state.State != "monitoring" {
		return
	}
	check("proxy_exit_matches", state.ProxyExit == manifest.Expected)
	check("fourteen_frontloaded_rules", state.FilterCount == 14)
	user32 := windows.NewLazySystemDLL("user32.dll")
	enum := user32.NewProc("EnumWindows")
	pidProc := user32.NewProc("GetWindowThreadProcessId")
	visibleProc := user32.NewProc("IsWindowVisible")
	classProc := user32.NewProc("GetClassNameW")
	var visible uintptr
	var className string
	callback := windows.NewCallback(func(hwnd, parameter uintptr) uintptr {
		var pid uint32
		pidProc.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != state.PID {
			return 1
		}
		shown, _, _ := visibleProc.Call(hwnd)
		if shown == 0 {
			return 1
		}
		var class [128]uint16
		classProc.Call(hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
		name := windows.UTF16ToString(class[:])
		if strings.HasPrefix(name, "Chrome_WidgetWin_") {
			visible = hwnd
			className = name
			return 0
		}
		return 1
	})
	until = time.Now().Add(20 * time.Second)
	for time.Now().Before(until) && visible == 0 {
		enum.Call(callback, 0)
		time.Sleep(100 * time.Millisecond)
	}
	report["windowClass"] = className
	check("real_chrome_window_visible", visible != 0)
	// Allow startup device discovery and background services to settle before
	// collecting component identity. A terminated browser must fail this check.
	time.Sleep(12 * time.Second)
	check("installed_chrome_remains_monitoring", runtime.Status().State == "monitoring")
	guardian := filepath.Join(root, "bin", "proxy-harbor-guardian.exe")
	if _, err := exec.Command(guardian, "recover", state.Directory).CombinedOutput(); err == nil {
		t.Error("Concurrent recovery succeeded on a live session")
	}
	check("competing_recovery_preserves_live_session", runtime.Status().State == "monitoring" && runtime.Status().GuardianPID == state.GuardianPID)
	if _, err := runtime.V2rayNEndpoint(manifest.Expected, 10808); err == nil {
		t.Error("File bridge incorrectly identified as a v2rayN core")
	} else {
		check("unrelated_listener_rejected_by_desktop_discovery", true)
	}
	componentHandles := chromeComponentAudit(t, state, uint32(control.Process.Pid), report, check)
	defer func() {
		for _, handle := range componentHandles {
			windows.CloseHandle(handle)
		}
	}()
	_, err = runtime.Stop()
	check("runtime_stop_accepted", err == nil)
	until = time.Now().Add(20 * time.Second)
	for time.Now().Before(until) {
		state = runtime.Status()
		if state.State == "stopped" || state.State == "cleanup_required" || state.State == "failed" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	report["final"] = state
	check("runtime_stop_clean", state.State == "stopped" && state.Reason == "user_stopped" && state.FilterCount == 0)
	for role, handle := range componentHandles {
		result, err := windows.WaitForSingleObject(handle, 3000)
		check("owned_"+role+"_exited", err == nil && result == windows.WAIT_OBJECT_0)
	}
	result, err := windows.WaitForSingleObject(controlHandle, 0)
	check("original_chrome_survives", err == nil && result == uint32(windows.WAIT_TIMEOUT))
	if visible != 0 {
		shown, _, _ := visibleProc.Call(visible)
		check("owned_window_closed", shown == 0)
	}
	data, _ = exec.Command(filepath.Join(root, "bin", "proxy-harbor-guardian.exe"), "inspect", state.Directory).Output()
	var inventory struct {
		Rules int    `json:"rulesPresent"`
		Error uint32 `json:"windowsError"`
	}
	err = json.Unmarshal(data, &inventory)
	check("independent_rules_zero", err == nil && inventory.Error == 0 && inventory.Rules == 0)
	if state.State == "stopped" && inventory.Rules == 0 {
		report["cleanup"] = "verified"
	}
}
