//go:build p0system && windows

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/coder/websocket"
	"golang.org/x/sys/windows"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"proxyharbor/internal/session"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagedChromeSession(t *testing.T) {
	recoveryGuest(t)
	root := `C:\P0Lab\.local\p0`
	bin := filepath.Join(root, "bin")
	guardian := filepath.Join(bin, "proxy-harbor-guardian.exe")
	var manifest struct {
		Round  string `json:"publicBridgeRound"`
		Chrome bool   `json:"chromeSessionChecks"`
	}
	data, _ := os.ReadFile(`C:\P0Lab\manifest.json`)
	if json.Unmarshal(data, &manifest) != nil || !manifest.Chrome {
		t.Fatal("Explicit Chrome package required")
	}
	report := map[string]any{"schemaVersion": 1, "scope": "Real installed Chrome binary copy, isolated profile, guest sing-box TUN, existing host proxy via temporary file channel; no account login or Claude", "checks": map[string]bool{}, "cleanup": "pending"}
	checks := report["checks"].(map[string]bool)
	defer func() {
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "managed-chrome-report.json"), data, 0600)
	}()
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Chrome session: %s", name)
		}
	}
	bridgeLog, _ := os.Create(filepath.Join(root, "chrome-bridge.jsonl"))
	defer bridgeLog.Close()
	bridge := exec.Command(`C:\P0Lab\node.exe`, `scripts\p0\codex-file-bridge.mjs`, "guest", `C:\P0Results\proxy-bridge-`+manifest.Round, "900000")
	bridge.Stdout = bridgeLog
	bridge.Stderr = bridgeLog
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { bridge.Process.Kill(); bridge.Wait() }()
	bridgeAddress := ""
	for i := 0; i < 150; i++ {
		out, _ := os.ReadFile(bridgeLog.Name())
		line := strings.SplitN(string(out), "\n", 2)[0]
		var r struct{ Address string }
		if json.Unmarshal([]byte(line), &r) == nil && r.Address != "" {
			bridgeAddress = r.Address
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if bridgeAddress == "" {
		t.Fatal("Guest file bridge failed to start")
	}
	_, port, _ := net.SplitHostPort(bridgeAddress)
	portNumber, _ := strconv.Atoi(port)
	config := map[string]any{"log": map[string]any{"level": "warn", "output": filepath.Join(root, "chrome-tun.log")}, "dns": map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "remote", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "proxy"}}, "final": "remote"}, "inbounds": []any{map[string]any{"type": "tun", "tag": "tun", "interface_name": "singbox_tun", "address": []string{"172.19.0.1/30"}, "auto_route": true, "strict_route": true, "stack": "system"}}, "outbounds": []any{map[string]any{"type": "http", "tag": "proxy", "server": "127.0.0.1", "server_port": portNumber}}, "route": map[string]any{"rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}, "final": "proxy"}}
	encoded, _ := json.MarshalIndent(config, "", "  ")
	configuration := filepath.Join(root, "chrome-tun.json")
	os.WriteFile(configuration, encoded, 0600)
	validation, err := exec.Command(filepath.Join(bin, "sing-box.exe"), "check", "-c", configuration).CombinedOutput()
	if err != nil {
		t.Fatalf("Guest TUN config: %v %s", err, validation)
	}
	tunLog, _ := os.Create(filepath.Join(root, "chrome-tun-console.log"))
	defer tunLog.Close()
	tun := exec.Command(filepath.Join(bin, "sing-box.exe"), "run", "-c", configuration)
	tun.Stdout = tunLog
	tun.Stderr = tunLog
	if err = tun.Start(); err != nil {
		t.Fatal(err)
	}
	tunWaited := false
	defer func() {
		if !tunWaited {
			tun.Process.Kill()
			tun.Wait()
		}
	}()
	time.Sleep(3 * time.Second)
	images, err := session.CollectImages("chrome", `C:\P0Lab\chrome\chrome.exe`)
	if err != nil {
		t.Fatal(err)
	}
	report["componentCount"] = len(images)
	var c, e, k, u windows.Filetime
	windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u)
	created := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
	clean := true
	for _, scenario := range []string{"normal", "guardian_crash", "tun_exit"} {
		func() {
			var nonce [16]byte
			rand.Read(nonce[:])
			h := hex.EncodeToString(nonce[:])
			id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
			folder := filepath.Join(root, "sessions", id)
			os.MkdirAll(folder, 0700)
			request := fmt.Sprintf("PH1\n%s\n%d\n%d\n%s\nchrome\n%d\nEND\n%s\n", id, os.Getpid(), created, port, len(images), strings.Join(images, "\n"))
			os.WriteFile(filepath.Join(folder, "request.txt"), []byte(request), 0600)
			listener, _ := net.Listen("tcp4", "127.0.0.1:0")
			_, debugPort, _ := net.SplitHostPort(listener.Addr().String())
			listener.Close()
			cmd := exec.Command(guardian, "start", folder)
			cmd.Env = append(os.Environ(), "PH_GUEST_CHROME_DEBUG_PORT="+debugPort)
			log, _ := os.Create(filepath.Join(root, "chrome-"+scenario+"-guardian.log"))
			defer log.Close()
			cmd.Stdout = log
			cmd.Stderr = log
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			read := func() map[string]any {
				data, _ := os.ReadFile(filepath.Join(folder, "status.json"))
				r := map[string]any{}
				json.Unmarshal(data, &r)
				return r
			}
			defer func() {
				if !waited {
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
					time.Sleep(time.Second)
					cmd.Process.Kill()
					cmd.Wait()
				}
				inspect, err := exec.Command(guardian, "inspect", folder).Output()
				var inventory struct {
					Rules int `json:"rulesPresent"`
				}
				if err != nil || json.Unmarshal(inspect, &inventory) != nil || inventory.Rules != 0 {
					clean = false
					out, err := exec.Command(guardian, "recover", folder).CombinedOutput()
					t.Logf("Chrome residual recovery: %s %v", out, err)
				}
			}()
			var state map[string]any
			for i := 0; i < 400; i++ {
				state = read()
				if state["state"] == "monitoring" || state["state"] == "failed" || state["state"] == "cleanup_required" {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			report[scenario+"_initial"] = state
			if diagnostic, e := os.ReadFile(filepath.Join(folder, "exit-check.json")); e == nil {
				var item any
				if json.Unmarshal(diagnostic, &item) == nil {
					report[scenario+"_exitCheck"] = item
				}
			}
			check(scenario+"_monitoring", state["state"] == "monitoring")
			if state["state"] != "monitoring" {
				return
			}
			check(scenario+"_all_component_rules", state["filterCount"] == float64(6*len(images)))
			pid := uint32(state["pid"].(float64))
			process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
			if err != nil {
				check(scenario+"_browser_alive", false)
				return
			}
			defer windows.CloseHandle(process)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			ip, err := chromeExit(ctx, "http://127.0.0.1:"+debugPort)
			if err != nil {
				t.Logf("Browser %s: %v; guard %v", scenario, err, read())
			}
			report[scenario+"_browserExit"] = ip
			check(scenario+"_browser_https_matches_proxy", err == nil && ip == state["proxyExit"] && net.ParseIP(ip) != nil)
			switch scenario {
			case "normal":
				os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
			case "guardian_crash":
				cmd.Process.Kill()
				cmd.Wait()
				waited = true
				code, e := windows.WaitForSingleObject(process, 5000)
				check("guardian_crash_closes_browser", e == nil && code == windows.WAIT_OBJECT_0)
				out, e := exec.Command(guardian, "inspect", folder).Output()
				var inv struct {
					Rules int `json:"rulesPresent"`
				}
				json.Unmarshal(out, &inv)
				check("crash_retains_component_rules", e == nil && inv.Rules == 6*len(images))
				e = exec.Command(guardian, "recover", folder).Run()
				check("crash_recovery_succeeds", e == nil)
			case "tun_exit":
				tun.Process.Kill()
				tun.Wait()
				tunWaited = true
			}
			if !waited {
				until := time.Now().Add(15 * time.Second)
				for time.Now().Before(until) {
					state = read()
					if state["state"] == "stopped" || state["state"] == "cleanup_required" || state["state"] == "failed" {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				report[scenario+"_final"] = state
				check(scenario+"_stopped_cleanly", state["state"] == "stopped" && state["filterCount"] == float64(0))
				expected := "user_stopped"
				if scenario == "tun_exit" {
					expected = "tun_process_exited"
				}
				check(scenario+"_reason", state["reason"] == expected || scenario == "tun_exit" && state["reason"] == "tun_route_changed")
				cmd.Wait()
				waited = true
			}
			code, e := windows.WaitForSingleObject(process, 5000)
			check(scenario+"_browser_terminated", e == nil && code == windows.WAIT_OBJECT_0)
		}()
		if t.Failed() {
			break
		}
	}
	if clean {
		report["cleanup"] = "verified"
	} else {
		report["cleanup"] = "failed"
	}
	// Include only temporary test infrastructure diagnostics; no account data.
	for _, name := range []string{"chrome-tun.log", "chrome-tun-console.log", "chrome-bridge.jsonl"} {
		if content, e := os.ReadFile(filepath.Join(root, name)); e == nil && len(content) < 65536 {
			report[name] = string(content)
		}
	}
}

func chromeExit(ctx context.Context, base string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	var socket string
	for socket == "" {
		request, _ := http.NewRequestWithContext(ctx, "GET", base+"/json/list", nil)
		response, err := client.Do(request)
		if err == nil {
			var pages []struct {
				Type   string
				Socket string `json:"webSocketDebuggerUrl"`
			}
			json.NewDecoder(response.Body).Decode(&pages)
			response.Body.Close()
			for _, p := range pages {
				if p.Type == "page" {
					socket = p.Socket
					break
				}
			}
		}
		if socket == "" {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	conn, _, err := websocket.Dial(ctx, socket, nil)
	if err != nil {
		return "", err
	}
	defer conn.CloseNow()
	id := 0
	command := func(method string, params any) (map[string]any, error) {
		id++
		data, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
		if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
			return nil, err
		}
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return nil, err
			}
			r := map[string]any{}
			json.Unmarshal(data, &r)
			if r["id"] == float64(id) {
				if r["error"] != nil {
					return nil, fmt.Errorf("CDP: %v", r["error"])
				}
				return r, nil
			}
		}
	}
	// A fresh URL and matching document location prevent a previous successful
	// page from satisfying a reconnect check before the new navigation commits.
	url := fmt.Sprintf("https://api.ipify.org/?p0=%d", time.Now().UnixNano())
	encodedURL, _ := json.Marshal(url)
	if _, err = command("Page.navigate", map[string]any{"url": url}); err != nil {
		return "", err
	}
	for {
		expression := "location.href === " + string(encodedURL) + " && document.readyState === 'complete' && document.body ? document.body.innerText.trim() : ''"
		r, err := command("Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true})
		if err != nil {
			return "", err
		}
		outer, _ := r["result"].(map[string]any)
		inner, _ := outer["result"].(map[string]any)
		value, _ := inner["value"].(string)
		if net.ParseIP(value) != nil {
			return value, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("Browser did not return an IP: %s", value)
		case <-time.After(200 * time.Millisecond):
		}
	}
}
