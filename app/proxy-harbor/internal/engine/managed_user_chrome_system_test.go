//go:build p0system && windows

package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedUserChromeSession(t *testing.T) {
	prepareCapsuleFixtures(t)
	copyCapsuleChrome(t)
	root := `C:\P0Lab\.local\p0`
	bin := filepath.Join(root, "bin")
	guardian := filepath.Join(bin, "proxy-harbor-guardian.exe")
	var manifest struct {
		Round    string `json:"publicBridgeRound"`
		Expected string `json:"expectedProxyIPv4"`
	}
	data, _ := os.ReadFile(`C:\P0Lab\manifest.json`)
	if json.Unmarshal(data, &manifest) != nil || net.ParseIP(manifest.Expected) == nil {
		t.Fatal("Explicit public package reference required")
	}
	checks := map[string]bool{}
	report := map[string]any{"schemaVersion": 1, "scope": "Production dedicated-user guardian, real Chrome and real TLS via existing host proxy; independent WFP and Job containment; no browser sandbox or TLS bypass", "checks": checks, "cleanup": "pending", "expectedProxyExit": manifest.Expected}
	defer func() {
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "managed-user-chrome-report.json"), data, 0600)
	}()
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Managed user Chrome: %s", name)
		}
	}
	for _, scenario := range []string{"normal", "proxy_failure", "guardian_crash"} {
		func() {
			log, _ := os.Create(filepath.Join(root, "managed-user-chrome-bridge-"+scenario+".jsonl"))
			defer log.Close()
			bridge := exec.Command(`C:\P0Lab\node.exe`, `scripts\p0\codex-file-bridge.mjs`, "guest", `C:\P0Results\proxy-bridge-`+manifest.Round, "900000")
			bridge.Stdout = log
			bridge.Stderr = log
			if err := bridge.Start(); err != nil {
				t.Fatal(err)
			}
			stopped := false
			stop := func() {
				if !stopped {
					bridge.Process.Kill()
					bridge.Wait()
					stopped = true
				}
			}
			defer stop()
			address := ""
			for i := 0; i < 150; i++ {
				data, _ := os.ReadFile(log.Name())
				var row struct{ Address string }
				if json.Unmarshal(bytes.SplitN(data, []byte{'\n'}, 2)[0], &row) == nil && row.Address != "" {
					address = row.Address
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if address == "" {
				t.Fatal("Guest bridge not ready")
			}
			_, port, _ := net.SplitHostPort(address)
			var nonce [16]byte
			rand.Read(nonce[:])
			h := hex.EncodeToString(nonce[:])
			id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
			folder := filepath.Join(root, "sessions", id)
			os.MkdirAll(folder, 0700)
			var c, e, k, u windows.Filetime
			windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u)
			created := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
			owner := guestProxyEndpoint(t, manifest.Expected, bridge.Process.Pid)
			image := filepath.Join(capsuleAppDir, "chrome", "chrome.exe")
			if scenario != "guardian_crash" && os.Getenv("PH_GUEST_INSTALLED_CHROME") == "1" {
				image = `C:\Program Files\Google\Chrome\Application\chrome.exe`
			}
			report[scenario+"_executable"] = image
			request := fmt.Sprintf("PH2\n%s\n%d\n%d\n%s\nchrome-user\n1\n%s %d %d\n%s\n", id, os.Getpid(), created, port, owner.IPv4, owner.PID, owner.Created, image)
			os.WriteFile(filepath.Join(folder, "request.txt"), []byte(request), 0600)
			inspect := func() int {
				out, err := exec.Command(guardian, "inspect", folder).Output()
				var row struct {
					Rules int `json:"rulesPresent"`
				}
				if err != nil || json.Unmarshal(out, &row) != nil {
					return -1
				}
				return row.Rules
			}
			read := func() map[string]any {
				data, _ := os.ReadFile(filepath.Join(folder, "status.json"))
				r := map[string]any{}
				json.Unmarshal(data, &r)
				return r
			}
			mode := "hold"
			if scenario == "normal" {
				mode = "dom"
			}
			command := exec.Command(guardian, "start", folder)
			command.Env = append(os.Environ(), "PH_GUEST_CHROME_MODE="+mode)
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			waited := false
			defer func() {
				if !waited {
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						command.Process.Kill()
						<-done
					}
					waited = true
				}
				if inspect() != 0 {
					out, err := exec.Command(guardian, "recover", folder).CombinedOutput()
					if err != nil {
						t.Errorf("Recovery failed: %v %s", err, out)
					}
				}
			}()
			var initial map[string]any
			until := time.Now().Add(40 * time.Second)
			for time.Now().Before(until) {
				initial = read()
				if initial["state"] == "monitoring" || initial["state"] == "stopped" || initial["state"] == "failed" || initial["state"] == "cleanup_required" {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			report[scenario+"Initial"] = initial
			check(scenario+"_real_proxy_preflight", initial["proxyExit"] == manifest.Expected)
			if initial["state"] != "monitoring" && !(scenario == "normal" && initial["state"] == "stopped") {
				t.Errorf("Chrome did not launch: %v", initial)
				return
			}
			if scenario != "normal" {
				check(scenario+"_fourteen_rules", inspect() == 14)
			}
			var process windows.Handle
			if pid, ok := initial["pid"].(float64); ok && pid > 0 {
				process, _ = windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
				if process != 0 {
					defer windows.CloseHandle(process)
				}
			}
			switch scenario {
			case "proxy_failure":
				time.Sleep(2 * time.Second)
				stop()
			case "guardian_crash":
				command.Process.Kill()
				<-done
				waited = true
				if process != 0 {
					code, err := windows.WaitForSingleObject(process, 5000)
					check(scenario+"_job_root_dead", err == nil && code == windows.WAIT_OBJECT_0)
				}
				check(scenario+"_rules_persist", inspect() == 14)
				image := filepath.Join(capsuleAppDir, "chrome", "chrome.exe")
				check(scenario+"_image_removed_before_recovery", os.Rename(image, image+".fixture-removed") == nil)
				for _, leaf := range []string{"identity.txt", "proxy-identity.txt"} {
					path := filepath.Join(folder, leaf)
					original, _ := os.ReadFile(path)
					os.WriteFile(path, []byte("corrupt"), 0600)
					err := exec.Command(guardian, "recover", folder).Run()
					check(scenario+"_corrupt_"+leaf+"_refuses", err != nil && inspect() == 14)
					os.WriteFile(path, original, 0600)
				}
				out, err := exec.Command(guardian, "recover", folder).CombinedOutput()
				check(scenario+"_separate_recovery", err == nil && inspect() == 0)
				if err != nil {
					t.Logf("%v %s", err, out)
				}
			}
			if !waited {
				select {
				case err := <-done:
					waited = true
					check(scenario+"_guardian_finished", err == nil)
				case <-time.After(70 * time.Second):
					t.Error("Chrome guardian did not complete")
					return
				}
			}
			final := read()
			report[scenario+"Final"] = final
			report[scenario+"BrowserStdout"] = stdout.String()
			report[scenario+"BrowserStderr"] = stderr.String()
			check(scenario+"_clean_state", final["state"] == "stopped" && inspect() == 0)
			if scenario == "normal" {
				check(scenario+"_actual_https_page_exit", strings.Contains(stdout.String(), manifest.Expected))
				check(scenario+"_normal_application_exit", final["reason"] == "application_exited")
			}
			if scenario == "proxy_failure" {
				check(scenario+"_terminated_on_proxy_failure", final["reason"] == "proxy_unavailable")
				if process != 0 {
					code, err := windows.WaitForSingleObject(process, 5000)
					check(scenario+"_root_dead", err == nil && code == windows.WAIT_OBJECT_0)
				}
			}
			_, identityErr := os.Stat(filepath.Join(folder, "identity.txt"))
			check(scenario+"_identity_record_removed", os.IsNotExist(identityErr))
		}()
	}
	report["cleanup"] = "verified"
	for name, ok := range checks {
		if !ok && (strings.Contains(name, "clean") || strings.Contains(name, "recovery") || strings.Contains(name, "record_removed")) {
			report["cleanup"] = "failed"
		}
	}
}
