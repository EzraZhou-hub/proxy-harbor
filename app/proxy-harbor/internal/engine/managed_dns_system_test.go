//go:build p0system && windows

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestManagedDNSParentHold(t *testing.T) {
	if os.Getenv("PH_DNS_PARENT_HOLD") != "1" {
		t.Skip("Child lifetime fixture only")
	}
	recoveryGuest(t)
	for {
		time.Sleep(time.Second)
	}
}

func TestManagedSystemDNSLifecycle(t *testing.T) {
	prepareCapsuleFixtures(t)
	copyCapsuleChrome(t)
	root := `C:\P0Lab\.local\p0`
	guardian := filepath.Join(root, "bin", "proxy-harbor-guardian.exe")
	checks := map[string]bool{}
	report := map[string]any{"checks": checks, "scope": "Persistent session DNS guard, independent watcher, real Chrome, controlled TLS proxy and system DNS observer"}
	t.Cleanup(func() {
		report["cleanup"] = "verified"
		if t.Failed() {
			report["cleanup"] = "not_verified"
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "managed-system-dns-report.json"), data, 0600)
	})
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Managed DNS: %s", name)
		}
	}
	wire := dnsCoverageObserver(t)
	ps := func(script string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command", "$ErrorActionPreference='Stop';"+script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	const owner = "ProxyHarbor.P0.ManagedSystemDNS"
	if err := ps(`if(@(Get-DnsClientNrptRule|Where-Object {$_.Namespace -contains '.p0-dns-audit.invalid'}).Count){throw 'Existing observer'};Add-DnsClientNrptRule -Namespace '.p0-dns-audit.invalid' -NameServers '127.0.0.1' -DisplayName '` + owner + `'|Out-Null`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := ps(`Get-DnsClientNrptRule|Where-Object {$_.DisplayName -eq '` + owner + `' -and @($_.Namespace).Count -eq 1 -and $_.Namespace -contains '.p0-dns-audit.invalid'}|ForEach-Object {Remove-DnsClientNrptRule -Name $_.Name -Force}`)
		check("nrpt_removed", err == nil)
	})
	query := func() bool {
		name := fmt.Sprintf("%016x.p0-dns-audit.invalid", uint64(time.Now().UnixNano()))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
		if err != nil {
			check("no_blocked_wire_"+strings.Split(name, ".")[0], len(wire(name)) == 0)
		}
		return err == nil && len(ips) > 0 && len(wire(name)) > 0
	}
	check("dns_initially_usable", query())
	address, _, _ := managedExitFixture(t, report, nil, nil)
	_, port, _ := net.SplitHostPort(address)
	proxy := guestProxyEndpoint(t, "131.103.130.202", os.Getpid())
	for _, scenario := range []string{"normal_stop", "desktop_exit", "guardian_crash", "watcher_crash", "both_crash"} {
		t.Run(scenario, func(t *testing.T) {
			var nonce [16]byte
			rand.Read(nonce[:])
			h := hex.EncodeToString(nonce[:])
			id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
			folder := filepath.Join(root, "sessions", id)
			if err := os.MkdirAll(folder, 0700); err != nil {
				t.Fatal(err)
			}
			parent := proxy
			var actor *exec.Cmd
			if scenario == "desktop_exit" {
				exe, _ := os.Executable()
				actor = exec.Command(exe, "-test.run=^TestManagedDNSParentHold$", "-test.timeout=150s")
				actor.Env = append(os.Environ(), "PH_DNS_PARENT_HOLD=1")
				if err := actor.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { actor.Process.Kill(); actor.Wait() }()
				parent = guestProxyEndpoint(t, proxy.IPv4, actor.Process.Pid)
			}
			request := fmt.Sprintf("PH5\n%s\n%d\n%d\n%s\nchrome-user\n1\n%s %d %d\n%s\n",
				id, parent.PID, parent.Created, port, proxy.IPv4, proxy.PID, proxy.Created, filepath.Join(capsuleAppDir, "chrome", "chrome.exe"))
			os.WriteFile(filepath.Join(folder, "request.txt"), []byte(request), 0600)
			read := func() map[string]any {
				data, _ := os.ReadFile(filepath.Join(folder, "status.json"))
				row := map[string]any{}
				json.Unmarshal(data, &row)
				return row
			}
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
			cmd := exec.Command(guardian, "start", folder)
			cmd.Env = append(os.Environ(), "PH_GUEST_CHROME_MODE=hold")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waited := false
			defer func() {
				if !waited {
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
					select {
					case <-done:
					case <-time.After(12 * time.Second):
						cmd.Process.Kill()
						<-done
					}
				}
				if inspect() != 0 {
					out, err := exec.Command(guardian, "recover", folder).CombinedOutput()
					if err != nil {
						t.Errorf("Recovery: %v %s", err, out)
					}
				}
			}()
			until := time.Now().Add(25 * time.Second)
			for time.Now().Before(until) {
				s := read()
				if s["state"] == "monitoring" || s["state"] == "failed" || s["state"] == "cleanup_required" {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			initial := read()
			report[scenario+"Initial"] = initial
			if initial["state"] != "monitoring" {
				t.Fatalf("Not monitoring: %v", initial)
			}
			check(scenario+"_twenty_rules", inspect() == 20)
			check(scenario+"_dns_restricted", !query())
			var watchPID uint32
			var watchBorn uint64
			binding, _ := os.ReadFile(filepath.Join(folder, "dns-watch.ready"))
			if _, err := fmt.Sscanf(string(binding), "%d %d", &watchPID, &watchBorn); err != nil {
				t.Fatal(err)
			}
			watch, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, watchPID)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(watch)
			var c, e, k, u windows.Filetime
			if err = windows.GetProcessTimes(watch, &c, &e, &k, &u); err != nil || (uint64(c.HighDateTime)<<32|uint64(c.LowDateTime)) != watchBorn {
				t.Fatal("Watcher identity mismatch")
			}
			switch scenario {
			case "normal_stop":
				os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
			case "desktop_exit":
				actor.Process.Kill()
			case "guardian_crash":
				cmd.Process.Kill()
			case "watcher_crash":
				windows.TerminateProcess(watch, 1)
			case "both_crash":
				// Stop the watcher first and immediately stop its supervisor.
				// Persistent filters must remain until explicit recovery.
				resume := pauseOwnedGuestGuardian(t, uint32(cmd.Process.Pid), uint32(initial["supervisorThreadId"].(float64)))
				windows.TerminateProcess(watch, 1)
				cmd.Process.Kill()
				resume()
			}
			select {
			case <-done:
				waited = true
			case <-time.After(20 * time.Second):
				t.Fatal("Guardian did not finish")
			}
			if scenario == "both_crash" {
				windows.WaitForSingleObject(watch, 3000)
				check("both_crash_dns_stays_blocked", !query())
				original, _ := os.ReadFile(filepath.Join(folder, "request.txt"))
				os.WriteFile(filepath.Join(folder, "request.txt"), []byte("corrupt"), 0600)
				check("corrupt_request_refuses_restore", exec.Command(guardian, "recover", folder).Run() != nil)
				os.WriteFile(filepath.Join(folder, "request.txt"), original, 0600)
			} else {
				wait, err := windows.WaitForSingleObject(watch, 12000)
				check(scenario+"_watcher_exited", err == nil && wait == windows.WAIT_OBJECT_0)
				check(scenario+"_dns_restored_automatically", query())
			}
			out, err := exec.Command(guardian, "recover", folder).CombinedOutput()
			check(scenario+"_explicit_recovery", err == nil && inspect() == 0)
			if err != nil {
				t.Logf("%v %s", err, out)
			}
			check(scenario+"_dns_usable_after_recovery", query())
			final := read()
			report[scenario+"Final"] = final
			check(scenario+"_identity_record_removed", func() bool { _, e := os.Stat(filepath.Join(folder, "identity.txt")); return os.IsNotExist(e) }())
		})
	}
}
