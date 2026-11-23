//go:build p0system && windows

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A guest-only, byte-transparent transport fault injector. It never interprets
// proxy payloads or reads the host client's node configuration.
func TestP0TUNFaultRelay(t *testing.T) {
	if os.Getenv("PH_TUN_FAULT_RELAY") != "1" {
		t.Skip("Child fixture only")
	}
	recoveryGuest(t)
	target, marker := os.Getenv("PH_TUN_RELAY_TARGET"), os.Getenv("PH_TUN_RELAY_MARKER")
	host, _, err := net.SplitHostPort(target)
	if err != nil || host != "127.0.0.1" || !strings.HasPrefix(marker, `C:\P0Lab\.local\p0\`) {
		t.Fatal("Invalid fixture scope")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:10808")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	go func() {
		for {
			time.Sleep(25 * time.Millisecond)
			if _, e := os.Stat(marker); e == nil {
				mu.Lock()
				for c := range active {
					c.Close()
				}
				mu.Unlock()
			}
		}
	}()
	for {
		client, e := listener.Accept()
		if e != nil {
			return
		}
		go func() {
			defer client.Close()
			if _, e := os.Stat(marker); e == nil {
				return
			}
			upstream, e := net.DialTimeout("tcp4", target, 3*time.Second)
			if e != nil {
				return
			}
			defer upstream.Close()
			mu.Lock()
			active[client] = true
			active[upstream] = true
			mu.Unlock()
			defer func() { mu.Lock(); delete(active, client); delete(active, upstream); mu.Unlock() }()
			done := make(chan int64, 1)
			go func() { n, _ := io.Copy(upstream, client); upstream.Close(); done <- n }()
			received, _ := io.Copy(client, upstream)
			client.Close()
			fmt.Printf("relay_bytes sent=%d received=%d\n", <-done, received)
		}()
	}
}

func TestManagedTUNSystemDNS(t *testing.T) {
	prepareCapsuleFixtures(t)
	copyCapsuleChrome(t)
	root := `C:\P0Lab\.local\p0`
	bin := filepath.Join(root, "bin")
	guardian := filepath.Join(bin, "proxy-harbor-guardian.exe")
	var manifest struct {
		Round    string `json:"publicBridgeRound"`
		Expected string `json:"expectedProxyIPv4"`
		Address  string `json:"publicTestAddress"`
	}
	data, _ := os.ReadFile(`C:\P0Lab\manifest.json`)
	if json.Unmarshal(data, &manifest) != nil || len(manifest.Round) != 8 || net.ParseIP(manifest.Expected) == nil || net.ParseIP(manifest.Address) == nil {
		t.Fatal("Explicit public fixture required")
	}
	checks := map[string]bool{}
	report := map[string]any{"checks": checks, "scope": "PH4, guest real sing-box TUN, real existing host HTTP proxy via bounded file channel; transport faults are injected in guest, not a host v2rayN node restart", "cleanup": "pending", "expectedProxyIPv4": manifest.Expected}
	report["transparentHTTPS"] = "not_accepted; separate curl baseline timed out before protection; this test validates the selected application's explicit HTTP path and TUN route supervision"
	t.Cleanup(func() {
		report["cleanup"] = "verified"
		if t.Failed() {
			report["cleanup"] = "not_verified"
		}
		b, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "tun-dns-report.json"), b, 0600)
	})
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("TUN DNS: %s", name)
		}
	}
	ps := func(script string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		b, e := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command", "$ErrorActionPreference='Stop';"+script).CombinedOutput()
		if e != nil {
			return fmt.Errorf("%w: %s", e, b)
		}
		return nil
	}
	wire := dnsCoverageObserver(t)
	const nrptOwner = "ProxyHarbor.P0.TUNDNS"
	if err := ps(`if(@(Get-DnsClientNrptRule|Where-Object {$_.Namespace -contains '.p0-dns-audit.invalid'}).Count){throw 'Existing observer'};Add-DnsClientNrptRule -Namespace '.p0-dns-audit.invalid' -NameServers '127.0.0.1' -DisplayName '` + nrptOwner + `'|Out-Null`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		check("test_nrpt_removed", ps(`Get-DnsClientNrptRule|Where-Object {$_.DisplayName -eq '`+nrptOwner+`' -and $_.Namespace -contains '.p0-dns-audit.invalid'}|ForEach-Object {Remove-DnsClientNrptRule -Name $_.Name -Force}`) == nil)
	})
	dns := func() bool {
		name := fmt.Sprintf("%x.p0-dns-audit.invalid", time.Now().UnixNano())
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", name)
		if e != nil {
			check("blocked_query_no_wire_"+strings.Split(name, ".")[0], len(wire(name)) == 0)
		}
		return e == nil && len(ips) > 0 && len(wire(name)) > 0
	}
	check("system_dns_baseline", dns())
	log, e := os.Create(filepath.Join(root, "tun-dns-bridge.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	bridge := exec.Command(`C:\P0Lab\node.exe`, `scripts\p0\codex-file-bridge.mjs`, "guest", `C:\P0Results\proxy-bridge-`+manifest.Round, "900000")
	bridge.Stdout = log
	bridge.Stderr = log
	if e = bridge.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { bridge.Process.Kill(); bridge.Wait() }()
	bridgeAddress := ""
	for until := time.Now().Add(20 * time.Second); time.Now().Before(until); {
		b, _ := os.ReadFile(log.Name())
		var row struct{ Address string }
		if json.Unmarshal(bytes.SplitN(b, []byte{'\n'}, 2)[0], &row) == nil && row.Address != "" {
			bridgeAddress = row.Address
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if bridgeAddress == "" {
		t.Fatal("Bridge unavailable")
	}
	config := map[string]any{"log": map[string]any{"level": "info"}, "inbounds": []any{map[string]any{"type": "tun", "tag": "tun", "interface_name": "singbox_tun", "address": []string{"172.19.0.1/30"}, "auto_route": true, "strict_route": true, "dns_mode": "disabled", "stack": "gvisor"}}, "outbounds": []any{map[string]any{"type": "http", "tag": "proxy", "server": "127.0.0.1", "server_port": 10808}}, "route": map[string]any{"final": "proxy", "auto_detect_interface": true}}
	configPath := filepath.Join(root, "tun-dns.json")
	b, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, b, 0600)
	if b, e := exec.Command(filepath.Join(bin, "sing-box.exe"), "check", "-c", configPath).CombinedOutput(); e != nil {
		t.Fatalf("TUN config %v %s", e, b)
	}
	var relay, tun *exec.Cmd
	stop := func(c **exec.Cmd) {
		if *c != nil {
			(*c).Process.Kill()
			(*c).Wait()
			*c = nil
		}
	}
	defer stop(&relay)
	defer stop(&tun)
	marker := filepath.Join(root, "tun-transport-block")
	startRelay := func() {
		os.Remove(marker)
		exe, _ := os.Executable()
		relay = exec.Command(exe, "-test.run=^TestP0TUNFaultRelay$", "-test.timeout=600s")
		relay.Env = append(os.Environ(), "PH_TUN_FAULT_RELAY=1", "PH_TUN_RELAY_TARGET="+bridgeAddress, "PH_TUN_RELAY_MARKER="+marker)
		relayLog, e := os.OpenFile(filepath.Join(root, "tun-relay-console.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer relayLog.Close()
		relay.Stdout = relayLog
		relay.Stderr = relayLog
		if e := relay.Start(); e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 50; i++ {
			c, e := net.DialTimeout("tcp4", "127.0.0.1:10808", 100*time.Millisecond)
			if e == nil {
				c.Close()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("Relay not listening")
	}
	startTUN := func() {
		file, e := os.OpenFile(filepath.Join(root, "tun-dns-console.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer file.Close()
		tun = exec.Command(filepath.Join(bin, "sing-box.exe"), "run", "-c", configPath)
		tun.Stdout = file
		tun.Stderr = file
		if e := tun.Start(); e != nil {
			t.Fatal(e)
		}
		for until := time.Now().Add(10 * time.Second); time.Now().Before(until); {
			// check reports TUN independently; its listener-recognition failure
			// is expected for this guest-only relay rather than v2rayN.
			data, _ := exec.Command(guardian, "check").Output()
			var ready struct {
				TUN bool `json:"tunReady"`
			}
			if json.Unmarshal(data, &ready) == nil && ready.TUN {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("Guest TUN did not acquire the expected default route")
	}
	startRelay()
	startTUN()
	scenarios := []string{"normal", "interactive_chrome", "short_transport_outage", "long_transport_outage", "proxy_listener_restart", "tun_interface_down", "tun_process_exit", "normal_after_faults"}
	if selected := os.Getenv("PH_TUN_SCENARIOS"); selected != "" {
		valid := map[string]bool{}
		for _, name := range scenarios {
			valid[name] = true
		}
		scenarios = strings.Split(selected, ",")
		for _, name := range scenarios {
			if !valid[name] {
				t.Fatal("Unknown selected scenario")
			}
		}
	}
	report["scenarios"] = scenarios
	for scenarioIndex, scenario := range scenarios {
		if !t.Run(scenario, func(t *testing.T) {
			var nonce [16]byte
			if _, e := rand.Read(nonce[:]); e != nil {
				t.Fatal(e)
			}
			h := hex.EncodeToString(nonce[:])
			id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
			folder := filepath.Join(root, "sessions", id)
			if e := os.MkdirAll(folder, 0700); e != nil {
				t.Fatal(e)
			}
			owner := guestProxyEndpoint(t, manifest.Expected, relay.Process.Pid)
			var c, exited, k, u windows.Filetime
			windows.GetProcessTimes(windows.CurrentProcess(), &c, &exited, &k, &u)
			created := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
			request := fmt.Sprintf("PH4\n%s\n%d\n%d\n10808\nchrome-user\n1\n%s %d %d\n%s\n", id, os.Getpid(), created, owner.IPv4, owner.PID, owner.Created, filepath.Join(capsuleAppDir, "chrome", "chrome.exe"))
			os.WriteFile(filepath.Join(folder, "request.txt"), []byte(request), 0600)
			read := func(leaf string) map[string]any {
				b, _ := os.ReadFile(filepath.Join(folder, leaf))
				row := map[string]any{}
				json.Unmarshal(b, &row)
				return row
			}
			inspect := func() int {
				b, e := exec.Command(guardian, "inspect", folder).Output()
				var r struct {
					Rules int `json:"rulesPresent"`
				}
				if e != nil || json.Unmarshal(b, &r) != nil {
					return -1
				}
				return r.Rules
			}
			dom := scenario == "normal" || scenario == "normal_after_faults"
			mode := "hold"
			if dom {
				mode = "dom"
			}
			cmd := exec.Command(guardian, "start", folder)
			if scenario != "interactive_chrome" {
				cmd.Env = append(os.Environ(), "PH_GUEST_CHROME_MODE="+mode)
			}
			defer func() {
				if diagnosis := read("component-check.json"); len(diagnosis) != 0 {
					report[scenario+"ComponentCheck"] = diagnosis
				}
			}()
			var browserOutput bytes.Buffer
			cmd.Stdout = &browserOutput
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waited := false
			defer func() {
				os.Remove(marker)
				if !waited {
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
					select {
					case <-done:
					case <-time.After(15 * time.Second):
						cmd.Process.Kill()
						<-done
					}
				}
				if inspect() != 0 {
					b, e := exec.Command(guardian, "recover", folder).CombinedOutput()
					check(scenario+"_fallback_recovery", e == nil && inspect() == 0)
					if e != nil {
						t.Logf("Recovery %v %s", e, b)
					}
				}
			}()
			var initial map[string]any
			for until := time.Now().Add(40 * time.Second); time.Now().Before(until); {
				initial = read("status.json")
				if initial["state"] == "monitoring" || initial["state"] == "stopped" || initial["state"] == "failed" || initial["state"] == "cleanup_required" {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			report[scenario+"Initial"] = initial
			if initial["state"] != "monitoring" && !(dom && initial["state"] == "stopped") {
				t.Fatalf("Not monitoring: %v", initial)
			}
			if !dom {
				check(scenario+"_dns_and_application_rules", inspect() == 20 && initial["dns"] == "system_blocked")
			}
			check(scenario+"_tun_selected", initial["tunIndex"].(float64) > 0)
			var process windows.Handle
			if !dom {
				check(scenario+"_system_dns_blocked", !dns())
				check(scenario+"_native_tls_proxy_exit", initial["proxyExit"] == manifest.Expected)
				var err error
				process, err = windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(initial["pid"].(float64)))
				if err != nil {
					t.Fatal(err)
				}
				defer windows.CloseHandle(process)
			}
			expected := "user_stopped"
			faultAt := time.Now()
			previousCheck := fmt.Sprint(read("exit-check.json")["checkedAt"])
			switch scenario {
			case "interactive_chrome":
				deadline := time.Now().Add(15 * time.Second)
				for time.Now().Before(deadline) && read("status.json")["state"] == "monitoring" {
					time.Sleep(200 * time.Millisecond)
				}
				check("interactive_chrome_survived_startup", !time.Now().Before(deadline) && read("status.json")["state"] == "monitoring")
				probe := read("exit-check.json")
				check("interactive_chrome_fresh_exit_check", probe["matchesExpected"] == true && fmt.Sprint(probe["checkedAt"]) != previousCheck)
				os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
			case "short_transport_outage":
				os.WriteFile(marker, []byte("block"), 0600)
				time.Sleep(4 * time.Second)
				os.Remove(marker)
				for until := time.Now().Add(30 * time.Second); time.Now().Before(until); {
					if read("status.json")["state"] != "monitoring" {
						break
					}
					row := read("exit-check.json")
					if fmt.Sprint(row["checkedAt"]) != previousCheck && row["matchesExpected"] == true {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				row := read("exit-check.json")
				if read("status.json")["state"] == "monitoring" {
					check("short_outage_fresh_health_check", fmt.Sprint(row["checkedAt"]) != previousCheck && row["matchesExpected"] == true)
					check("short_outage_dns_still_blocked", !dns())
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
				} else {
					expected = "exit_unverified"
					report["shortOutageBehavior"] = "Session terminated on failed health check; requires explicit new session"
				}
			case "long_transport_outage":
				os.WriteFile(marker, []byte("block"), 0600)
				expected = "exit_unverified"
			case "proxy_listener_restart":
				old := relay.Process.Pid
				stop(&relay)
				startRelay()
				check("proxy_restarted_with_new_pid", relay.Process.Pid != old)
				expected = "proxy_unavailable"
			case "tun_interface_down":
				index := strconv.Itoa(int(initial["tunIndex"].(float64)))
				if e := ps(`$n=Get-NetAdapter -InterfaceIndex ` + index + `;if($n.Name -ne 'singbox_tun'){throw 'Not fixture TUN'};$n|Disable-NetAdapter -Confirm:$false`); e != nil {
					t.Fatal(e)
				}
				expected = "tun_route_changed"
			case "tun_process_exit":
				stop(&tun)
				expected = "tun_route_changed"
			default:
				if dom {
					expected = "application_exited"
				} else {
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
				}
			}
			select {
			case <-done:
				waited = true
			case <-time.After(50 * time.Second):
				t.Fatal("Guardian did not close after fault")
			}
			report[scenario+"FaultToFinishMs"] = time.Since(faultAt).Milliseconds()
			os.Remove(marker)
			final := read("status.json")
			report[scenario+"Final"] = final
			report[scenario+"ExitCheck"] = read("exit-check.json")
			check(scenario+"_correct_stop_reason", final["reason"] == expected)
			check(scenario+"_all_rules_removed", final["state"] == "stopped" && inspect() == 0 && final["dns"] == "restored")
			if dom {
				report[scenario+"BrowserStdout"] = browserOutput.String()
				check(scenario+"_actual_chrome_https_page", strings.Contains(browserOutput.String(), manifest.Expected))
			} else {
				wait, e := windows.WaitForSingleObject(process, 1000)
				check(scenario+"_chrome_terminated", e == nil && wait == windows.WAIT_OBJECT_0)
			}
			// The fixture TUN may itself intercept DNS. Remove it before checking
			// restoration against the original independent loopback DNS baseline.
			if scenario == "tun_interface_down" {
				index := strconv.Itoa(int(initial["tunIndex"].(float64)))
				check("disabled_fixture_adapter_reenabled", ps(`$n=Get-NetAdapter -InterfaceIndex `+index+`;if($n.Name -ne 'singbox_tun'){throw 'Not fixture TUN'};$n|Enable-NetAdapter -Confirm:$false`) == nil)
			}
			stop(&tun)
			check(scenario+"_system_dns_restored", dns())
			check(scenario+"_no_identity_record", func() bool { _, e := os.Stat(filepath.Join(folder, "identity.txt")); return os.IsNotExist(e) }())
		}) {
			break
		}
		if t.Failed() {
			break
		}
		if scenarioIndex+1 < len(scenarios) {
			startTUN()
		}
	}
}
