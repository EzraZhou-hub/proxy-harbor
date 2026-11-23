//go:build p0system && windows

package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagedSessionGuardian(t *testing.T) {
	testManagedSessionGuardian(t, false)
}
func TestManagedUserSessionGuardian(t *testing.T) {
	testManagedSessionGuardian(t, true)
}
func testManagedSessionGuardian(t *testing.T, user bool) {
	recoveryGuest(t)
	root := `C:\P0Lab\.local\p0`
	guardian := filepath.Join(root, "bin", "proxy-harbor-guardian.exe")
	image := filepath.Join(root, "bin", "session-fixture.exe")
	cases := []map[string]any{}
	reportName := "managed-session-report.json"
	if user {
		reportName = "managed-user-session-report.json"
	}
	defer func() {
		data, _ := json.MarshalIndent(map[string]any{"schemaVersion": 1, "overall": "bounded_fixture_only", "scope": "Actual WFP proxy-only rules, Job termination, event monitoring and recovery in disposable guest; fixture mode skips TUN and public exit checks", "cases": cases}, "", "  ")
		os.WriteFile(filepath.Join(root, reportName), data, 0600)
	}()
	scenarios := []string{"stop", "tcp4", "tcp6", "udp4", "udp6", "proxy_failure", "unknown_child", "guardian_crash"}
	if user {
		scenarios = append(scenarios, "policy_changed", "monitor_unavailable", "port_takeover", "parent_exit")
	}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			record := map[string]any{"scenario": scenario, "checks": map[string]bool{}, "cleanup": "pending"}
			cases = append(cases, record)
			defer func() {
				data, _ := json.MarshalIndent(map[string]any{"scope": "Guest fixture mode; no real application or TUN claim", "cases": cases}, "", "  ")
				os.WriteFile(filepath.Join(root, reportName), data, 0600)
			}()
			checks := record["checks"].(map[string]bool)
			check := func(name string, ok bool) {
				t.Helper()
				checks[name] = ok
				if !ok {
					t.Errorf("Guardian %s: %s", scenario, name)
				}
			}
			upstream, _, _, stopUpstream := systemProxy(t, "http", false)
			_, port, _ := strings.Cut(upstream, ":")
			var nonce [16]byte
			rand.Read(nonce[:])
			h := hex.EncodeToString(nonce[:])
			id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
			folder := filepath.Join(root, "sessions", id)
			os.MkdirAll(folder, 0700)
			var c, e, k, u windows.Filetime
			windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u)
			created := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
			parentPID := os.Getpid()
			var parentActor *exec.Cmd
			if scenario == "parent_exit" {
				parentActor = exec.Command(image, "-session-fixture", folder, "-parent-hold")
				if err := parentActor.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { parentActor.Process.Kill(); parentActor.Wait() }()
				parentPID = parentActor.Process.Pid
				handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(parentPID))
				if err != nil {
					t.Fatal(err)
				}
				windows.GetProcessTimes(handle, &c, &e, &k, &u)
				windows.CloseHandle(handle)
				created = uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
			}
			mode := "fixture"
			ruleCount := 6
			if user {
				mode = "fixture-user"
				ruleCount = 14
			}
			request := []byte(fmt.Sprintf("PH1\n%s\n%d\n%d\n%s\n%s\n1\nEND\n%s\n", id, parentPID, created, port, mode, image))
			os.WriteFile(filepath.Join(folder, "request.txt"), request, 0600)
			inspect := func() int {
				out, err := exec.Command(guardian, "inspect", folder).Output()
				var r struct {
					Rules int `json:"rulesPresent"`
				}
				if err != nil || json.Unmarshal(out, &r) != nil {
					return -1
				}
				return r.Rules
			}
			read := func() map[string]any {
				data, _ := os.ReadFile(filepath.Join(folder, "status.json"))
				result := map[string]any{}
				json.Unmarshal(data, &result)
				return result
			}
			waitState := func(states ...string) map[string]any {
				until := time.Now().Add(15 * time.Second)
				var r map[string]any
				for time.Now().Before(until) {
					r = read()
					for _, state := range states {
						if r["state"] == state {
							return r
						}
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Errorf("Guardian state timeout: %v", r)
				return r
			}
			command := exec.Command(guardian, "start", folder)
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
					time.Sleep(time.Second)
					command.Process.Kill()
					command.Wait()
				}
				if inspect() != 0 {
					recovery := exec.Command(guardian, "recover", folder)
					out, err := recovery.CombinedOutput()
					if err != nil {
						t.Logf("Recovery: %s %v", out, err)
					}
				}
				if inspect() == 0 {
					record["cleanup"] = "verified"
				} else {
					record["cleanup"] = "failed"
					t.Error("Session filters remain")
				}
			}()
			initial := waitState("monitoring", "failed", "cleanup_required")
			check("launch_reaches_monitoring", initial["state"] == "monitoring")
			if initial["state"] != "monitoring" {
				t.Logf("%v %s", initial, output.String())
				return
			}
			check("all_proxy_only_rules", inspect() == ruleCount)
			pid := uint32(initial["pid"].(float64))
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(handle)
			fixtureFolder := folder
			if user {
				data, _ := os.ReadFile(filepath.Join(folder, "fixture-directory.txt"))
				fixtureFolder = string(data)
				if !strings.HasPrefix(strings.ToLower(fixtureFolder), `c:\users\ph_`) {
					t.Fatal("Invalid fixture profile location")
				}
			}
			sequence := 0
			ask := func(action, network, address string) map[string]any {
				sequence++
				data, _ := json.Marshal(map[string]any{"sequence": sequence, "action": action, "network": network, "address": address})
				os.WriteFile(filepath.Join(fixtureFolder, "command.json"), data, 0600)
				until := time.Now().Add(4 * time.Second)
				if action == "bind-trusted" {
					until = time.Now().Add(8 * time.Second)
				}
				for time.Now().Before(until) {
					out, _ := os.ReadFile(filepath.Join(fixtureFolder, "result.json"))
					r := map[string]any{}
					if json.Unmarshal(out, &r) == nil && r["sequence"] == float64(sequence) {
						return r
					}
					if read()["state"] != "monitoring" {
						return nil
					}
					time.Sleep(20 * time.Millisecond)
				}
				return nil
			}
			check("proxied_echo_works", ask("proxy", "", "")["success"] == true)
			check("existing_proxy_tunnel_works", ask("held", "", "")["success"] == true)
			child := ask("child", "", "")
			check("known_child_started", child["success"] == true)
			if child["success"] != true {
				t.Fatalf("Fixture stopped before child check: %v %s", read(), output.String())
			}
			childHandle, childErr := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(child["childPid"].(float64)))
			if childErr != nil {
				t.Fatal(childErr)
			}
			defer windows.CloseHandle(childHandle)
			endpoint := systemEcho(t, "tcp4", "0")
			check("unrelated_control_before", systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-address", endpoint))
			switch scenario {
			case "stop":
				os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
			case "tcp4", "tcp6", "udp4", "udp6":
				target := systemEcho(t, scenario, "0")
				check("direct_observer_reachable_before", systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-network", scenario, "-address", target))
				ask("direct", scenario, target)
				check("direct_observer_reachable_after", systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-network", scenario, "-address", target))
			case "proxy_failure":
				stopUpstream()
			case "parent_exit":
				parentActor.Process.Kill()
				parentActor.Wait()
			case "port_takeover":
				check("proxy_tunnel_closed_before_port_probe", ask("drop-held", "", "")["success"] == true)
				resume := pauseOwnedGuestGuardian(t, uint32(command.Process.Pid), uint32(initial["supervisorThreadId"].(float64)))
				stopUpstream()
				row := ask("bind-trusted", "", "")
				record["portTakeoverTrustedImageResult"] = row
				stage, _ := os.ReadFile(filepath.Join(fixtureFolder, "bind-stage.json"))
				record["portBindStage"] = string(stage)
				if row["accessDenied"] != true {
					t.Logf("Trusted-image bind fixture result: %v", row)
				}
				check("same_image_other_user_cannot_take_proxy_port", row["success"] == false && row["accessDenied"] == true && row["fixtureError"] != true)
				out, e := exec.Command(filepath.Join(root, "control", "session-fixture.exe"), "-session-fixture", folder, "-bind-only", "127.0.0.1:"+port).Output()
				var bind map[string]any
				json.Unmarshal(out, &bind)
				check("other_image_cannot_take_proxy_port", e == nil && bind["success"] == false && bind["accessDenied"] == true)
				resume()
			case "policy_changed", "monitor_unavailable":
				action := "fault-policy"
				if scenario == "monitor_unavailable" {
					action = "fault-monitor"
				}
				check("guest_fault_injection_succeeded", exec.Command(guardian, action, folder).Run() == nil)
			case "unknown_child":
				if user {
					target, wireCount := capsuleWireEcho(t, "tcp4")
					check("unknown_observer_control_before", systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-address", target))
					before := wireCount()
					ask("unknown", "tcp4", target)
					time.Sleep(300 * time.Millisecond)
					check("unlisted_child_first_packet_not_received", before > 0 && wireCount() == before)
				} else {
					ask("unknown", "", "")
				}
			case "guardian_crash":
				command.Process.Kill()
				command.Wait()
				waited = true
				_, err := windows.WaitForSingleObject(handle, 5000)
				check("root_wait_completed", err == nil)
				check("persistent_rules_after_guardian_crash", inspect() == ruleCount)
				bad := bytes.Replace(request, []byte("\n"+port+"\n"), []byte("\n1024\n"), 1)
				os.WriteFile(filepath.Join(folder, "request.txt"), bad, 0600)
				err = exec.Command(guardian, "recover", folder).Run()
				check("wrong_recovery_port_refused", err != nil && inspect() == ruleCount)
				os.WriteFile(filepath.Join(folder, "request.txt"), request, 0600)
				err = exec.Command(guardian, "recover", folder).Run()
				check("fresh_process_recovers_owned_rules", err == nil && inspect() == 0)
			}
			if !waited {
				final := waitState("stopped", "failed", "cleanup_required")
				record["final"] = final
				expected := map[string]string{"stop": "user_stopped", "proxy_failure": "proxy_unavailable", "unknown_child": "unlisted_component"}[scenario]
				if user && scenario == "unknown_child" {
					expected = "bypass_blocked"
				}
				if scenario == "policy_changed" || scenario == "monitor_unavailable" {
					expected = scenario
				}
				if scenario == "port_takeover" {
					expected = "proxy_unavailable"
				}
				if scenario == "parent_exit" {
					expected = "desktop_exited"
				}
				if expected == "" {
					expected = "bypass_blocked"
				}
				check("expected_termination_reason", final["reason"] == expected)
				check("normal_cleanup_verified", final["state"] == "stopped" && final["filterCount"] == float64(0))
				if user && final["state"] != "stopped" {
					details, _ := os.ReadFile(filepath.Join(folder, "identity-error.json"))
					t.Logf("Identity cleanup diagnostic: %s", details)
				}
				command.Wait()
				waited = true
			}
			rootWait, rootErr := windows.WaitForSingleObject(handle, 5000)
			childWait, err := windows.WaitForSingleObject(childHandle, 5000)
			check("root_process_terminated", rootErr == nil && rootWait == windows.WAIT_OBJECT_0)
			check("descendant_terminated", err == nil && childWait == windows.WAIT_OBJECT_0)
			check("unrelated_control_after", systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-address", endpoint))
			check("independent_filter_inventory_zero", inspect() == 0)
			if scenario == "port_takeover" {
				out, e := exec.Command(filepath.Join(root, "control", "session-fixture.exe"), "-session-fixture", folder, "-bind-only", "127.0.0.1:"+port).Output()
				var row map[string]any
				json.Unmarshal(out, &row)
				check("same_bind_probe_works_after_explicit_cleanup", e == nil && row["success"] == true)
			}
			record["proxyPort"], _ = strconv.Atoi(port)
		})
	}
}
