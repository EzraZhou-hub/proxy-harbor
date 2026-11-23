//go:build p0system && windows

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The only executable launched through the candidate is our sibling temporary
// probe. No installed application or arbitrary user-supplied path is accepted.
func TestP0TransparentInterception(t *testing.T) {
	working, err := os.Getwd()
	if err != nil || !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("Transparent interception tests are guest-only")
	}
	binaryDirectory := filepath.Join(working, ".local", "p0", "bin")
	guard := filepath.Join(binaryDirectory, "p0-relay-guard.exe")
	helperGuard := filepath.Join(binaryDirectory, "p0-helper-guard.exe")
	helperProbe := filepath.Join(binaryDirectory, "helpers", "proxy-harbor-p0-helper.exe")
	probe := filepath.Join(binaryDirectory, "proxy-harbor-p0-probe.exe")
	control := filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe")
	relay := filepath.Join(binaryDirectory, "proxy-harbor-p0-relay.exe")
	candidate := filepath.Join(binaryDirectory, "transparent", "proxychains_win32_x64.exe")
	before := systemGuard(t, guard, "inspect")
	if before["elevated"] != true || before["rulesPresent"] != float64(0) {
		t.Fatal("Expected an elevated disposable guest with no relay policy")
	}
	cases := []*relayCaseReport{}
	defer func() {
		report := map[string]any{"schemaVersion": 1, "generatedAt": time.Now().UTC().Format(time.RFC3339Nano), "overall": "not_accepted", "scope": "Only temporary probe; Winsock hostname/IPv4, no complete DNS API coverage claim", "cases": cases}
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", "transparent-policy-report.json"), data, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	for _, protocol := range []string{"http", "https", "socks5"} {
		for _, auth := range []bool{false, true} {
			record := &relayCaseReport{Protocol: protocol, Auth: auth, Checks: map[string]bool{}, Cleanup: "not_needed"}
			cases = append(cases, record)
			t.Run(fmt.Sprintf("%s/auth=%v", protocol, auth), func(t *testing.T) {
				check := func(name string, success bool) {
					t.Helper()
					record.Checks[name] = success
					if !success {
						t.Fatalf("Transparent observation failed: %s", name)
					}
				}
				upstreamAddress, certificate, targets, stopUpstream := systemProxy(t, protocol, auth)
				defer stopUpstream()
				address, stopRelay, relayPID := systemRelayWithPID(t, relay, protocol, upstreamAddress, certificate, auth)
				defer stopRelay()
				_, port, _ := net.SplitHostPort(address)
				configuration := "strict_chain\nproxy_dns\nremote_dns_subnet_cidr_v4 198.18.0.0/15\nuse_fake_ip_when_hostname_not_matched 1\nresolve_locally_if_match_hosts 0\nmap_resolved_ip_to_host 0\nsearch_for_host_by_resolved_ip 0\nfirst_tunnel_uses_ipv4 1\nfirst_tunnel_uses_ipv6 0\ndefault_target PROXY\ntcp_connect_time_out 1000\ntcp_read_time_out 1000\nlog_level 200\n[ProxyList]\nsocks5 127.0.0.1 " + port + "\n"
				configurationPath := filepath.Join(t.TempDir(), "proxychains.conf")
				if err := os.WriteFile(configurationPath, []byte(configuration), 0600); err != nil {
					t.Fatal(err)
				}
				defer func() {
					helperRemoved, helperErr := systemGuardResult(helperGuard, "remove-fixture-only")
					removed, err := systemGuardResult(guard, "remove-fixture-only")
					if err != nil || removed["rulesPresent"] != float64(0) || helperErr != nil || helperRemoved["rulesPresent"] != float64(0) {
						record.Cleanup = "failed"
						t.Errorf("Transparent guard cleanup: %v %v", removed, err)
						return
					}
					record.Cleanup = "verified"
				}()
				installed := systemGuard(t, guard, "install-fixture-only", port)
				check("persistent_guard_installed", installed["rulesPresent"] == float64(4))
				helperInstalled := systemGuard(t, helperGuard, "install-fixture-only", port)
				check("helper_guard_installed_before_launch", helperInstalled["rulesPresent"] == float64(4))
				check("helper_unhooked_direct_blocked", !systemProbe(t, helperProbe, "-transparent-target", "198.51.100.7:443"))
				check("non_intercepted_ipv4_blocked", !systemProbe(t, probe, "-transparent-target", "198.51.100.7:443"))
				for _, scenario := range []struct {
					api, target string
					depth       int
					helper      bool
				}{
					{"winsock", "no-local-dns.proxy-harbor.invalid:443", 0, false}, {"winsock", "198.51.100.7:443", 0, false},
					{"getaddrinfoex-w", "no-local-dns.proxy-harbor.invalid:443", 0, false}, {"getaddrinfoex-a", "no-local-dns.proxy-harbor.invalid:443", 0, false},
					{"dnsquery-w", "no-local-dns.proxy-harbor.invalid:443", 0, false}, {"dnsquery-a", "no-local-dns.proxy-harbor.invalid:443", 0, false},
					{"dnsquery-utf8", "no-local-dns.proxy-harbor.invalid:443", 0, false}, {"dnsqueryex-sync", "no-local-dns.proxy-harbor.invalid:443", 0, false},
					{"getaddrinfoex-async", "no-local-dns.proxy-harbor.invalid:443", 0, false}, {"dnsqueryex-async", "no-local-dns.proxy-harbor.invalid:443", 0, false},
					{"winsock", "no-local-dns.proxy-harbor.invalid:443", 1, false},
					{"winsock", "no-local-dns.proxy-harbor.invalid:443", 2, false},
					{"dnsqueryex-sync", "no-local-dns.proxy-harbor.invalid:443", 2, false},
					{"dnsqueryex-async", "no-local-dns.proxy-harbor.invalid:443", 2, false},
					{"winsock", "no-local-dns.proxy-harbor.invalid:443", 1, true},
					{"dnsqueryex-sync", "no-local-dns.proxy-harbor.invalid:443", 2, true},
					{"dnsqueryex-async", "no-local-dns.proxy-harbor.invalid:443", 2, true},
					{"dnsqueryex-cancel", "no-local-dns.proxy-harbor.invalid:443", 2, true},
					{"dnsquery-raw-blocked", "no-local-dns.proxy-harbor.invalid:443", 2, true},
				} {
					target := scenario.target
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					command := exec.CommandContext(ctx, candidate, "-q", "-f", configurationPath, probe, "-transparent-target", target, "-resolve-api", scenario.api, "-spawn-depth", fmt.Sprint(scenario.depth), fmt.Sprintf("-use-helper=%v", scenario.helper))
					command.Env = append(os.Environ(), fmt.Sprintf("P0_EXPECTED_RELAY_PID=%d", relayPID))
					var stderr bytes.Buffer
					command.Stderr = &stderr
					output, err := command.Output()
					cancel()
					name := scenario.api + "_domain"
					if strings.HasPrefix(target, "198.") {
						name = "winsock_ipv4"
					}
					if scenario.depth > 0 {
						name += fmt.Sprintf("_depth%d", scenario.depth)
					}
					if scenario.helper {
						name += "_helper"
					}
					os.WriteFile(filepath.Join(t.TempDir(), name+".log"), append(append([]byte(nil), output...), stderr.Bytes()...), 0600)
					var success bool
					for _, line := range bytes.Split(output, []byte{'\n'}) {
						var observed struct {
							Success bool
							PIDs    []int
						}
						if json.Unmarshal(bytes.TrimSpace(line), &observed) == nil && observed.Success && len(observed.PIDs) == scenario.depth+1 {
							success = true
						}
					}
					if err != nil || !success {
						t.Logf("Candidate %s: %v stdout=%s stderr=%s", name, err, output, stderr.Bytes())
					}
					noConnectionExpected := scenario.api == "getaddrinfoex-async" || scenario.api == "dnsqueryex-cancel" || scenario.api == "dnsquery-raw-blocked"
					label := "_through_proxy"
					if noConnectionExpected {
						label = "_rejected"
						if scenario.api == "dnsqueryex-cancel" {
							label = "_cancel_completed_once"
						}
					}
					check(name+label, err == nil && success)
					if noConnectionExpected {
						select {
						case <-targets:
							check(name+"_no_upstream_request", false)
						case <-time.After(30 * time.Millisecond):
							check(name+"_no_upstream_request", true)
						}
						continue
					}
					select {
					case observed := <-targets:
						check(name+"_original_target_preserved", observed == target)
					case <-time.After(time.Second):
						check(name+"_original_target_preserved", false)
					}
				}
				endpoint := systemEcho(t, "tcp4", "0")
				check("same_name_other_path_unaffected", systemProbe(t, control, "-address", endpoint))
				stopRelay()
				check("helper_relay_exit_direct_still_blocked", !systemProbe(t, helperProbe, "-transparent-target", "198.51.100.7:443"))
				check("relay_exit_direct_still_blocked", !systemProbe(t, probe, "-transparent-target", "198.51.100.7:443"))
				replacement, err := net.Listen("tcp4", address)
				if err != nil {
					t.Fatal(err)
				}
				defer replacement.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				command := exec.CommandContext(ctx, candidate, "-q", "-f", configurationPath, probe, "-transparent-target", "no-local-dns.proxy-harbor.invalid:443")
				command.Env = append(os.Environ(), fmt.Sprintf("P0_EXPECTED_RELAY_PID=%d", relayPID))
				output, err := command.Output()
				cancel()
				check("replacement_entry_rejected", err != nil && !bytes.Contains(output, []byte(`"success":true`)))
				replacement.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
				connection, err := replacement.Accept()
				if err == nil {
					connection.Close()
				}
				check("replacement_received_no_connection", err != nil)
			})
		}
	}
}
