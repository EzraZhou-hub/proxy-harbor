//go:build p0system && windows

package engine

import (
	"bytes"
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
)

func TestP0IsolatedTransparentKernel(t *testing.T) {
	isolationKernel(t, "appcontainer", "isolated-kernel-report.json")
}
func TestP0WFPIsolatedKernel(t *testing.T) {
	isolationKernel(t, "appcontainer-wfp", "wfp-isolated-kernel-report.json")
}
func isolationKernel(t *testing.T, mode, reportName string) {
	working, _ := os.Getwd()
	if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("Combined kernel experiment is guest-only")
	}
	bin := filepath.Join(working, ".local", "p0", "bin")
	cases := []map[string]any{}
	defer func() {
		data, err := json.MarshalIndent(map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "Zero-capability AppContainer, transparent hooks, fixed helper descendants and persistent application/port rules; no desktop enablement", "cases": cases}, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", reportName), data, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	for _, protocol := range []string{"http", "https", "socks5"} {
		for _, auth := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/auth=%v", protocol, auth), func(t *testing.T) {
				var proofKey [32]byte
				if _, err := rand.Read(proofKey[:]); err != nil {
					t.Fatal(err)
				}
				t.Setenv("P0_RELAY_PROOF_KEY", hex.EncodeToString(proofKey[:]))
				t.Setenv("P0_PEER_TABLE_DIAGNOSTIC", "1")
				checks := map[string]bool{}
				record := map[string]any{"protocol": protocol, "auth": auth, "checks": checks, "cleanup": "pending"}
				packageClean := true
				cases = append(cases, record)
				check := func(id string, ok bool) {
					t.Helper()
					checks[id] = ok
					if !ok {
						t.Errorf("Combined kernel %s", id)
					}
				}
				upstream, cert, targets, stopUpstream := systemProxy(t, protocol, auth)
				defer stopUpstream()
				address, stopRelay, pid := systemRelayWithPID(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), protocol, upstream, cert, auth)
				defer stopRelay()
				_, port, _ := net.SplitHostPort(address)
				configuration := "strict_chain\nproxy_dns\nremote_dns_subnet_cidr_v4 198.18.0.0/15\nuse_fake_ip_when_hostname_not_matched 1\nresolve_locally_if_match_hosts 0\nmap_resolved_ip_to_host 0\nsearch_for_host_by_resolved_ip 0\nfirst_tunnel_uses_ipv4 1\nfirst_tunnel_uses_ipv6 0\ndefault_target PROXY\ntcp_connect_time_out 1000\ntcp_read_time_out 1000\nlog_level 200\n[ProxyList]\nsocks5 127.0.0.1 " + port + "\n"
				configPath := filepath.Join(bin, "isolation-transparent.conf")
				if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(configPath)
				guards := []string{filepath.Join(bin, "p0-relay-guard.exe"), filepath.Join(bin, "p0-helper-guard.exe"), filepath.Join(bin, "p0-port-guard.exe")}
				defer func() {
					ok := packageClean
					for _, guard := range guards {
						r, err := systemGuardResult(guard, "remove-fixture-only")
						if err != nil || r["rulesPresent"] != float64(0) {
							ok = false
							t.Error("Combined policy cleanup", r, err)
						}
					}
					if ok {
						record["cleanup"] = "verified"
					} else {
						record["cleanup"] = "failed"
					}
				}()
				for i, guard := range guards {
					action := "install-fixture-only"
					if i == 2 {
						action = "reserve-fixture-only"
					}
					check(fmt.Sprintf("persistent_policy_%d", i), systemGuard(t, guard, action, port)["rulesPresent"] == float64(4))
				}
				observations := []map[string]any{}
				record["observations"] = observations
				for _, scenario := range []string{"transparent-winsock-root", "transparent-winsock-child", "transparent-winsock", "transparent-dns-sync", "transparent-dns-async"} {
					var nonce [8]byte
					if _, err := rand.Read(nonce[:]); err != nil {
						t.Fatal(err)
					}
					label := hex.EncodeToString(nonce[:])
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					command := exec.CommandContext(ctx, filepath.Join(bin, "p0-dns-isolation.exe"), mode, label, port, scenario)
					command.Env = append(os.Environ(), fmt.Sprintf("P0_EXPECTED_RELAY_PID=%d", pid))
					output, err := command.CombinedOutput()
					cancel()
					var identity dnsIsolationResult
					explicitPhase := false
					chainOK, proxyOK := false, false
					for _, line := range bytes.Split(output, []byte{'\n'}) {
						var phase struct {
							IsolationPhase string `json:"isolationPhase"`
						}
						if json.Unmarshal(line, &phase) == nil && phase.IsolationPhase == "explicit_proxy" {
							explicitPhase = true
							continue
						}
						var native dnsIsolationResult
						if json.Unmarshal(line, &native) == nil && native.IsolationResult {
							identity = native
						}
						var result struct {
							Success   bool
							Detail    string
							PIDs      []int `json:"pids"`
							Container bool  `json:"zeroCapabilityAppContainer"`
						}
						if json.Unmarshal(line, &result) == nil && result.Success {
							expectedDepth := 3
							if scenario == "transparent-winsock-root" {
								expectedDepth = 1
							}
							if scenario == "transparent-winsock-child" {
								expectedDepth = 2
							}
							if !explicitPhase && len(result.PIDs) == expectedDepth && result.Container && (result.Detail == "child fixture completed" || (expectedDepth == 1 && result.Detail == "echo observation")) {
								chainOK = true
							}
							if explicitPhase && result.Detail == "echo observation" && result.Container {
								proxyOK = true
							}
						}
					}
					observations = append(observations, map[string]any{"scenario": scenario, "isolation": identity, "childChainUsable": chainOK, "explicitProxyUsable": proxyOK, "output": string(output)})
					record["observations"] = observations
					check(scenario+"_completed_and_restored", err == nil && identity.Error == 0 && identity.ACLRestored && identity.RelayACLRestored && identity.ProfileDeleted && identity.LoopbackRestored)
					check(scenario+"_zero_capability_identity", identity.IsAppContainer == 1 && identity.CapabilityCount == 0)
					if mode == "appcontainer-wfp" {
						check(scenario+"_no_debug_loopback_exemption", !identity.LoopbackEnabled)
						check(scenario+"_sid_policy_installed_and_removed", identity.PackageRulesInstalled == 6 && identity.PackagePolicyRestored)
						inventory, err := systemGuardResult(filepath.Join(bin, "p0-isolation-inspect.exe"), "inspect")
						cleared := err == nil && inventory["rulesPresent"] == float64(0)
						packageClean = packageClean && cleared && identity.PackagePolicyRestored
						check(scenario+"_independent_sid_inventory_zero", cleared)
					}
					check(scenario+"_parent_child_grandchild_proxy", identity.ChildExitCode == 0 && chainOK)
					check(scenario+"_explicit_proxy_positive_control", identity.ProxyChildExitCode == 0 && proxyOK)
					seenChain, seenExplicit := false, false
					for drain := true; drain; {
						select {
						case target := <-targets:
							if target == "no-local-dns.proxy-harbor.invalid:443" {
								seenChain = true
							}
							if target == label+".p0-dns-audit.invalid:443" {
								seenExplicit = true
							}
						case <-time.After(50 * time.Millisecond):
							drain = false
						}
					}
					check(scenario+"_upstream_original_targets", seenChain && seenExplicit)
				}
			})
		}
	}
}
