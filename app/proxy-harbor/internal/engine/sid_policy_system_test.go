//go:build p0system && windows

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestP0SIDPolicyUnlistedComponent(t *testing.T) {
	recoveryGuest(t)
	working, _ := os.Getwd()
	bin := filepath.Join(working, ".local", "p0", "bin")
	control := filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe")
	cases := []map[string]any{}
	cleanup := "pending"
	defer func() {
		data, _ := json.MarshalIndent(map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "An executable with no per-path application guard, inside the temporary SID policy; only the exact relay port is allowed", "cases": cases, "cleanup": cleanup}, "", "  ")
		os.WriteFile(filepath.Join(working, ".local", "p0", "sid-policy-boundary-report.json"), data, 0600)
	}()
	upstream, cert, targets, stopUpstream := systemProxy(t, "http", false)
	defer stopUpstream()
	address, stopRelay := systemRelay(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream, cert, false)
	defer stopRelay()
	_, port, _ := net.SplitHostPort(address)
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			endpoint := systemEcho(t, network, "0")
			_, forbiddenPort, _ := net.SplitHostPort(endpoint)
			checks := map[string]bool{}
			item := map[string]any{"network": network, "checks": checks}
			cases = append(cases, item)
			check := func(id string, ok bool) {
				t.Helper()
				checks[id] = ok
				if !ok {
					t.Errorf("SID policy %s/%s", network, id)
				}
			}
			check("same_image_unrestricted_baseline", systemProbe(t, control, "-network", network, "-address", endpoint))
			var nonce [8]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			label := hex.EncodeToString(nonce[:])
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, filepath.Join(bin, "p0-dns-isolation.exe"), "appcontainer-wfp", label, port, "unlisted-"+network)
			command.Env = append(os.Environ(), "P0_UNLISTED_TEST_PORT="+forbiddenPort)
			output, err := command.CombinedOutput()
			var identity dnsIsolationResult
			denied, proxy := false, false
			phase := false
			for _, line := range bytes.Split(output, []byte{'\n'}) {
				var marker struct {
					IsolationPhase string `json:"isolationPhase"`
				}
				if json.Unmarshal(line, &marker) == nil && marker.IsolationPhase == "explicit_proxy" {
					phase = true
					continue
				}
				var native dnsIsolationResult
				if json.Unmarshal(line, &native) == nil && native.IsolationResult {
					identity = native
				}
				var result struct {
					Success   bool
					Detail    string
					Container bool `json:"zeroCapabilityAppContainer"`
				}
				if json.Unmarshal(line, &result) == nil && result.Container {
					if phase && result.Success && result.Detail == "echo observation" {
						proxy = true
					}
					if !phase && !result.Success && strings.Contains(result.Detail, network) && strings.Contains(result.Detail, forbiddenPort) {
						denied = true
					}
				}
			}
			item["isolation"] = identity
			item["output"] = string(output)
			check("native_scope_completed", err == nil && identity.Error == 0 && identity.ChildExitCode == 1 && identity.ProxyChildExitCode == 0)
			check("unlisted_component_direct_denied", denied)
			check("same_identity_proxy_works", proxy)
			check("no_debug_exemption", !identity.LoopbackEnabled && identity.IsAppContainer == 1 && identity.CapabilityCount == 0)
			check("policy_and_permissions_restored", identity.PackageRulesInstalled == 6 && identity.PackagePolicyRestored && identity.ACLRestored && identity.ProfileDeleted)
			inventory, e := systemGuardResult(filepath.Join(bin, "p0-isolation-inspect.exe"), "inspect")
			check("independent_inventory_zero", e == nil && inventory["rulesPresent"] == float64(0))
			select {
			case target := <-targets:
				check("domain_preserved_at_upstream", target == label+".p0-dns-audit.invalid:443")
			case <-time.After(time.Second):
				check("domain_preserved_at_upstream", false)
			}
			check("same_image_unrestricted_after_cleanup", systemProbe(t, control, "-network", network, "-address", endpoint))
		})
	}
	inventory, err := systemGuardResult(filepath.Join(bin, "p0-isolation-inspect.exe"), "inspect")
	if err == nil && inventory["rulesPresent"] == float64(0) {
		cleanup = "verified"
	} else {
		cleanup = "failed"
		t.Error("SID policy boundary cleanup failed")
	}
}
