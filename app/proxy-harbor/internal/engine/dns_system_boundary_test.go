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

// A private .invalid NRPT entry is an observation fixture, not a protection
// policy. It exists only in the disposable guest, points at a real local DNS
// observer, and is removed by exact ownership on every normal exit.
func TestP0SystemDNSBoundary(t *testing.T) {
	systemDNSBoundary(t, "appcontainer", "dns-system-boundary-report.json")
}
func TestP0WFPDNSBoundary(t *testing.T) {
	systemDNSBoundary(t, "appcontainer-wfp", "dns-wfp-boundary-report.json")
}
func systemDNSBoundary(t *testing.T, mode, reportName string) {
	working, _ := os.Getwd()
	if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("System DNS boundary experiment is disposable-guest-only")
	}
	bin := filepath.Join(working, ".local", "p0", "bin")
	guard := filepath.Join(bin, "p0-relay-guard.exe")
	control := filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe")
	probe := filepath.Join(bin, "proxy-harbor-p0-probe.exe")
	if status := systemGuard(t, guard, "inspect"); status["elevated"] != true || status["rulesPresent"] != float64(0) {
		t.Fatal("A clean elevated guest is required")
	}
	wire := dnsCoverageObserver(t)
	servicePID, serviceState, serviceError := dnsServiceStatus()
	cases := []map[string]any{}
	cleanup, nrptCleanup := "not_needed", "not_needed"
	defer func() {
		report := map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "Controlled default resolver, cache and zero-capability AppContainer; not arbitrary application acceptance", "cases": cases, "cleanup": cleanup, "nrptCleanup": nrptCleanup, "dnsServicePid": servicePID, "dnsServiceState": serviceState, "dnsServiceError": serviceError, "applicationProtectionVerified": false}
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", reportName), data, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	ps := func(script string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';"+script).CombinedOutput()
	}
	const owner = "ProxyHarbor.P0.DefaultDNS.OfflineFixture"
	before, err := ps(`$r=@(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq '` + owner + `' -or $_.Namespace -contains '.p0-dns-audit.invalid' }); if($r.Count){throw 'Observation namespace already configured'}; 'clean'`)
	if err != nil || !bytes.Contains(before, []byte("clean")) {
		t.Fatalf("NRPT preflight failed: %v %s", err, before)
	}
	// Write recovery instructions before changing the guest-only fixture.
	journal := []byte(`{"scope":"guest-only .p0-dns-audit.invalid","owner":"` + owner + `","recovery":"Remove only the NRPT entry matching both exact DisplayName and exact one-element namespace"}`)
	if err := os.WriteFile(filepath.Join(working, ".local", "p0", "dns-nrpt-recovery.json"), journal, 0600); err != nil {
		t.Fatal(err)
	}
	nrptCleanup = "pending"
	defer func() {
		out, err := ps(`$r=@(Get-DnsClientNrptRule | Where-Object {$_.DisplayName -eq '` + owner + `'}); foreach($i in $r){if(@($i.Namespace).Count -ne 1 -or $i.Namespace[0] -ne '.p0-dns-audit.invalid' -or @($i.NameServers).Count -ne 1 -or $i.NameServers[0] -ne '127.0.0.1'){throw 'Refusing unexpected NRPT owner object'}; Remove-DnsClientNrptRule -Name $i.Name -Force}; if(@(Get-DnsClientNrptRule | Where-Object {$_.DisplayName -eq '` + owner + `'}).Count){throw 'NRPT entry remains'}; 'verified'`)
		if err != nil || !bytes.Contains(out, []byte("verified")) {
			nrptCleanup = "failed"
			t.Errorf("NRPT cleanup: %v %s", err, out)
		} else {
			nrptCleanup = "verified"
		}
	}()
	if out, err := ps(`Add-DnsClientNrptRule -Namespace '.p0-dns-audit.invalid' -NameServers '127.0.0.1' -DisplayName '` + owner + `' | Out-Null; 'installed'`); err != nil || !bytes.Contains(out, []byte("installed")) {
		t.Fatalf("NRPT fixture install: %v %s", err, out)
	}
	upstream, cert, targets, stopUpstream := systemProxy(t, "http", false)
	defer stopUpstream()
	address, stopRelay, _ := systemRelayWithPID(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream, cert, false)
	defer stopRelay()
	_, port, _ := net.SplitHostPort(address)
	label := func() string {
		var data [8]byte
		if _, err := rand.Read(data[:]); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(data[:])
	}
	invoke := func(id, scenario, hostLabel string, isolated bool) (dnsAuditProbe, dnsIsolationResult, []dnsWireEvent) {
		host := hostLabel + ".p0-dns-audit.invalid"
		beforeCount := len(wire(host))
		executable, args := control, []string{"-dns-audit", scenario, "-dns-audit-name", host}
		if isolated {
			executable, args = filepath.Join(bin, "p0-dns-isolation.exe"), []string{mode, hostLabel, port, scenario}
		} else if strings.HasPrefix(id, "guard_") {
			executable = probe
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, args...)
		output, err := command.CombinedOutput()
		var result dnsAuditProbe
		var identity dnsIsolationResult
		proxyOK := false
		for _, line := range bytes.Split(output, []byte{'\n'}) {
			var p dnsAuditProbe
			if json.Unmarshal(line, &p) == nil && p.Success && p.Name == host {
				result = p
			}
			var native dnsIsolationResult
			if json.Unmarshal(line, &native) == nil && native.IsolationResult {
				identity = native
			}
			var echo struct {
				Success bool
				Detail  string
			}
			if json.Unmarshal(line, &echo) == nil && echo.Success && echo.Detail == "echo observation" {
				proxyOK = true
			}
		}
		time.Sleep(60 * time.Millisecond)
		events := wire(host)[beforeCount:]
		checks := map[string]bool{"fixture_completed": err == nil && result.Success && len(result.Entries) == 1}
		if isolated {
			checks["identity_verified"] = identity.Error == 0 && identity.IsAppContainer == 1 && identity.CapabilityCount == 0 && identity.PackageSIDAccess && identity.AllPackagesAccess
			checks["scope_restored"] = identity.ACLRestored && identity.ProfileDeleted && identity.LoopbackEnabled == (mode == "appcontainer") && identity.LoopbackRestored
			if mode == "appcontainer-wfp" {
				inventory, err := systemGuardResult(filepath.Join(bin, "p0-isolation-inspect.exe"), "inspect")
				checks["sid_policy_installed_and_restored"] = identity.PackageRulesInstalled == 6 && identity.PackagePolicyRestored && err == nil && inventory["rulesPresent"] == float64(0)
			}
			checks["proxy_usable_in_same_identity"] = proxyOK && identity.ProxyChildExitCode == 0
			select {
			case target := <-targets:
				checks["proxy_domain_preserved"] = target == host+":443"
			case <-time.After(time.Second):
				checks["proxy_domain_preserved"] = false
			}
		}
		item := map[string]any{"id": id, "scenario": scenario, "probe": result, "isolation": identity, "newWireEvents": events, "checks": checks}
		cases = append(cases, item)
		for name, ok := range checks {
			if !ok {
				t.Errorf("%s/%s: %v output=%s", id, name, err, output)
			}
		}
		return result, identity, events
	}
	// Default resolver must be demonstrably reachable before considering silence
	// under restriction. Each cold query has a new nonce; no global cache flush.
	for _, scenario := range []string{"w", "a", "utf8", "ex-sync", "ex-async", "ex-system"} {
		p, _, events := invoke("baseline_"+scenario, scenario, label(), false)
		valid := len(p.Entries) == 1 && p.Entries[0].Status == 0 && p.Entries[0].Address == "198.51.100.77" && len(events) > 0
		cases[len(cases)-1]["checks"].(map[string]bool)["default_resolver_positive_control"] = valid
		if !valid {
			t.Fatalf("Default resolver positive control unavailable for %s: %+v events=%+v", scenario, p, events)
		}
	}
	if installed := systemGuard(t, guard, "install-fixture-only", port); installed["rulesPresent"] != float64(4) {
		t.Fatal("Guard installation failed")
	}
	cleanup = "pending"
	defer func() {
		removed, err := systemGuardResult(guard, "remove-fixture-only")
		if err != nil || removed["rulesPresent"] != float64(0) {
			cleanup = "failed"
			t.Error("System DNS guard cleanup failed")
		} else {
			cleanup = "verified"
		}
	}()
	for _, scenario := range []string{"w", "a", "utf8", "ex-sync", "ex-async", "ex-system", "ex-custom-server"} {
		invoke("guard_"+scenario, scenario, label(), false)
		p, _, events := invoke("isolated_cold_"+scenario, scenario, label(), true)
		denied := len(events) == 0 && len(p.Entries) == 1 && p.Entries[0].Status == 5 && !p.Entries[0].Records
		cases[len(cases)-1]["checks"].(map[string]bool)["cold_dns_denied_without_wire"] = denied
		if !denied {
			t.Errorf("Isolation did not independently deny cold %s: %+v wire=%+v", scenario, p, events)
		}
	}
	for _, scenario := range []string{"w-cache-only", "ex-cache-only"} {
		hostLabel := label()
		p, _, events := invoke("warm_seed_"+scenario, "w", hostLabel, false)
		if len(events) == 0 || len(p.Entries) != 1 || p.Entries[0].Status != 0 {
			t.Errorf("Warm cache seed failed: %+v", p)
		}
		p, _, events = invoke("warm_cache_control_"+scenario, scenario, hostLabel, false)
		warm := len(events) == 0 && len(p.Entries) == 1 && p.Entries[0].Status == 0 && p.Entries[0].Records && p.Entries[0].Address == "198.51.100.77"
		cases[len(cases)-1]["checks"].(map[string]bool)["system_cache_is_actually_warm"] = warm
		if !warm {
			t.Errorf("Cache-only positive control failed: %+v wire=%+v", p, events)
		}
		p, _, events = invoke("isolated_warm_"+scenario, scenario, hostLabel, true)
		// Warm cache results are measured, not counted as remote DNS success.
		cases[len(cases)-1]["checks"].(map[string]bool)["cache_only_no_wire"] = len(events) == 0
		if len(events) != 0 {
			t.Errorf("Cache-only request emitted DNS: %+v", events)
		}
		t.Logf("%s status=%v records=%v", scenario, p.Entries, len(events))
	}
	fmt.Fprintln(os.Stdout, "Default DNS boundary observations saved separately from production acceptance")
}
