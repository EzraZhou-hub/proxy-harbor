//go:build p0system && windows

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestP0PublicNetworkGuard(t *testing.T) {
	working, _ := os.Getwd()
	if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("Public network guard test is guest-only")
	}
	var manifest struct {
		PublicNetwork bool `json:"publicNetwork"`
		IPv4Only      bool `json:"publicIPv4Only"`
	}
	data, err := os.ReadFile(filepath.Join(working, "manifest.json"))
	if err != nil || json.Unmarshal(data, &manifest) != nil || !manifest.PublicNetwork {
		t.Fatal("Explicit networked validation package required")
	}
	bin := filepath.Join(working, ".local", "p0", "bin")
	probe := filepath.Join(bin, "proxy-harbor-p0-probe.exe")
	control := filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe")
	guard := filepath.Join(bin, "p0-relay-guard.exe")
	cases := []map[string]any{}
	cleanup := "not_needed"
	allAvailable := true
	defer func() {
		report := map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "Network-enabled disposable guest, fixed Cloudflare DNS TCP/UDP responses, no system DNS changes", "ipv4OnlyRequested": manifest.IPv4Only, "allBaselinesAvailable": allAvailable, "cases": cases, "cleanup": cleanup, "publicIPv6Coverage": "not_verified"}
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", "public-network-report.json"), encoded, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	if r := systemGuard(t, guard, "inspect"); r["rulesPresent"] != float64(0) {
		t.Fatal("Clean guard required")
	}
	run := func(exe, network, address string, observe ...bool) map[string]any {
		observed := len(observe) > 0 && observe[0]
		budget := 7 * time.Second
		if observed {
			budget = 12 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		arguments := []string{"-public-wire", "-network", network, "-address", address}
		if observed {
			exe = filepath.Join(bin, "p0-net-events.exe")
			arguments = []string{"observe-fixed-public-udp"}
		}
		out, commandError := exec.CommandContext(ctx, exe, arguments...).Output()
		record := map[string]any{}
		var observation map[string]any
		for _, line := range bytes.Split(out, []byte{'\n'}) {
			parsed := map[string]any{}
			if json.Unmarshal(line, &parsed) != nil {
				continue
			}
			if parsed["publicWire"] == true {
				record = parsed
			}
			if parsed["netEventObservation"] == true {
				observation = parsed
			}
		}
		if observed {
			record["wfpObservation"] = observation
			record["observerCompleted"] = commandError == nil
		}
		return record
	}
	networks := []string{"tcp4", "udp4", "tcp6", "udp6"}
	if manifest.IPv4Only {
		networks = networks[:2]
	}
	for _, network := range networks {
		address := "1.1.1.1:53"
		if strings.HasSuffix(network, "6") {
			address = "[2606:4700:4700::1111]:53"
		}
		baseline := run(control, network, address)
		item := map[string]any{"network": network, "baseline": baseline, "checks": map[string]bool{}, "outcome": "not_verified"}
		cases = append(cases, item)
		if baseline["success"] != true {
			allAvailable = false
			item["outcome"] = "environment_baseline_unavailable"
			t.Logf("%s baseline unavailable: %v", network, baseline)
			continue
		}
		checks := item["checks"].(map[string]bool)
		defer func() {
			r, e := systemGuardResult(guard, "remove-fixture-only")
			if e != nil || r["rulesPresent"] != float64(0) {
				cleanup = "failed"
				t.Error("Public guard cleanup", r, e)
			} else if cleanup != "failed" {
				cleanup = "verified"
			}
		}()
		cleanup = "pending"
		checks["four_rules"] = systemGuard(t, guard, "install-fixture-only", "48732")["rulesPresent"] == float64(4)
		blocked := run(probe, network, address, network == "udp4")
		item["protected"] = blocked
		denialProved := blocked["accessDenied"] == true
		if network == "udp4" {
			observation, _ := blocked["wfpObservation"].(map[string]any)
			count, _ := observation["matchedProjectDropEvents"].(float64)
			denialProved = blocked["observerCompleted"] == true && observation["windowsError"] == float64(0) && observation["collectionRestored"] == true && count > 0
			checks["diagnostic_collection_restored"] = observation["collectionRestored"] == true
		}
		checks["protected_denied_with_kernel_evidence"] = blocked["publicWire"] == true && blocked["success"] == false && denialProved
		other := run(control, network, address)
		item["controlAfterBlock"] = other
		checks["other_program_still_reaches_real_endpoint"] = other["success"] == true
		checks["explicit_rule_remove"] = systemGuard(t, guard, "remove-fixture-only")["rulesPresent"] == float64(0)
		restored := run(probe, network, address)
		item["restored"] = restored
		checks["same_protected_program_restored"] = restored["success"] == true
		item["outcome"] = "bounded_public_path_passed"
		for name, ok := range checks {
			if !ok {
				item["outcome"] = "failed"
				t.Errorf("Public %s/%s: %v", network, name, item)
			}
		}
	}
}
