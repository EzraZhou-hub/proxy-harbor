//go:build p0system && windows

package engine

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func recoveryGuest(t *testing.T) {
	t.Helper()
	cwd, _ := os.Getwd()
	if !strings.EqualFold(cwd, `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("Recovery tests require the isolated guest")
	}
}

func recoveryCommand(t *testing.T, action string, extra ...string) (map[string]any, error) {
	t.Helper()
	args := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", `C:\P0Lab\scripts\p0\guest-recovery.ps1`, "-Action", action}, extra...)
	data, err := exec.Command("powershell.exe", args...).CombinedOutput()
	if err != nil {
		return nil, err
	}
	var record map[string]any
	if err = json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Invalid recovery output: %v %s", err, data)
	}
	return record, nil
}

func TestP0RecoveryPreparation(t *testing.T) {
	recoveryGuest(t)
	// Fixed unused port: every actual echo endpoint below uses a different port.
	record, err := recoveryCommand(t, "Arm", "-Port", "48731")
	if err != nil || record["rulesPresent"] != float64(8) {
		t.Fatalf("Arm failed: %v %v", record, err)
	}
	// Fresh recovery process must observe the state without deleting policy.
	record, err = recoveryCommand(t, "Status")
	if err != nil || record["state"] != "blocked_pending_recovery" || record["automaticRelease"] != false {
		t.Fatalf("Restarted controller lost state: %v %v", record, err)
	}
	for _, name := range []string{"proxy-harbor-p0-probe.exe", `helpers\proxy-harbor-p0-helper.exe`} {
		if systemProbe(t, filepath.Join(`C:\P0Lab\.local\p0\bin`, name), "-address", systemEcho(t, "tcp4", "0")) {
			t.Fatal("Before reboot fixture escaped blocking")
		}
	}
	// Leave persistent rules deliberately installed for the authorized guest reboot.
}

func TestP0RecoveryAfterBoot(t *testing.T) {
	recoveryGuest(t)
	before, err := os.ReadFile(`C:\P0Lab\.local\p0\reboot-before.txt`)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(`C:\P0Lab\.local\p0\reboot-after.txt`)
	if err != nil || string(before) == string(after) {
		t.Fatal("Guest boot identity did not change")
	}
	checks := map[string]bool{"guest_boot_changed": true}
	defer func() {
		data, _ := json.MarshalIndent(map[string]any{"checks": checks, "overall": "not_accepted"}, "", "  ")
		os.WriteFile(`C:\P0Lab\.local\p0\reboot-policy-report.json`, data, 0600)
	}()
	check := func(name string, success bool) {
		t.Helper()
		checks[name] = success
		if !success {
			t.Fatal(name)
		}
	}
	status, err := recoveryCommand(t, "Status")
	check("rules_survived_guest_restart", err == nil && status["rulesPresent"] == float64(8) && status["state"] == "blocked_pending_recovery")
	paths := map[string]string{"parent": `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-probe.exe`, "helper": `C:\P0Lab\.local\p0\bin\helpers\proxy-harbor-p0-helper.exe`}
	endpoints := map[string]string{}
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		endpoints[network] = systemEcho(t, network, "0")
		for name, path := range paths {
			check(name+"_"+network+"_blocked_before_recovery", !systemProbe(t, path, "-network", network, "-address", endpoints[network]))
		}
		check("control_"+network+"_unaffected", systemProbe(t, `C:\P0Lab\.local\p0\control\proxy-harbor-p0-probe.exe`, "-network", network, "-address", endpoints[network]))
	}
	journal := `C:\P0Lab\.local\p0\policy-session.json`
	original, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(journal, []byte("{"), 0600)
	_, err = recoveryCommand(t, "Release")
	os.WriteFile(journal, original, 0600)
	check("damaged_journal_refuses_release", err != nil)
	status, err = recoveryCommand(t, "Status")
	check("damaged_journal_kept_rules", err == nil && status["rulesPresent"] == float64(8))
	status, err = recoveryCommand(t, "Release")
	check("explicit_release_cleared_owned_rules", err == nil && status["rulesPresent"] == float64(0))
	status, err = recoveryCommand(t, "Release")
	check("release_is_idempotent", err == nil && status["rulesPresent"] == float64(0))
	for network, endpoint := range endpoints {
		for name, path := range paths {
			check(name+"_"+network+"_restored", systemProbe(t, path, "-network", network, "-address", endpoint))
		}
	}
}
