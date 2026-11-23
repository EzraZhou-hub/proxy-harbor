//go:build p0system && windows

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestP0SessionDNSRPCGuard(t *testing.T) {
	recoveryGuest(t)
	root := `C:\P0Lab\.local\p0`
	report := map[string]any{"scope": "Guest-only per-account RPC filter and default DNS observer"}
	t.Cleanup(func() {
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "rpc-dns-report.json"), data, 0600)
	})
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
	const owner = "ProxyHarbor.P0.RPCDNS"
	if err := ps(`if(@(Get-DnsClientNrptRule|Where-Object {$_.Namespace -contains '.p0-dns-audit.invalid'}).Count){throw 'Existing observer'};Add-DnsClientNrptRule -Namespace '.p0-dns-audit.invalid' -NameServers '127.0.0.1' -DisplayName '` + owner + `'|Out-Null`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := ps(`Get-DnsClientNrptRule|Where-Object {$_.DisplayName -eq '` + owner + `' -and @($_.Namespace).Count -eq 1 -and $_.Namespace -contains '.p0-dns-audit.invalid'}|ForEach-Object {Remove-DnsClientNrptRule -Name $_.Name -Force}`)
		report["nrptRemoved"] = err == nil
		if err != nil {
			t.Error(err)
		}
	})
	for i, mode := range []string{"control", "filtered"} {
		name := fmt.Sprintf("%016x.p0-dns-audit.invalid", uint64(time.Now().UnixNano())+uint64(i))
		out, err := exec.Command(filepath.Join(root, "bin", "rpc-dns-lab.exe"), mode, name).CombinedOutput()
		report[mode+"Output"] = string(out)
		report[mode+"Wire"] = wire(name)
		if err != nil {
			t.Errorf("%s lab: %v %s", mode, err, out)
		}
		var result struct {
			Status  uint32 `json:"dnsStatus"`
			Records bool   `json:"records"`
		}
		if json.Unmarshal(bytes.SplitN(out, []byte{'\n'}, 2)[0], &result) != nil {
			t.Errorf("Missing DNS result: %s", out)
			continue
		}
		ok := result.Status == 0 && result.Records && len(wire(name)) > 0
		if mode == "filtered" {
			ok = result.Status != 0 && !result.Records && len(wire(name)) == 0
		}
		report[mode+"Passed"] = ok
		if !ok {
			t.Errorf("%s DNS containment failed: %s", mode, out)
		}
	}
}
