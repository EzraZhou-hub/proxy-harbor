//go:build p0system && windows

package engine

import (
	"bufio"
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

func TestP0TemporarySystemDNSBlock(t *testing.T) {
	recoveryGuest(t)
	root := `C:\P0Lab\.local\p0`
	checks := map[string]bool{}
	report := map[string]any{"checks": checks, "scope": "Temporary system-wide port 53/853 block; shared default DNS and restoration. No claim about arbitrary HTTPS DoH."}
	t.Cleanup(func() {
		report["cleanup"] = "verified"
		for _, ok := range checks {
			if !ok {
				report["cleanup"] = "not_verified"
			}
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "temporary-dns-block-report.json"), data, 0600)
	})
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("DNS block: %s", name)
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
	const owner = "ProxyHarbor.P0.TemporaryDNSBlock"
	if err := ps(`if(@(Get-DnsClientNrptRule|Where-Object {$_.Namespace -contains '.p0-dns-audit.invalid'}).Count){throw 'Existing observer'};Add-DnsClientNrptRule -Namespace '.p0-dns-audit.invalid' -NameServers '127.0.0.1' -DisplayName '` + owner + `'|Out-Null`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := ps(`Get-DnsClientNrptRule|Where-Object {$_.DisplayName -eq '` + owner + `' -and @($_.Namespace).Count -eq 1 -and $_.Namespace -contains '.p0-dns-audit.invalid'}|ForEach-Object {Remove-DnsClientNrptRule -Name $_.Name -Force};if(@(Get-DnsClientNrptRule|Where-Object DisplayName -eq '` + owner + `').Count){throw 'NRPT remains'}`)
		check("observer_configuration_removed", err == nil)
	})
	query := func() bool {
		t.Helper()
		name := fmt.Sprintf("%016x.p0-dns-audit.invalid", uint64(time.Now().UnixNano()))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
		success := err == nil && len(addresses) > 0 && len(wire(name)) > 0
		if !success {
			check("blocked_query_absent_at_observer_"+strings.Split(name, ".")[0], len(wire(name)) == 0)
		}
		return success
	}
	inspect := func(want int) bool {
		out, err := exec.Command(filepath.Join(root, "bin", "dns-block-lab.exe"), "inspect").Output()
		var result struct {
			Rules int
			Error uint32
		}
		return err == nil && json.Unmarshal(out, &result) == nil && result.Error == 0 && result.Rules == want
	}
	peers := map[string]string{}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		peers[network] = systemEcho(t, network, "853")
	}
	reachable := func(network, address string) bool {
		c, err := net.DialTimeout(network, address, 500*time.Millisecond)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = c.Write([]byte("dns-protection-test"))
		if err != nil {
			return false
		}
		var data [64]byte
		n, err := c.Read(data[:])
		return err == nil && string(data[:n]) == "dns-protection-test"
	}
	check("no_initial_rules", inspect(0))
	for network, address := range peers {
		check(network+"_observer_positive", reachable(network, address))
	}
	check("system_dns_before", query())
	for _, mode := range []string{"normal_exit", "forced_exit", "system_exit", "system_forced_exit", "service_exit"} {
		cmd := exec.Command(filepath.Join(root, "bin", "dns-block-lab.exe"))
		rules := 4
		if strings.HasPrefix(mode, "system_") {
			cmd.Args = append(cmd.Args, "system")
			rules = 6
		}
		if mode == "service_exit" {
			cmd.Args = append(cmd.Args, "service")
			rules = 2
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waited := false
		defer func() {
			if !waited {
				cmd.Process.Kill()
				cmd.Wait()
			}
		}()
		line, err := bufio.NewReader(stdout).ReadBytes('\n')
		var ready struct {
			Ready bool
			Error uint32
		}
		if err != nil || json.Unmarshal(line, &ready) != nil || !ready.Ready || ready.Error != 0 {
			t.Fatalf("Guard failed to start: %s %v", line, err)
		}
		check(mode+"_rules_present", inspect(rules))
		check(mode+"_shared_dns_blocked", !query())
		for network, address := range peers {
			check(mode+"_"+network+"_transport_result", reachable(network, address) == (mode == "service_exit"))
		}
		forced := strings.Contains(mode, "forced_exit")
		if forced {
			cmd.Process.Kill()
		} else {
			stdin.Close()
		}
		err = cmd.Wait()
		waited = true
		check(mode+"_process_result", (err == nil) == !forced)
		check(mode+"_rules_removed", inspect(0))
		check(mode+"_system_dns_restored", query())
		for network, address := range peers {
			check(mode+"_"+network+"_restored", reachable(network, address))
		}
	}
}
