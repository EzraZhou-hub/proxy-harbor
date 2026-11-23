//go:build p0system && windows

package engine

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lifecyclePS(script string) ([]byte, error) {
	return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';"+script).CombinedOutput()
}

func TestP0SIDLifecycle(t *testing.T) {
	recoveryGuest(t)
	root := `C:\P0Lab\.local\p0`
	bin := filepath.Join(root, "bin")
	inspector := filepath.Join(bin, "p0-isolation-inspect.exe")
	checks := map[string]bool{}
	cleanup := "pending"
	report := map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "Live zero-capability SID fixture; guest NIC disable/enable with controlled loopback endpoints; no routed network handover, sleep, reboot or desktop application claim", "checks": checks}
	defer func() {
		report["cleanup"] = cleanup
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "sid-lifecycle-report.json"), data, 0600)
	}()
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Lifecycle observation failed: %s", name)
		}
	}
	inspect := func(want float64) bool {
		r, e := systemGuardResult(inspector, "inspect")
		return e == nil && r["rulesPresent"] == want
	}
	check("initial_sid_rules_zero", inspect(0))
	otherGuard := filepath.Join(bin, "p0-helper-guard.exe")
	other, otherErr := systemGuardResult(otherGuard, "install-fixture-only", "48731")
	check("separate_fixture_guard_installed", otherErr == nil && other["rulesPresent"] == float64(4))
	t.Cleanup(func() {
		r, e := systemGuardResult(otherGuard, "remove-fixture-only")
		if e != nil || r["rulesPresent"] != float64(0) {
			t.Error("Separate fixture cleanup failed")
		}
	})
	upstream, ca, _, stopUpstream := systemProxy(t, "http", false)
	relay, stopRelay, _ := systemRelayWithPID(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream, ca, false)
	_, port, _ := strings.Cut(relay, ":")
	endpoints := map[string]string{}
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		endpoints[network] = systemEcho(t, network, "0")
		check("baseline_"+network, systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-network", network, "-address", endpoints[network]))
	}
	// Snapshot the exact five fixture DACLs before launching a crashable owner.
	snapshotScript := `$paths=@('C:\P0Lab','C:\P0Lab\.local','C:\P0Lab\.local\p0','C:\P0Lab\.local\p0\bin','C:\P0Lab\.local\p0\bin\proxy-harbor-p0-probe.exe');@($paths|ForEach-Object{@{path=$_;sddl=(Get-Acl -LiteralPath $_).Sddl}})|ConvertTo-Json -Compress`
	snapshot, err := lifecyclePS(snapshotScript)
	if err != nil {
		t.Fatalf("DACL snapshot: %v %s", err, snapshot)
	}
	report["daclSnapshotRecorded"] = true
	os.WriteFile(filepath.Join(root, "lifecycle-acl-baseline.json"), snapshot, 0600)
	for round := 0; round < 2; round++ {
		func() {
			cmd := exec.Command(filepath.Join(bin, "p0-dns-isolation.exe"), "appcontainer-wfp", fmt.Sprintf("%016x", round+1), port, "lifecycle")
			input, _ := cmd.StdinPipe()
			output, _ := cmd.StdoutPipe()
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			profile := fmt.Sprintf("ProxyHarbor.P0.DNS.%d.appcontainer-wfp", cmd.Process.Pid)
			lines := make(chan map[string]any, 32)
			go func() {
				scanner := bufio.NewScanner(output)
				for scanner.Scan() {
					var item map[string]any
					if json.Unmarshal(scanner.Bytes(), &item) == nil {
						lines <- item
					}
				}
				close(lines)
			}()
			next := func() map[string]any {
				select {
				case value := <-lines:
					return value
				case <-time.After(8 * time.Second):
					t.Error("interactive fixture timeout")
					return nil
				}
			}
			ask := func(action, network, address string) bool {
				json.NewEncoder(input).Encode(map[string]string{"action": action, "network": network, "address": address})
				r := next()
				if r == nil || r["action"] != action {
					t.Errorf("Unexpected fixture response: %v %s", r, stderr.String())
					return false
				}
				return r["success"] == true
			}
			waited := false
			defer func() {
				input.Close()
				if !waited {
					cmd.Process.Kill()
					cmd.Wait()
				}
				// A dead controller leaves persistent rules. Recovery runs in a fresh process.
				if !inspect(0) {
					r, e := systemGuardResult(inspector, "recover-fixture-only")
					check(fmt.Sprintf("round%d_supervised_policy_recovery", round), e == nil && r["recovered"] == true)
				}
				encoded := base64.StdEncoding.EncodeToString(snapshot)
				restore := `Add-Type 'using System;using System.Runtime.InteropServices;public class P0Profile{[DllImport("userenv.dll",CharSet=CharSet.Unicode)]public static extern int DeleteAppContainerProfile(string name);[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint revision,out IntPtr sd,out uint size);[DllImport("advapi32.dll",SetLastError=true)]public static extern bool GetSecurityDescriptorDacl(IntPtr sd,out bool present,out IntPtr dacl,out bool defaulted);[DllImport("advapi32.dll",CharSet=CharSet.Unicode)]public static extern uint SetNamedSecurityInfo(string path,uint type,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);[DllImport("kernel32.dll")]public static extern IntPtr LocalFree(IntPtr p);}';$items=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + encoded + `'))|ConvertFrom-Json;foreach($item in $items){$sd=[IntPtr]::Zero;$size=[uint32]0;if(-not [P0Profile]::ConvertStringSecurityDescriptorToSecurityDescriptor($item.sddl,1,[ref]$sd,[ref]$size)){throw 'Invalid DACL snapshot'};try{$present=$false;$defaulted=$false;$acl=[IntPtr]::Zero;if(-not [P0Profile]::GetSecurityDescriptorDacl($sd,[ref]$present,[ref]$acl,[ref]$defaulted) -or -not $present){throw 'Missing DACL'};$errorCode=[P0Profile]::SetNamedSecurityInfo($item.path,1,4,[IntPtr]::Zero,[IntPtr]::Zero,$acl,[IntPtr]::Zero);if($errorCode -ne 0){throw "DACL restore $errorCode"}}finally{[void][P0Profile]::LocalFree($sd)};$actual=[Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath $item.path).Sddl);$expected=[Security.AccessControl.RawSecurityDescriptor]::new($item.sddl);$actualAcl=New-Object byte[] $actual.DiscretionaryAcl.BinaryLength;$expectedAcl=New-Object byte[] $expected.DiscretionaryAcl.BinaryLength;$actual.DiscretionaryAcl.GetBinaryForm($actualAcl,0);$expected.DiscretionaryAcl.GetBinaryForm($expectedAcl,0);if([Convert]::ToBase64String($actualAcl) -ne [Convert]::ToBase64String($expectedAcl) -or $actual.Owner -ne $expected.Owner -or $actual.Group -ne $expected.Group -or (($actual.ControlFlags -band 4096) -ne ($expected.ControlFlags -band 4096))){throw ('ACL mismatch: '+$item.path+' expected '+$item.sddl+' actual '+(Get-Acl -LiteralPath $item.path).Sddl)}};$result=[P0Profile]::DeleteAppContainerProfile('` + profile + `');if($result -ne 0 -and $result -ne -2147024894){throw "Profile cleanup $result"}`
				out, e := lifecyclePS(restore)
				check(fmt.Sprintf("round%d_exact_dacl_profile_cleanup", round), e == nil)
				if e != nil {
					t.Logf("%s", out)
				}
			}()
			ready := next()
			if ready["ready"] != true || ready["container"] != true {
				t.Fatalf("Invalid container fixture: %v %s", ready, stderr.String())
			}
			prefix := fmt.Sprintf("round%d_", round)
			check(prefix+"six_rules_installed", inspect(6))
			busyResult, busyErr := systemGuardResult(inspector, "recover-fixture-only")
			check(prefix+"live_fixture_refuses_release", busyErr != nil && busyResult["windowsError"] == float64(170) && inspect(6))
			blocked := func(phase string) {
				for network, address := range endpoints {
					check(prefix+phase+"_blocked_"+network, !ask("direct", network, address))
					check(prefix+phase+"_control_"+network, systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-network", network, "-address", address))
				}
			}
			if round == 1 {
				check(prefix+"proxy_before_controller_kill", ask("proxy", "", relay))
				cmd.Process.Kill()
				cmd.Wait()
				waited = true
				check(prefix+"six_persistent_rules_after_controller_kill", inspect(6))
				_, e := systemGuardResult(inspector, "recover-fixture-only")
				check(prefix+"fresh_process_explicit_recovery", e == nil && inspect(0))
				return
			}
			publicBaseline := func(phase string) {
				cmd := exec.Command(filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-public-wire", "-network", "tcp4", "-address", "1.1.1.1:53")
				out, e := cmd.Output()
				r := map[string]any{}
				json.Unmarshal(out, &r)
				report[phase+"_public_baseline"] = r
				check(phase+"_public_route_available", e == nil && r["success"] == true)
				json.NewEncoder(input).Encode(map[string]string{"action": "public", "network": "tcp4"})
				r = next()
				report[phase+"_public_restricted"] = r
				check(phase+"_public_tcp_policy_denied", r["action"] == "public" && r["accessDenied"] == true && r["success"] == false)
			}
			publicBaseline("before_nic_cycle")
			check("proxy_connect", ask("proxy", "", relay))
			check("existing_tunnel_echo", ask("echo", "", ""))
			blocked("normal")
			journal := filepath.Join(root, "isolated-sid-recovery.json")
			original, e := os.ReadFile(journal)
			if e != nil {
				t.Fatal(e)
			}
			for name, damaged := range map[string][]byte{"truncated": []byte("{"), "wrong_port": bytes.Replace(original, []byte(`"port":`+port), []byte(`"port":1024`), 1), "trailing": append(append([]byte{}, original...), byte('x'))} {
				if bytes.Equal(damaged, original) {
					t.Fatalf("Invalid tamper fixture: %s", name)
				}
				if e := os.WriteFile(journal, damaged, 0600); e != nil {
					t.Fatal(e)
				}
				_, e := systemGuardResult(inspector, "recover-fixture-only")
				check("tampered_"+name+"_refuses_without_deleting", e != nil && inspect(6))
				if e := os.WriteFile(journal, original, 0600); e != nil {
					t.Fatal(e)
				}
			}
			// Real guest NIC state changes; keep loopback observers alive for attribution.
			down := `$a=@(Get-NetAdapter|Where-Object Status -eq 'Up');if($a.Count -ne 1){throw 'Expected one active disposable guest adapter'};$a[0].InterfaceGuid.ToString()|Set-Content C:\P0Lab\.local\p0\lifecycle-adapter.txt;$a[0]|Disable-NetAdapter -Confirm:$false;$b=Get-NetAdapter|Where-Object InterfaceGuid -eq $a[0].InterfaceGuid;if($b.Status -ne 'Disabled'){throw 'Adapter did not disable'}`
			up := `$id=(Get-Content C:\P0Lab\.local\p0\lifecycle-adapter.txt).Trim();$a=@(Get-NetAdapter|Where-Object {$_.InterfaceGuid.ToString() -eq $id});if($a.Count -ne 1){throw 'Adapter identity changed'};$a[0]|Enable-NetAdapter -Confirm:$false;for($i=0;$i -lt 40;$i++){if((Get-NetAdapter|Where-Object {$_.InterfaceGuid.ToString() -eq $id}).Status -eq 'Up'){exit 0};Start-Sleep -Milliseconds 100};throw 'Adapter did not return up'`
			defer func() {
				out, e := lifecyclePS(up)
				check("guest_adapter_restored", e == nil)
				if e != nil {
					t.Logf("%s", out)
				}
			}()
			out, e := lifecyclePS(down)
			check("guest_adapter_actually_disabled", e == nil)
			if e != nil {
				t.Logf("%s", out)
			}
			blocked("nic_down")
			check("existing_loopback_tunnel_during_nic_down", ask("echo", "", ""))
			out, e = lifecyclePS(up)
			check("guest_adapter_actually_reenabled", e == nil)
			if e != nil {
				t.Logf("%s", out)
			}
			blocked("nic_up")
			publicBaseline("after_nic_cycle")
			check("new_tunnel_after_nic_up", ask("proxy", "", relay))
			stopUpstream()
			check("existing_tunnel_fails_after_upstream_stop", !ask("echo", "", ""))
			check("new_tunnel_fails_after_upstream_stop", !ask("proxy", "", relay))
			blocked("upstream_down")
			stopRelay()
			check("new_tunnel_fails_after_relay_kill", !ask("proxy", "", relay))
			blocked("relay_killed")
			upstream2, ca2, _, _ := systemProxy(t, "http", false)
			restored, _, _ := systemRelayWithPID(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream2, ca2, false, "-listen-port", port)
			check("same_port_relay_restart", restored == relay && ask("proxy", "", relay))
			check("recovered_tunnel_echo", ask("echo", "", ""))
			blocked("relay_restarted")
			io.WriteString(input, "{\"action\":\"crash\"}\n")
			result := next()
			check("child_crash_observed", result["childExitCode"] == float64(7) && result["packagePolicyRestored"] == true && result["aclRestored"] == true && result["profileDeleted"] == true)
			check("child_crash_cleanup_zero", inspect(0))
			cmd.Wait()
			waited = true
		}()
	}
	if inspect(0) && checks["round0_exact_dacl_profile_cleanup"] && checks["round1_exact_dacl_profile_cleanup"] && checks["guest_adapter_restored"] {
		cleanup = "verified"
	} else {
		cleanup = "failed"
	}
	check("final_sid_rules_zero", inspect(0))
	other, otherErr = systemGuardResult(otherGuard, "inspect")
	check("sid_recovery_preserved_separate_guard", otherErr == nil && other["rulesPresent"] == float64(4))
	other, otherErr = systemGuardResult(otherGuard, "remove-fixture-only")
	check("separate_guard_explicit_cleanup", otherErr == nil && other["rulesPresent"] == float64(0))
	if !checks["separate_guard_explicit_cleanup"] {
		cleanup = "failed"
	}
}
