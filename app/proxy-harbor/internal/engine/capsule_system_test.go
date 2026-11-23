//go:build p0system && windows

package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const capsuleAppDir = `C:\Program Files\ProxyHarborP0Capsule`

func capsuleWireEcho(t *testing.T, network string) (string, func() uint64) {
	t.Helper()
	var packets atomic.Uint64
	host := "127.0.0.1"
	if strings.HasSuffix(network, "6") {
		host = "::1"
	}
	if strings.HasPrefix(network, "udp") {
		socket, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { socket.Close() })
		go func() {
			var data [64]byte
			for {
				n, peer, e := socket.ReadFrom(data[:])
				if e != nil {
					return
				}
				packets.Add(1)
				socket.WriteTo(data[:n], peer)
			}
		}()
		return socket.LocalAddr().String(), packets.Load
	}
	listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			packets.Add(1)
			go func() { defer conn.Close(); conn.SetDeadline(time.Now().Add(3 * time.Second)); io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String(), packets.Load
}

func prepareCapsuleFixtures(t *testing.T) {
	t.Helper()
	recoveryGuest(t)
	if _, err := os.Lstat(capsuleAppDir); !os.IsNotExist(err) {
		t.Fatal("Refuse to adopt an existing fixture application directory")
	}
	if err := os.Mkdir(capsuleAppDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if filepath.Clean(capsuleAppDir) != `C:\Program Files\ProxyHarborP0Capsule` {
			t.Fatal("Unexpected cleanup path")
		}
		if err := os.RemoveAll(capsuleAppDir); err != nil {
			t.Error(err)
		}
	})
	data, err := os.ReadFile(`C:\P0Lab\.local\p0\bin\capsule-probe.exe`)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"capsule-probe.exe", "unlisted.exe"} {
		if err := os.WriteFile(filepath.Join(capsuleAppDir, name), data, 0755); err != nil {
			t.Fatal(err)
		}
	}
}
func TestP0CapsuleInheritance(t *testing.T) {
	testP0CapsuleInheritance(t, false)
}
func TestP0UserCapsuleInheritance(t *testing.T) {
	testP0CapsuleInheritance(t, true)
}
func testP0CapsuleInheritance(t *testing.T, user bool) {
	prepareCapsuleFixtures(t)
	root := `C:\P0Lab\.local\p0`
	bin := filepath.Join(root, "bin")
	runner := filepath.Join(bin, "p0-capsule.exe")
	rules, rounds, reportName := float64(6), 2, "capsule-inheritance-report.json"
	if user {
		runner = filepath.Join(bin, "p0-user-capsule.exe")
		rules = 8
		rounds = 1
		reportName = "user-capsule-inheritance-report.json"
	}
	checks := map[string]bool{}
	report := map[string]any{"schemaVersion": 1, "checks": checks, "cleanup": "pending", "scope": "Zero-capability AppContainer SID inherited by an unlisted child; direct first packets attempted before any monitor or child-specific EXE rule"}
	if user {
		report["scope"] = "Dedicated ordinary user SID inherited by an unlisted child; direct first packets attempted before any monitor or child-specific EXE rule"
	}
	defer func() {
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, reportName), data, 0600)
	}()
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Capsule: %s", name)
		}
	}
	inspect := func(want float64) bool {
		inspector := filepath.Join(bin, "p0-isolation-inspect.exe")
		if user {
			inspector = runner
		}
		r, e := systemGuardResult(inspector, "inspect")
		return e == nil && r["rulesPresent"] == want
	}
	upstream, ca, _, _ := systemProxy(t, "http", false)
	relay, stopRelay := systemRelay(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream, ca, false)
	_, port, _ := strings.Cut(relay, ":")
	defer stopRelay()
	reserved := systemGuard(t, filepath.Join(bin, "p0-port-guard.exe"), "reserve-fixture-only", port)
	check("trusted_port_reserved", reserved["rulesPresent"] == float64(4))
	defer systemGuard(t, filepath.Join(bin, "p0-port-guard.exe"), "remove-fixture-only")
	for pass := 0; pass < rounds; pass++ {
		func() {
			label := fmt.Sprintf("%016x", time.Now().UnixNano()+int64(pass))
			command := exec.Command(runner, "probe", label, port, "P0")
			input, _ := command.StdinPipe()
			output, _ := command.StdoutPipe()
			var stderr bytes.Buffer
			command.Stderr = &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				input.Close()
				if !waited {
					command.Process.Kill()
					command.Wait()
				}
				if !inspect(0) {
					out, err := exec.Command(runner, "recover", label, port, "P0").CombinedOutput()
					if err != nil {
						t.Errorf("Capsule recovery: %v %s", err, out)
					}
				}
			}()
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
				case item := <-lines:
					return item
				case <-time.After(8 * time.Second):
					return nil
				}
			}
			native := next()
			prefix := fmt.Sprintf("round%d_", pass)
			check(prefix+"identity_armed_before_execution", native["capsuleReady"] == true && native["rules"] == rules && native["debugLoopback"] == false)
			if native["capsuleReady"] != true {
				t.Fatalf("Capsule startup: %v %s", native, stderr.String())
			}
			ready := next()
			sid, _ := native["sid"].(string)
			check(prefix+"root_same_container_identity", ready["ready"] == true && ready["sid"] == sid)
			if ready["ready"] != true {
				t.Fatalf("Capsule client: %v %s", ready, stderr.String())
			}
			ask := func(action, network, address string) map[string]any {
				json.NewEncoder(input).Encode(map[string]string{"action": action, "network": network, "address": address})
				item := next()
				if item["action"] != action {
					t.Errorf("Invalid client response: %v", item)
				}
				return item
			}
			check(prefix+"proxy_works", ask("proxy", "", "")["success"] == true)
			check(prefix+"held_proxy_works", ask("held", "", "")["success"] == true)
			for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
				endpoint, wireCount := capsuleWireEcho(t, network)
				check(prefix+"baseline_"+network, systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-network", network, "-address", endpoint))
				before := wireCount()
				child := ask("child", network, endpoint)
				report[prefix+network+"_child"] = child
				check(prefix+"unlisted_first_packet_denied_"+network, child["success"] == false && child["fixtureError"] != true && before > 0 && wireCount() == before)
				check(prefix+"wire_observer_healthy_after_"+network, systemProbe(t, filepath.Join(root, "control", "proxy-harbor-p0-probe.exe"), "-network", network, "-address", endpoint) && wireCount() > before)
				check(prefix+"unlisted_inherits_sid_"+network, child["sid"] == sid)
				check(prefix+"parent_remains_usable_"+network, ask("held", "", "")["success"] == true)
			}
			var out []byte
			var err error
			if !user {
				out, err = exec.Command(runner, "recover", label, port, "P0").CombinedOutput()
				check(prefix+"live_identity_refuses_recovery", err != nil && inspect(6))
				report[prefix+"liveRecoveryOutput"] = string(out)
			}
			if pass == 0 {
				json.NewEncoder(input).Encode(map[string]string{"action": "exit"})
				result := next()
				check(prefix+"clean_exit", result["capsuleResult"] == true && result["jobEmpty"] == true && result["policyRestored"] == true && result["profileDeleted"] == true)
				command.Wait()
				waited = true
			} else {
				stopRelay()
				check(prefix+"proxy_failure_closes_existing_tunnel", ask("held", "", "")["success"] == false)
				check(prefix+"proxy_failure_no_fallback", ask("proxy", "", "")["success"] == false)
				endpoint := systemEcho(t, "tcp4", "0")
				denied := ask("child", "tcp4", endpoint)
				check(prefix+"new_child_still_blocked_after_proxy_failure", denied["accessDenied"] == true && denied["sid"] == sid)
				pid := uint32(native["pid"].(float64))
				process, e := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
				if e != nil {
					t.Fatal(e)
				}
				defer windows.CloseHandle(process)
				command.Process.Kill()
				command.Wait()
				waited = true
				code, e := windows.WaitForSingleObject(process, 5000)
				check(prefix+"controller_death_closes_job", e == nil && code == windows.WAIT_OBJECT_0)
				check(prefix+"persistent_sid_policy_survives", inspect(6))
				journal := filepath.Join(root, "isolated-sid-recovery.json")
				original, _ := os.ReadFile(journal)
				os.WriteFile(journal, []byte("{"), 0600)
				_, e = exec.Command(runner, "recover", label, port, "P0").Output()
				check(prefix+"corrupt_record_refuses_without_release", e != nil && inspect(6))
				os.WriteFile(journal, original, 0600)
				_, e = exec.Command(runner, "recover", label, "1024", "P0").Output()
				check(prefix+"wrong_port_refuses_without_release", e != nil && inspect(6))
				out, e = exec.Command(runner, "recover", label, port, "P0").CombinedOutput()
				check(prefix+"separate_recovery", e == nil && inspect(0))
				if e != nil {
					t.Logf("%s", out)
				}
			}
			check(prefix+"independent_sid_inventory_zero", inspect(0))
		}()
	}
	if inspect(0) {
		report["cleanup"] = "verified"
	} else {
		report["cleanup"] = "failed"
	}
}
