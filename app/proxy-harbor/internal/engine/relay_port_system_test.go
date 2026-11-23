//go:build p0system && windows

package engine

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestP0RelayPortOwnership(t *testing.T) {
	working, _ := os.Getwd()
	if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("Port reservation experiment is disposable-guest-only")
	}
	bin := filepath.Join(working, ".local", "p0", "bin")
	guard := filepath.Join(bin, "p0-port-guard.exe")
	appGuard := filepath.Join(bin, "p0-relay-guard.exe")
	probe := filepath.Join(bin, "proxy-harbor-p0-probe.exe")
	checks := map[string]bool{}
	cleanup := "not_needed"
	defer func() {
		data, err := json.MarshalIndent(map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "Persistent reservation of one fixed guest relay port; executable path identity, not a general PID binding", "checks": checks, "cleanup": cleanup}, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", "relay-port-report.json"), data, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	check := func(id string, ok bool) {
		t.Helper()
		checks[id] = ok
		if !ok {
			t.Errorf("Port reservation: %s", id)
		}
	}
	if r, err := systemGuardResult(guard, "inspect"); err != nil || r["rulesPresent"] != float64(0) {
		t.Fatal("Expected clean guest port guard", r, err)
	}
	if r := systemGuard(t, appGuard, "inspect"); r["rulesPresent"] != float64(0) {
		t.Fatal("Expected clean application guard")
	}
	upstream, cert, _, stopUpstream := systemProxy(t, "http", false)
	defer stopUpstream()
	relay := filepath.Join(bin, "proxy-harbor-p0-relay.exe")
	address, stopRelay, _ := systemRelayWithPID(t, relay, "http", upstream, cert, false)
	_, port, _ := net.SplitHostPort(address)
	// A pre-existing untrusted bind is held across installation. AUTH_LISTEN
	// must independently stop it from becoming a replacement server later.
	prebound, err := windows.Socket(windows.AF_INET6, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.Closesocket(prebound)
	if err := windows.SetsockoptInt(prebound, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1); err != nil {
		t.Fatal(err)
	}
	portNumber, _ := strconv.Atoi(port)
	socketAddress := &windows.SockaddrInet6{Port: portNumber}
	socketAddress.Addr[15] = 1
	if err := windows.Bind(prebound, socketAddress); err != nil {
		t.Fatal(err)
	}
	journal, _ := json.Marshal(map[string]any{"scope": "guest relay port only", "port": port, "owner": "Proxy Harbor P0 disposable relay port reservation", "recoveryCommand": "p0-port-guard.exe remove-fixture-only"})
	if err := os.WriteFile(filepath.Join(working, ".local", "p0", "port-recovery.json"), journal, 0600); err != nil {
		t.Fatal(err)
	}
	cleanup = "pending"
	defer func() {
		a, ae := systemGuardResult(appGuard, "remove-fixture-only")
		p, pe := systemGuardResult(guard, "remove-fixture-only")
		if ae != nil || pe != nil || a["rulesPresent"] != float64(0) || p["rulesPresent"] != float64(0) {
			cleanup = "failed"
			t.Error("Port/application cleanup failed", a, ae, p, pe)
		} else {
			cleanup = "verified"
		}
	}()
	r := systemGuard(t, guard, "reserve-fixture-only", port)
	check("four_persistent_port_rules", r["rulesPresent"] == float64(4))
	check("reservation_install_idempotent", systemGuard(t, guard, "reserve-fixture-only", port)["systemChanged"] == false)
	check("application_rules_installed", systemGuard(t, appGuard, "install-fixture-only", port)["rulesPresent"] == float64(4))
	check("existing_relay_still_works", systemProbe(t, probe, "-proxy-protocol", "socks5", "-proxy", address))
	stopRelay()
	check("prebound_replacement_denied_listen", errors.Is(windows.Listen(prebound, 1), syscall.Errno(10013)))
	windows.Closesocket(prebound)
	// Check errors are access denial, not just another process still owning it.
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		for _, host := range []string{"loopback", "wildcard"} {
			ip := "127.0.0.1"
			if strings.HasSuffix(network, "6") {
				ip = "::1"
			}
			if host == "wildcard" {
				ip = "0.0.0.0"
				if strings.HasSuffix(network, "6") {
					ip = "::"
				}
			}
			endpoint := net.JoinHostPort(ip, port)
			var bindErr error
			if strings.HasPrefix(network, "udp") {
				p, e := net.ListenPacket(network, endpoint)
				bindErr = e
				if p != nil {
					p.Close()
				}
			} else {
				l, e := net.Listen(network, endpoint)
				bindErr = e
				if l != nil {
					l.Close()
				}
			}
			check("replacement_denied_"+network+"_"+host, errors.Is(bindErr, syscall.Errno(10013)))
		}
	}
	check("relay_exit_target_fails_closed", !systemProbe(t, probe, "-proxy-protocol", "socks5", "-proxy", address))
	check("reservation_survives_controller_exit", systemGuard(t, guard, "inspect")["rulesPresent"] == float64(4))
	other := systemEcho(t, "tcp4", "0")
	check("other_port_unaffected", systemProbe(t, filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe"), "-address", other))
	// The fixed trusted relay executable can recover the exact port; no rules
	// are temporarily removed to achieve this.
	recovered, stopRecovered, _ := systemRelayWithPID(t, relay, "http", upstream, cert, false, "-listen-port", port)
	check("trusted_relay_exact_port_recovery", recovered == address && systemProbe(t, probe, "-proxy-protocol", "socks5", "-proxy", recovered))
	stopRecovered()
	check("application_guard_removed", systemGuard(t, appGuard, "remove-fixture-only")["rulesPresent"] == float64(0))
	check("port_guard_removed", systemGuard(t, guard, "remove-fixture-only")["rulesPresent"] == float64(0))
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		host := "127.0.0.1"
		if strings.HasSuffix(network, "6") {
			host = "::1"
		}
		endpoint := net.JoinHostPort(host, port)
		var err error
		if strings.HasPrefix(network, "udp") {
			var p net.PacketConn
			p, err = net.ListenPacket(network, endpoint)
			if p != nil {
				p.Close()
			}
		} else {
			var l net.Listener
			l, err = net.Listen(network, endpoint)
			if l != nil {
				l.Close()
			}
		}
		check("binding_restored_"+network, err == nil)
	}
}
