//go:build p0system && windows

package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestP0UDPAndDualStack(t *testing.T) {
	working, _ := os.Getwd()
	if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("UDP/dual-stack experiment is guest-only")
	}
	bin := filepath.Join(working, ".local", "p0", "bin")
	probe := filepath.Join(bin, "proxy-harbor-p0-probe.exe")
	control := filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe")
	guard := filepath.Join(bin, "p0-relay-guard.exe")
	checks := map[string]bool{}
	cleanup := "not_needed"
	defer func() {
		data, err := json.MarshalIndent(map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "Controlled UDP4/UDP6 ports 53,443,3478, small/large datagrams and native IPv4-mapped IPv6 socket; not public IPv6 or wire-fragmentation acceptance", "checks": checks, "cleanup": cleanup}, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", "udp-dualstack-report.json"), data, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	check := func(id string, ok bool) {
		t.Helper()
		checks[id] = ok
		if !ok {
			t.Errorf("UDP/dual-stack: %s", id)
		}
	}
	type endpoint struct {
		network, address string
		received         *atomic.Int32
	}
	endpoints := []endpoint{}
	for _, network := range []string{"udp4", "udp6"} {
		for _, port := range []string{"53", "443", "3478"} {
			host := "127.0.0.1"
			if network == "udp6" {
				host = "::1"
			}
			packet, err := net.ListenPacket(network, net.JoinHostPort(host, port))
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			count := &atomic.Int32{}
			endpoints = append(endpoints, endpoint{network, packet.LocalAddr().String(), count})
			go func() {
				buffer := make([]byte, 65535)
				for {
					n, peer, err := packet.ReadFrom(buffer)
					if err != nil {
						return
					}
					count.Add(1)
					packet.WriteTo(buffer[:n], peer)
				}
			}()
		}
	}
	observe := func(stage string, exe string, expected bool) {
		for _, e := range endpoints {
			for _, size := range []string{"2", "60000"} {
				before := e.received.Load()
				ok := systemProbe(t, exe, "-network", e.network, "-address", e.address, "-payload-size", size)
				time.Sleep(10 * time.Millisecond)
				_, port, _ := net.SplitHostPort(e.address)
				id := stage + "_" + e.network + "_port" + port + "_bytes" + size
				check(id+"_client", ok == expected)
				check(id+"_observer", (e.received.Load() > before) == expected)
			}
		}
	}
	mapped := systemEcho(t, "tcp4", "0")
	check("mapped_socket_baseline", systemProbe(t, probe, "-network", "tcp-mapped", "-address", mapped))
	observe("baseline", probe, true)
	upstream, cert, _, stopUpstream := systemProxy(t, "http", false)
	defer stopUpstream()
	address, stopRelay := systemRelay(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream, cert, false)
	defer stopRelay()
	_, port, _ := net.SplitHostPort(address)
	defer func() {
		r, err := systemGuardResult(guard, "remove-fixture-only")
		if err != nil || r["rulesPresent"] != float64(0) {
			cleanup = "failed"
			t.Error("UDP guard cleanup", r, err)
		} else {
			cleanup = "verified"
		}
	}()
	cleanup = "pending"
	check("four_rules", systemGuard(t, guard, "install-fixture-only", port)["rulesPresent"] == float64(4))
	check("tcp_proxy_still_works", systemProbe(t, probe, "-proxy-protocol", "socks5", "-proxy", address))
	observe("guarded", probe, false)
	observe("control_unaffected", control, true)
	check("mapped_socket_guarded", !systemProbe(t, probe, "-network", "tcp-mapped", "-address", mapped))
	check("mapped_control_unaffected", systemProbe(t, control, "-network", "tcp-mapped", "-address", mapped))
	stopRelay()
	observe("relay_exited", probe, false)
	check("rules_survive_relay_exit", systemGuard(t, guard, "inspect")["rulesPresent"] == float64(4))
	check("explicit_remove", systemGuard(t, guard, "remove-fixture-only")["rulesPresent"] == float64(0))
	observe("restored", probe, true)
	check("mapped_socket_restored", systemProbe(t, probe, "-network", "tcp-mapped", "-address", mapped))
	fmt.Fprintln(os.Stdout, "UDP and mapped socket observations recorded with positive endpoint controls")
}
