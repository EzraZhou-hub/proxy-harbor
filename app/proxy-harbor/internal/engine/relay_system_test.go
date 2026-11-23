//go:build p0system && windows

package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type relayCaseReport struct {
	Protocol string          `json:"protocol"`
	Auth     bool            `json:"auth"`
	Checks   map[string]bool `json:"checks"`
	Cleanup  string          `json:"cleanup"`
}

// This test mutates only guest WFP policy for the sibling disposable probe.
// The explicit build tag, environment marker and exact guest working directory
// intentionally prevent execution on the development host.
func TestP0PersistentRelayGuard(t *testing.T) {
	working, err := os.Getwd()
	if err != nil || !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("System policy tests require the disposable C:\\P0Lab guest; never run on the host")
	}
	guard := filepath.Join(working, ".local", "p0", "bin", "p0-relay-guard.exe")
	probe := filepath.Join(working, ".local", "p0", "bin", "proxy-harbor-p0-probe.exe")
	control := filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe")
	relay := filepath.Join(working, ".local", "p0", "bin", "proxy-harbor-p0-relay.exe")
	before := systemGuard(t, guard, "inspect")
	if before["elevated"] != true || before["rulesPresent"] != float64(0) {
		t.Fatal("Expected an elevated guest with no relay guard rules")
	}
	cases := []*relayCaseReport{}
	defer func() {
		report := map[string]any{"schemaVersion": 1, "generatedAt": time.Now().UTC().Format(time.RFC3339Nano), "overall": "not_accepted", "scope": "Explicit relay and fixture only; no transparent interception or system DNS claim", "cases": cases}
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", "relay-policy-report.json"), data, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	for _, protocol := range []string{"http", "https", "socks5"} {
		for _, auth := range []bool{false, true} {
			record := &relayCaseReport{Protocol: protocol, Auth: auth, Checks: map[string]bool{}, Cleanup: "not_needed"}
			cases = append(cases, record)
			t.Run(fmt.Sprintf("%s/auth=%v", protocol, auth), func(t *testing.T) {
				check := func(name string, success bool) {
					t.Helper()
					record.Checks[name] = success
					if !success {
						t.Fatalf("Observation failed: %s", name)
					}
				}
				upstreamAddress, certPath, targets, stopUpstream := systemProxy(t, protocol, auth)
				defer stopUpstream()
				address, stopRelay := systemRelay(t, relay, protocol, upstreamAddress, certPath, auth)
				defer stopRelay()
				_, port, _ := net.SplitHostPort(address)
				endpoints := map[string]string{}
				for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
					endpoints[network] = systemEcho(t, network, "0")
					check("baseline_"+network, systemProbe(t, probe, "-network", network, "-address", endpoints[network]))
				}
				// Same port as the allowed relay, different protocol: a port-only
				// exception must not accidentally allow UDP.
				udpRelayPort := systemEcho(t, "udp4", port)
				held := systemHeldProbe(t, probe, endpoints["tcp4"])
				journal := map[string]any{"scope": probe, "relayAddress": address, "sublayer": "78c0ad13-2bd0-47bd-b5ec-0132d73b3e8c", "filterKeys": []string{"c7abcf41-e42f-4276-894c-6ba6ab0803e1", "c7abcf42-e42f-4276-894c-6ba6ab0803e1", "c7abcf43-e42f-4276-894c-6ba6ab0803e1", "c7abcf44-e42f-4276-894c-6ba6ab0803e1"}, "recoveryCommand": "p0-relay-guard.exe remove-fixture-only"}
				for name, file := range map[string]string{"toolSHA256": guard, "probeSHA256": probe} {
					data, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					digest := sha256.Sum256(data)
					journal[name] = hex.EncodeToString(digest[:])
				}
				journalData, _ := json.MarshalIndent(journal, "", "  ")
				if err := os.WriteFile(filepath.Join(working, ".local", "p0", "relay-recovery.json"), journalData, 0600); err != nil {
					t.Fatal(err)
				}
				defer func() {
					removed, err := systemGuardResult(guard, "remove-fixture-only")
					if err != nil || removed["rulesPresent"] != float64(0) {
						record.Cleanup = "failed"
						t.Errorf("Relay guard cleanup: %v %v", removed, err)
						return
					}
					record.Cleanup = "verified"
					for network, endpoint := range endpoints {
						if !systemProbe(t, probe, "-network", network, "-address", endpoint) {
							record.Cleanup = "failed"
							t.Errorf("Connectivity did not recover after cleanup: %s", network)
						}
					}
				}()
				installed := systemGuard(t, guard, "install-fixture-only", port)
				check("four_persistent_filters_installed", installed["rulesPresent"] == float64(4))
				check("existing_direct_connection_reauthorized", !held())
				check("relay_chain", systemProbe(t, probe, "-proxy-protocol", "socks5", "-proxy", address, "-target", "no-local-dns.proxy-harbor.invalid:443"))
				select {
				case target := <-targets:
					check("target_domain_forwarded_verbatim", target == "no-local-dns.proxy-harbor.invalid:443")
				case <-time.After(time.Second):
					check("target_domain_forwarded_verbatim", false)
				}
				dnsResult := systemProbeRecord(t, probe, "-proxy-protocol", "socks5", "-proxy", address, "-target", "dns.proxy-harbor.invalid:53", "-dns-message", hex.EncodeToString(labDNSQuery()))
				check("dns_wire_through_guarded_relay", dnsResult.Success && dnsResult.Response == hex.EncodeToString(labDNSAnswer()))
				select {
				case target := <-targets:
					check("dns_resolver_domain_forwarded", target == "dns.proxy-harbor.invalid:53")
				case <-time.After(time.Second):
					check("dns_resolver_domain_forwarded", false)
				}
				for network, endpoint := range endpoints {
					check("direct_blocked_"+network, !systemProbe(t, probe, "-network", network, "-address", endpoint))
					check("other_path_unaffected_"+network, systemProbe(t, control, "-network", network, "-address", endpoint))
				}
				check("udp_same_relay_port_blocked", !systemProbe(t, probe, "-network", "udp4", "-address", udpRelayPort))
				check("udp_control_same_port_works", systemProbe(t, control, "-network", "udp4", "-address", udpRelayPort))
				check("upstream_bypass_blocked", !systemProbe(t, probe, "-proxy-protocol", "http", "-proxy", upstreamAddress))
				stopUpstream()
				check("upstream_failure_relay_fails_closed", !systemProbe(t, probe, "-proxy-protocol", "socks5", "-proxy", address))
				check("upstream_failure_direct_stays_blocked", !systemProbe(t, probe, "-network", "tcp4", "-address", endpoints["tcp4"]))
				stopRelay()
				check("killed_relay_unavailable", !systemProbe(t, probe, "-proxy-protocol", "socks5", "-proxy", address))
				for network, endpoint := range endpoints {
					check("after_relay_kill_blocked_"+network, !systemProbe(t, probe, "-network", network, "-address", endpoint))
				}
			})
		}
	}
}

func systemGuardResult(executable string, args ...string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, executable, args...).CombinedOutput()
	var value map[string]any
	if decode := json.Unmarshal(data, &value); decode != nil {
		return nil, fmt.Errorf("invalid guard response: %w", decode)
	}
	if err != nil || value["windowsError"] != float64(0) {
		return value, fmt.Errorf("guard failed: %v", err)
	}
	return value, nil
}

func systemGuard(t *testing.T, executable string, args ...string) map[string]any {
	t.Helper()
	value, err := systemGuardResult(executable, args...)
	if err != nil {
		t.Fatalf("Guard: %v %v", value, err)
	}
	return value
}

func systemProbe(t *testing.T, executable string, args ...string) bool {
	return systemProbeRecord(t, executable, args...).Success
}

type systemProbeObservation struct {
	Success  bool
	Response string
}

func systemProbeRecord(t *testing.T, executable string, args ...string) systemProbeObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, executable, args...).Output()
	var value systemProbeObservation
	if decode := json.Unmarshal(data, &value); decode != nil {
		t.Fatalf("Invalid fixture response: %v %v", err, decode)
	}
	value.Success = err == nil && value.Success
	return value
}

func systemHeldProbe(t *testing.T, executable, address string) func() bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, executable, "-address", address, "-wait-for-input")
	input, _ := command.StdinPipe()
	output, _ := command.StdoutPipe()
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	reader := bufio.NewReader(output)
	line, err := reader.ReadBytes('\n')
	var ready struct{ Ready bool }
	if err != nil || json.Unmarshal(line, &ready) != nil || !ready.Ready {
		t.Fatal("Pre-existing probe connection was not ready")
	}
	return func() bool {
		io.WriteString(input, "continue\n")
		input.Close()
		line, err := reader.ReadBytes('\n')
		var result struct{ Success bool }
		if err != nil || json.Unmarshal(line, &result) != nil {
			t.Fatal("Pre-existing connection produced no observation")
		}
		return result.Success
	}
}

func systemRelay(t *testing.T, executable, protocol, upstream, certificate string, auth bool) (string, func()) {
	address, stop, _ := systemRelayWithPID(t, executable, protocol, upstream, certificate, auth)
	return address, stop
}

func systemRelayWithPID(t *testing.T, executable, protocol, upstream, certificate string, auth bool, extra ...string) (string, func(), int) {
	t.Helper()
	arguments := append([]string{"-protocol", protocol, "-upstream", upstream, "-fixture-ca", certificate}, extra...)
	command := exec.Command(executable, arguments...)
	command.Env = append(os.Environ(), "P0_PROXY_USER=", "P0_PROXY_PASSWORD=")
	if auth {
		command.Env = append(command.Env, "P0_PROXY_USER=fixture-user", "P0_PROXY_PASSWORD=fixture-secret")
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, _ := command.StdoutPipe()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { command.Process.Kill(); command.Wait() }) }
	t.Cleanup(stop)
	ready := make(chan string, 1)
	go func() {
		var record struct{ Address string }
		json.NewDecoder(output).Decode(&record)
		ready <- record.Address
	}()
	select {
	case address := <-ready:
		if address == "" {
			stop()
			t.Fatalf("Relay did not start: %s", stderr.String())
		}
		return address, stop, command.Process.Pid
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("Relay startup timed out")
		return "", stop, 0
	}
}

func systemEcho(t *testing.T, network, port string) string {
	t.Helper()
	host := "127.0.0.1"
	if strings.HasSuffix(network, "6") {
		host = "::1"
	}
	if strings.HasPrefix(network, "udp") {
		packet, err := net.ListenPacket(network, net.JoinHostPort(host, port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { packet.Close() })
		go func() {
			data := make([]byte, 64)
			for {
				n, peer, err := packet.ReadFrom(data)
				if err != nil {
					return
				}
				packet.WriteTo(data[:n], peer)
			}
		}()
		return packet.LocalAddr().String()
	}
	listener, err := net.Listen(network, net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); conn.SetDeadline(time.Now().Add(20 * time.Second)); io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

func systemProxy(t *testing.T, protocol string, auth bool) (string, string, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	certificatePath := ""
	if protocol == "https" {
		certificate, _ := labCertificate(t)
		certificatePath = filepath.Join(t.TempDir(), "fixture-ca.pem")
		if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
			t.Fatal(err)
		}
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	}
	var lock sync.Mutex
	connections := map[net.Conn]bool{}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			listener.Close()
			lock.Lock()
			defer lock.Unlock()
			for conn := range connections {
				conn.Close()
			}
		})
	}
	t.Cleanup(stop)
	targets := make(chan string, 32)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			lock.Lock()
			connections[conn] = true
			lock.Unlock()
			go func() {
				defer func() { conn.Close(); lock.Lock(); delete(connections, conn); lock.Unlock() }()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				reader := bufio.NewReader(conn)
				var target string
				if protocol != "socks5" {
					request, err := http.ReadRequest(reader)
					if err != nil || request.Method != "CONNECT" {
						return
					}
					if auth && request.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-secret")) {
						io.WriteString(conn, "HTTP/1.1 407 Rejected\r\nContent-Length: 0\r\n\r\n")
						return
					}
					target = request.Host
					io.WriteString(conn, "HTTP/1.1 200 Connected\r\n\r\n")
				} else {
					var greeting [2]byte
					if _, err := io.ReadFull(reader, greeting[:]); err != nil || greeting[0] != 5 {
						return
					}
					methods := make([]byte, greeting[1])
					if _, err := io.ReadFull(reader, methods); err != nil {
						return
					}
					method := byte(0)
					if auth {
						method = 2
					}
					if !bytes.Contains(methods, []byte{method}) {
						return
					}
					writeAll(conn, []byte{5, method})
					if auth {
						var head [2]byte
						if _, err := io.ReadFull(reader, head[:]); err != nil || head[0] != 1 {
							return
						}
						user := make([]byte, head[1])
						if _, err := io.ReadFull(reader, user); err != nil {
							return
						}
						length, err := reader.ReadByte()
						if err != nil {
							return
						}
						password := make([]byte, length)
						if _, err := io.ReadFull(reader, password); err != nil {
							return
						}
						if string(user) != "fixture-user" || string(password) != "fixture-secret" {
							writeAll(conn, []byte{1, 1})
							return
						}
						writeAll(conn, []byte{1, 0})
					}
					var request [4]byte
					if _, err := io.ReadFull(reader, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
						return
					}
					length := byte(4)
					if request[3] == 3 {
						var err error
						length, err = reader.ReadByte()
						if err != nil {
							return
						}
					} else if request[3] != 1 {
						return
					}
					name := make([]byte, length)
					if _, err := io.ReadFull(reader, name); err != nil {
						return
					}
					var port [2]byte
					if _, err := io.ReadFull(reader, port[:]); err != nil {
						return
					}
					host := string(name)
					if request[3] == 1 {
						host = net.IP(name).String()
					}
					target = net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))
					relayReply(conn, 0)
				}
				targets <- target
				if target == "dns.proxy-harbor.invalid:53" {
					dnsFixture(conn, labDNSAnswer())
					return
				}
				io.Copy(conn, reader)
			}()
		}
	}()
	return address, certificatePath, targets, stop
}
