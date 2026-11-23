//go:build p0system && windows

package engine

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A loopback TLS fixture for the production Windows HTTP probe. The short-lived
// root is generated inside this disposable guest and removed by exact context.
// These IP bodies are controlled test values, never real public-exit evidence.
func managedExitFixture(t *testing.T, report map[string]any, browserPage func(*http.Request, io.Writer), clientStream http.HandlerFunc) (string, *atomic.Value, *atomic.Bool) {
	t.Helper()
	recoveryGuest(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Proxy Harbor P0 temporary guest root " + serial.String()}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(name string) tls.Certificate {
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name, "*.p0-dns-audit.invalid"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		raw, e := x509.CreateCertificate(rand.Reader, cert, root, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{raw, der}, PrivateKey: key}
	}
	good, bad := leaf("api.ipify.org"), leaf("p0-wrong-host.invalid")
	rootName, _ := windows.UTF16PtrFromString("ROOT")
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(rootName)))
	if err != nil {
		t.Fatal(err)
	}
	context, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		windows.CertCloseStore(store, 0)
		t.Fatal(err)
	}
	var stored *windows.CertContext
	err = windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_NEW, &stored)
	windows.CertFreeCertificateContext(context)
	if err != nil {
		windows.CertCloseStore(store, 0)
		t.Fatal(err)
	}
	report["guestCertificateInstalled"] = true
	t.Cleanup(func() {
		deleted := windows.CertDeleteCertificateFromStore(stored) == nil
		found := false
		complete := false
		var previous *windows.CertContext
		for {
			next, e := windows.CertEnumCertificatesInStore(store, previous)
			previous = next
			if e != nil || next == nil {
				complete = errors.Is(e, syscall.Errno(0x80092004))
				break
			}
			if bytes.Equal(unsafe.Slice(next.EncodedCert, int(next.Length)), der) {
				found = true
			}
		}
		report["guestCertificateRemoved"] = deleted && complete && !found
		windows.CertCloseStore(store, 0)
		if !deleted || found || !complete {
			t.Error("Temporary guest certificate cleanup not verified")
		}
	})
	value := &atomic.Value{}
	value.Store("131.103.130.202")
	wrong := &atomic.Bool{}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if clientStream != nil && r.Method == "CONNECT" && (r.Host == "first.p0.invalid:443" || r.Host == "unlisted.p0.invalid:443") {
			clientStream(w, r)
			return
		}
		auditHost := browserPage != nil && strings.HasSuffix(r.Host, ".p0-dns-audit.invalid:443")
		if r.Method != "CONNECT" || (r.Host != "api.ipify.org:443" && !auditHost) {
			http.Error(w, "P0 fixed test target only", 502)
			return
		}
		conn, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(8 * time.Second))
			fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			config := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				if wrong.Load() {
					return &bad, nil
				}
				return &good, nil
			}}
			secure := tls.Server(conn, config)
			if secure.Handshake() != nil {
				return
			}
			request, e := http.ReadRequest(bufio.NewReader(secure))
			if e != nil {
				return
			}
			request.Body.Close()
			if browserPage != nil && strings.Contains(request.UserAgent(), "Chrome/") {
				browserPage(request, secure)
				return
			}
			body := value.Load().(string)
			fmt.Fprintf(secure, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", len(body))
			// The first fragment is itself a valid IPv4 literal.
			if len(body) > 12 {
				fmt.Fprint(secure, body[:12])
				time.Sleep(80 * time.Millisecond)
				body = body[12:]
			}
			fmt.Fprint(secure, body)
		}()
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close(); listener.Close() })
	return listener.Addr().String(), value, wrong
}

func TestManagedUserExitChange(t *testing.T) {
	prepareCapsuleFixtures(t)
	copyCapsuleChrome(t)
	testManagedExitChange(t, "chrome-user", filepath.Join(capsuleAppDir, "chrome", "chrome.exe"))
}

func TestManagedClientExitChange(t *testing.T) {
	recoveryGuest(t)
	testManagedExitChange(t, "client-user", `C:\P0Lab\.local\p0\bin\session-fixture.exe`)
}

func testManagedExitChange(t *testing.T, mode, image string) {
	root := `C:\P0Lab\.local\p0`
	guardian := filepath.Join(root, "bin", "proxy-harbor-guardian.exe")
	checks := map[string]bool{}
	report := map[string]any{"schemaVersion": 1, "mode": mode, "scope": "Controlled TLS observations in the offline test fixture", "checks": checks, "cleanup": "pending"}
	t.Cleanup(func() {
		if report["guestCertificateRemoved"] == true {
			report["cleanup"] = "verified"
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		name := "managed-user-exit-report.json"
		if mode == "client-user" {
			name = "managed-client-exit-report.json"
		}
		os.WriteFile(filepath.Join(root, name), data, 0600)
	})
	type streamEnd struct {
		host string
		n    int
		err  error
	}
	type streamPeer struct {
		host string
		conn net.Conn
	}
	opened := make(chan streamPeer, 2)
	closed := make(chan streamEnd, 2)
	stream := func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(35 * time.Second))
		if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		opened <- streamPeer{r.Host, conn}
		var byteRead [1]byte
		n, err := conn.Read(byteRead[:])
		closed <- streamEnd{r.Host, n, err}
	}
	address, value, wrong := managedExitFixture(t, report, nil, stream)
	_, port, _ := net.SplitHostPort(address)
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Exit health: %s", name)
		}
	}
	const expected = "131.103.130.202" // Local TLS response body only.
	scenarios := []string{"bad_tls_preflight", "wrong_initial_exit", "embedded_nul", "reserved_address", "wrong_proxy_process", "missing_tun", "exit_change"}
	if mode == "client-user" {
		scenarios = append(scenarios, "direct_connection")
	}
	for _, scenario := range scenarios {
		func() {
			runningCase := scenario == "exit_change" || scenario == "direct_connection"
			peers := map[string]net.Conn{}
			var clientHandle windows.Handle
			var observer *net.TCPListener
			if scenario == "direct_connection" {
				var err error
				observer, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer observer.Close()
				// Prove this endpoint can receive connections from outside the session.
				control, err := net.DialTimeout("tcp4", observer.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				control.Close()
				observer.SetDeadline(time.Now().Add(time.Second))
				accepted, err := observer.Accept()
				if err != nil {
					t.Fatal(err)
				}
				accepted.Close()
			}
			value.Store(expected)
			switch scenario {
			case "wrong_initial_exit":
				value.Store("131.103.130.203")
			case "embedded_nul":
				value.Store(expected + "\x00")
			case "reserved_address":
				value.Store("203.0.113.10")
			}
			wrong.Store(scenario == "bad_tls_preflight")
			var nonce [16]byte
			rand.Read(nonce[:])
			h := hex.EncodeToString(nonce[:])
			id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
			folder := filepath.Join(root, "sessions", id)
			os.MkdirAll(folder, 0700)
			var c, e, k, u windows.Filetime
			windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u)
			created := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
			proxyBorn := created
			if scenario == "wrong_proxy_process" {
				proxyBorn++
			}
			protocol := "PH2"
			if scenario == "missing_tun" {
				protocol = "PH4"
			}
			request := fmt.Sprintf("%s\n%s\n%d\n%d\n%s\n%s\n1\n%s %d %d\n%s\n", protocol, id, os.Getpid(), created, port, mode, expected, os.Getpid(), proxyBorn, image)
			os.WriteFile(filepath.Join(folder, "request.txt"), []byte(request), 0600)
			inspect := func() int {
				out, err := exec.Command(guardian, "inspect", folder).Output()
				var row struct {
					Rules int `json:"rulesPresent"`
				}
				if err != nil || json.Unmarshal(out, &row) != nil {
					return -1
				}
				return row.Rules
			}
			read := func() map[string]any {
				data, _ := os.ReadFile(filepath.Join(folder, "status.json"))
				r := map[string]any{}
				json.Unmarshal(data, &r)
				return r
			}
			cmd := exec.Command(guardian, "start", folder)
			cmd.Env = append(os.Environ(), "PH_GUEST_CHROME_MODE=hold")
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waited := false
			defer func() {
				if !waited {
					os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
					select {
					case <-done:
					case <-time.After(8 * time.Second):
						cmd.Process.Kill()
						<-done
					}
				}
				if inspect() != 0 {
					out, err := exec.Command(guardian, "recover", folder).CombinedOutput()
					if err != nil {
						t.Errorf("Controlled probe recovery: %v %s", err, out)
					}
				}
			}()
			var initial map[string]any
			until := time.Now().Add(30 * time.Second)
			for time.Now().Before(until) {
				initial = read()
				if initial["state"] == "monitoring" || initial["state"] == "failed" || initial["state"] == "cleanup_required" {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			report[scenario+"Initial"] = initial
			if !runningCase {
				reason := "exit_not_verified"
				if scenario == "wrong_initial_exit" {
					reason = "exit_mismatch_before_launch"
				}
				if scenario == "wrong_proxy_process" {
					reason = "proxy_owner_changed"
				}
				if scenario == "missing_tun" {
					reason = "tun_not_ready"
				}
				check(scenario+"_rejects_without_launch", initial["state"] == "failed" && initial["reason"] == reason && initial["pid"] == float64(0) && inspect() == 0)
			} else {
				check(scenario+"_initial_tls_exit_verified", initial["state"] == "monitoring" && initial["proxyExit"] == expected && inspect() == 14)
				if mode == "client-user" {
					timer := time.NewTimer(5 * time.Second)
					defer timer.Stop()
					for len(peers) < 2 {
						select {
						case peer := <-opened:
							peers[peer.host] = peer.conn
						case <-timer.C:
							t.Fatal("Both controlled destinations must connect before injecting the fault")
						}
					}
					check(scenario+"_both_connections_via_proxy", peers["first.p0.invalid:443"] != nil && peers["unlisted.p0.invalid:443"] != nil)
					pid, ok := initial["pid"].(float64)
					if !ok || pid == 0 {
						t.Fatal("Missing managed PID")
					}
					var err error
					clientHandle, err = windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
					if err != nil {
						t.Fatal(err)
					}
					defer windows.CloseHandle(clientHandle)
					if observer != nil {
						if _, err := fmt.Fprintln(peers["first.p0.invalid:443"], observer.Addr().String()); err != nil {
							t.Fatal(err)
						}
					}
				}
				if scenario == "exit_change" {
					value.Store("131.103.130.203")
				}
			}
			select {
			case err := <-done:
				waited = true
				check(scenario+"_guardian_finished", (err == nil) == runningCase)
			case <-time.After(30 * time.Second):
				t.Error("Exit-change monitor timeout")
				return
			}
			final := read()
			report[scenario+"Final"] = final
			report[scenario+"Output"] = output.String()
			if runningCase {
				reason := "exit_mismatch"
				if observer != nil {
					reason = "bypass_blocked"
					observer.SetDeadline(time.Now().Add(250 * time.Millisecond))
					c, err := observer.Accept()
					if c != nil {
						c.Close()
					}
					var timeout net.Error
					check("direct_peer_never_accepted", errors.As(err, &timeout) && timeout.Timeout())
					check("drop_identifies_attempted_port", final["blockedRemotePort"] == float64(observer.Addr().(*net.TCPAddr).Port))
				}
				check(scenario+"_terminates_and_cleans", final["state"] == "stopped" && final["reason"] == reason && inspect() == 0)
				if mode == "client-user" {
					wait, err := windows.WaitForSingleObject(clientHandle, 0)
					check(scenario+"_original_client_exited", err == nil && wait == windows.WAIT_OBJECT_0)
					// An idle peer may not get FIN/RST while emergency WFP rules
					// are active. Test the existing streams again after cleanup.
					if observer != nil {
						for host, peer := range peers {
							peer.SetWriteDeadline(time.Now().Add(time.Second))
							n, err := peer.Write([]byte{1})
							report["post_stop_write_"+host] = fmt.Sprintf("written=%d, error=%v", n, err)
						}
					}
					observations := map[string]string{}
					timer := time.NewTimer(5 * time.Second)
					ok := true
				observe:
					for len(observations) < 2 {
						select {
						case end := <-closed:
							observations[end.host] = fmt.Sprintf("read=%d, error=%v", end.n, end.err)
							ok = ok && end.n == 0 && (errors.Is(end.err, io.EOF) || errors.Is(end.err, syscall.WSAECONNRESET) || errors.Is(end.err, windows.WSAECONNABORTED) || errors.Is(end.err, windows.ERROR_NETNAME_DELETED) || errors.Is(end.err, windows.ERROR_CONNECTION_ABORTED))
						case <-timer.C:
							break observe
						}
					}
					timer.Stop()
					report[scenario+"_stream_ends"] = observations
					check(scenario+"_both_connections_closed", ok && observations["first.p0.invalid:443"] != "" && observations["unlisted.p0.invalid:443"] != "")
				}
			}
			_, err := os.Stat(filepath.Join(folder, "identity.txt"))
			check(scenario+"_identity_absent", os.IsNotExist(err))
			if scenario == "wrong_initial_exit" {
				_, err := exec.Command(guardian, "recover", folder).CombinedOutput()
				check("no_identity_recovery_is_idempotent", err == nil && read()["reason"] == "recovered" && inspect() == 0)
			}
			check(scenario+"_no_false_leak_claim", !strings.Contains(fmt.Sprint(final["reason"]), "real_ip_leaked"))
		}()
	}
}
