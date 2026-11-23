package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"proxyharbor/internal/domain"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func labUpstream(protocol string) Upstream {
	return Upstream{Profile: domain.ProxyProfile{Name: "P0 upstream", Protocol: protocol, Host: "127.0.0.1", Port: 7890}, Timeout: time.Second}
}

func pipeDialer(t *testing.T, server func(net.Conn) error, allowServerError bool) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "127.0.0.1:7890" {
			t.Errorf("unexpected route: %s %s", network, address)
		}
		client, peer := net.Pipe()
		finished := make(chan error, 1)
		go func() { defer peer.Close(); finished <- server(peer) }()
		t.Cleanup(func() {
			client.Close()
			select {
			case err := <-finished:
				if err != nil && !allowServerError {
					t.Errorf("fixture: %v", err)
				}
			case <-time.After(time.Second):
				peer.Close()
				t.Error("fixture did not stop")
			}
		})
		return client, nil
	}
}

func httpFixture(conn net.Conn, username, password string, status int) error {
	return httpFixtureTunnel(conn, username, password, status, "READY", echoTunnel)
}

func echoTunnel(conn net.Conn) error {
	_, err := io.Copy(conn, conn)
	return err
}

func httpFixtureTunnel(conn net.Conn, username, password string, status int, firstPayload string, tunnel func(net.Conn) error) error {
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if request.Method != "CONNECT" || request.Host != "no-local-dns.proxy-harbor.invalid:443" {
		return fmt.Errorf("unexpected tunnel target: %s %s", request.Method, request.Host)
	}
	auth := request.Header.Get("Proxy-Authorization")
	if username != "" {
		request.Header.Set("Authorization", auth)
		user, pass, ok := request.BasicAuth()
		if !ok || user != username || pass != password {
			return errors.New("fixture credentials mismatch")
		}
	} else if auth != "" {
		return errors.New("unexpected credentials")
	}
	if status != 200 {
		_, err := fmt.Fprintf(conn, "HTTP/1.1 %d Rejected\r\nContent-Length: 0\r\n\r\n", status)
		return err
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"+firstPayload); err != nil {
		return err
	}
	return tunnel(conn)
}

func assertTunnel(t *testing.T, upstream ProxyTransport) {
	t.Helper()
	conn, err := upstream.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ready := make([]byte, 5)
	if _, err := io.ReadFull(conn, ready); err != nil || string(ready) != "READY" {
		t.Fatalf("coalesced tunnel bytes lost: %q %v", ready, err)
	}
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err := io.ReadFull(conn, data); err != nil || string(data) != "PING" {
		t.Fatalf("tunnel echo failed: %q %v", data, err)
	}
}

func labCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "P0 local fixture"},
		DNSNames: []string{"proxy.proxy-harbor.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func TestHTTPAndHTTPSUpstreamTunnels(t *testing.T) {
	for _, protocol := range []string{"http", "https"} {
		for _, auth := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/auth=%v", protocol, auth), func(t *testing.T) {
				upstream := labUpstream(protocol)
				if auth {
					upstream.Username, upstream.Password = "fixture-user", "fixture-secret"
				}
				serve := func(conn net.Conn) error { return httpFixture(conn, upstream.Username, upstream.Password, 200) }
				if protocol == "https" {
					certificate, roots := labCertificate(t)
					upstream.Profile.Host = "proxy.proxy-harbor.invalid"
					upstream.BootstrapIPv4 = netip.MustParseAddr("127.0.0.1")
					upstream.TLS = &tls.Config{RootCAs: roots}
					plain := serve
					serve = func(conn net.Conn) error {
						secured := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
						defer secured.Close()
						if err := secured.Handshake(); err != nil {
							return err
						}
						if secured.ConnectionState().ServerName != upstream.Profile.Host {
							return errors.New("TLS SNI was not preserved")
						}
						return plain(secured)
					}
				}
				upstream.dialContext = pipeDialer(t, serve, false)
				assertTunnel(t, upstream)
			})
		}
	}
}

func socksFixture(conn net.Conn, username, password string) error {
	return socksFixtureTunnel(conn, username, password, "READY", echoTunnel)
}

func socksFixtureTunnel(conn net.Conn, username, password string, firstPayload string, tunnel func(net.Conn) error) error {
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return err
	}
	method := byte(0)
	if username != "" {
		method = 2
	}
	if greeting[0] != 5 || greeting[1] != 1 || greeting[2] != method {
		return errors.New("unexpected SOCKS greeting")
	}
	if err := writeAll(conn, []byte{5, method}); err != nil {
		return err
	}
	if method == 2 {
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return err
		}
		user := make([]byte, int(header[1]))
		if _, err := io.ReadFull(conn, user); err != nil {
			return err
		}
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		pass := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, pass); err != nil {
			return err
		}
		if header[0] != 1 || string(user) != username || string(pass) != password {
			return errors.New("SOCKS credentials mismatch")
		}
		if err := writeAll(conn, []byte{1, 0}); err != nil {
			return err
		}
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 || header[3] != 3 {
		return errors.New("SOCKS domain was resolved locally")
	}
	host := make([]byte, int(header[4]))
	if _, err := io.ReadFull(conn, host); err != nil {
		return err
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return err
	}
	if string(host) != "no-local-dns.proxy-harbor.invalid" || port[0] != 1 || port[1] != 187 {
		return errors.New("unexpected SOCKS target")
	}
	if err := writeAll(conn, append([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}, []byte(firstPayload)...)); err != nil {
		return err
	}
	return tunnel(conn)
}

func TestSOCKS5UsesRemoteDomainWithAndWithoutAuthentication(t *testing.T) {
	for _, auth := range []bool{false, true} {
		t.Run(fmt.Sprintf("auth=%v", auth), func(t *testing.T) {
			upstream := labUpstream("socks5")
			if auth {
				upstream.Username, upstream.Password = "fixture-user", "fixture-secret"
			}
			upstream.dialContext = pipeDialer(t, func(conn net.Conn) error { return socksFixture(conn, upstream.Username, upstream.Password) }, false)
			assertTunnel(t, upstream)
		})
	}
}

func TestProxyRejectionNeverRetriesDirectOrExposesCredentials(t *testing.T) {
	for _, status := range []int{407, 502} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			upstream := labUpstream("http")
			upstream.Username, upstream.Password = "fixture-user", "fixture-secret"
			var calls atomic.Int32
			dial := pipeDialer(t, func(conn net.Conn) error { return httpFixture(conn, upstream.Username, upstream.Password, status) }, false)
			upstream.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				calls.Add(1)
				return dial(ctx, network, address)
			}
			_, err := upstream.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443")
			if err == nil || calls.Load() != 1 {
				t.Fatalf("rejection must fail without retry: %v, calls=%d", err, calls.Load())
			}
			if strings.Contains(err.Error(), upstream.Password) || strings.Contains(err.Error(), upstream.Username) {
				t.Fatal("error exposed credentials")
			}
		})
	}
}

func TestHTTPSRejectsUntrustedCertificates(t *testing.T) {
	certificate, _ := labCertificate(t)
	upstream := labUpstream("https")
	upstream.Profile.Host = "proxy.proxy-harbor.invalid"
	upstream.BootstrapIPv4 = netip.MustParseAddr("127.0.0.1")
	upstream.TLS = &tls.Config{RootCAs: x509.NewCertPool()}
	upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
		return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}}).Handshake()
	}, true)
	_, err := upstream.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443")
	var failure *StageError
	if !errors.As(err, &failure) || failure.Stage != "TLS" {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
}

func TestInvalidRoutingNeverDials(t *testing.T) {
	for _, scenario := range []string{"missing-bootstrap", "ipv6-bootstrap", "udp", "target-injection", "insecure-tls"} {
		t.Run(scenario, func(t *testing.T) {
			upstream := labUpstream("http")
			network, address := "tcp4", "no-local-dns.proxy-harbor.invalid:443"
			switch scenario {
			case "missing-bootstrap":
				upstream.Profile.Host = "proxy.proxy-harbor.invalid"
			case "ipv6-bootstrap":
				upstream.Profile.Host = "proxy.proxy-harbor.invalid"
				upstream.BootstrapIPv4 = netip.MustParseAddr("::1")
			case "udp":
				network = "udp"
			case "target-injection":
				address = "host\r\nAuthorization:injected:443"
			case "insecure-tls":
				upstream.Profile.Protocol = "https"
				upstream.TLS = &tls.Config{InsecureSkipVerify: true}
			}
			upstream.dialContext = func(context.Context, string, string) (net.Conn, error) {
				t.Error("invalid plan dialed a socket")
				return nil, errors.New("unexpected dial")
			}
			if _, err := upstream.DialContext(context.Background(), network, address); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}

func TestCancellationClosesStalledHandshake(t *testing.T) {
	upstream := labUpstream("http")
	upstream.dialContext = pipeDialer(t, func(conn net.Conn) error { _, err := io.Copy(io.Discard, conn); return err }, false)
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	defer timer.Stop()
	defer cancel()
	started := time.Now()
	if _, err := upstream.DialContext(ctx, "tcp4", "no-local-dns.proxy-harbor.invalid:443"); err == nil {
		t.Fatal("cancelled handshake succeeded")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("cancellation did not interrupt the handshake")
	}
}

func TestOversizedProxyHeadersAreRejected(t *testing.T) {
	upstream := labUpstream("http")
	upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return err
		}
		_, err := io.WriteString(conn, "HTTP/1.1 200 Connected\r\nX-Fill: "+strings.Repeat("x", 128*1024)+"\r\n\r\n")
		return err
	}, true)
	if _, err := upstream.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443"); err == nil {
		t.Fatal("oversized proxy header accepted")
	}
}

func TestSOCKS5RefusesAuthenticationDowngradeAndFailedCredentials(t *testing.T) {
	for _, downgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("downgrade=%v", downgrade), func(t *testing.T) {
			upstream := labUpstream("socks5")
			upstream.Username, upstream.Password = "fixture-user", "fixture-secret"
			upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(conn, greeting); err != nil {
					return err
				}
				if downgrade {
					return writeAll(conn, []byte{5, 0})
				}
				if err := writeAll(conn, []byte{5, 2}); err != nil {
					return err
				}
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil {
					return err
				}
				if _, err := io.CopyN(io.Discard, conn, int64(header[1])); err != nil {
					return err
				}
				if _, err := io.ReadFull(conn, header[:1]); err != nil {
					return err
				}
				if _, err := io.CopyN(io.Discard, conn, int64(header[0])); err != nil {
					return err
				}
				return writeAll(conn, []byte{1, 1})
			}, false)
			_, err := upstream.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443")
			var failure *StageError
			if !errors.As(err, &failure) || failure.Stage != "认证" {
				t.Fatalf("SOCKS authentication failure accepted: %v", err)
			}
			if strings.Contains(err.Error(), upstream.Password) {
				t.Fatal("SOCKS error exposed credentials")
			}
		})
	}
}
