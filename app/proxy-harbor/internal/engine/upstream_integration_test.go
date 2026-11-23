//go:build p0integration

package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestP0RelayHalfClosePreservesTheFullResponse(t *testing.T) {
	for _, protocol := range []string{"http", "https"} {
		t.Run(protocol, func(t *testing.T) {
			proxy, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			upstream := labUpstream(protocol)
			upstream.Profile.Port = proxy.Addr().(*net.TCPAddr).Port
			var serverTLS *tls.Config
			if protocol == "https" {
				certificate, roots := labCertificate(t)
				upstream.Profile.Host = "proxy.proxy-harbor.invalid"
				upstream.BootstrapIPv4 = netip.MustParseAddr("127.0.0.1")
				upstream.TLS = &tls.Config{RootCAs: roots}
				serverTLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
			}
			requestBody := bytes.Repeat([]byte("request-"), 8192)
			responseBody := bytes.Repeat([]byte("response-after-EOF-"), 2048)
			completed := make(chan error, 1)
			go func() {
				conn, err := proxy.Accept()
				if err != nil {
					completed <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				if serverTLS != nil {
					conn = tls.Server(conn, serverTLS)
				}
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					completed <- err
					return
				}
				if request.Method != "CONNECT" || request.Host != "no-local-dns.proxy-harbor.invalid:443" {
					completed <- errors.New("unexpected relay target")
					return
				}
				if _, err := io.WriteString(conn, "HTTP/1.1 200 Connected\r\n\r\n"); err != nil {
					completed <- err
					return
				}
				payload, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(payload, requestBody) {
					completed <- fmt.Errorf("request lost before half-close: %v", err)
					return
				}
				completed <- writeAll(conn, responseBody)
			}()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			gate := openTestGate(t, upstream, 64)
			stopped := make(chan error, 1)
			go func() { stopped <- (Relay{Upstream: gate}).Serve(ctx, listener) }()
			defer func() {
				cancel()
				select {
				case err := <-stopped:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("relay shutdown timed out")
				}
			}()
			clientProxy := labUpstream("socks5")
			clientProxy.Profile.Port = listener.Addr().(*net.TCPAddr).Port
			conn, err := clientProxy.DialContext(ctx, "tcp4", "no-local-dns.proxy-harbor.invalid:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			if err := writeAll(conn, requestBody); err != nil {
				t.Fatal(err)
			}
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(response, responseBody) {
				t.Fatalf("response lost after half-close: bytes=%d %v", len(response), err)
			}
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Real loopback TCP/TLS sockets, explicit proxy traffic, no target application,
// DNS request, public endpoint, Windows policy or driver operation.
func TestP0RealSocketProtocols(t *testing.T) {
	for _, protocol := range []string{"http", "https", "socks5"} {
		for _, auth := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/auth=%v", protocol, auth), func(t *testing.T) {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				upstream := labUpstream(protocol)
				upstream.Profile.Port = listener.Addr().(*net.TCPAddr).Port
				if auth {
					upstream.Username, upstream.Password = "fixture-user", "fixture-secret"
				}
				var serverTLS *tls.Config
				if protocol == "https" {
					certificate, roots := labCertificate(t)
					upstream.Profile.Host = "proxy.proxy-harbor.invalid"
					upstream.BootstrapIPv4 = netip.MustParseAddr("127.0.0.1")
					upstream.TLS = &tls.Config{RootCAs: roots}
					serverTLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
				}
				finished := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						finished <- err
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					if serverTLS != nil {
						conn = tls.Server(conn, serverTLS)
					}
					if protocol == "socks5" {
						finished <- socksFixture(conn, upstream.Username, upstream.Password)
					} else {
						finished <- httpFixture(conn, upstream.Username, upstream.Password, 200)
					}
				}()
				assertTunnel(t, openTestGate(t, upstream, 64))
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(4 * time.Second):
					t.Fatal("real socket fixture did not stop")
				}
			})
		}
	}
}

func TestP0UnavailableProxyDoesNotContactTheTarget(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	closedProxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := closedProxy.Addr().(*net.TCPAddr).Port
	closedProxy.Close()
	upstream := labUpstream("http")
	upstream.Profile.Port = port
	upstream.Timeout = 200 * time.Millisecond
	if _, err := upstream.DialContext(context.Background(), "tcp4", target.Addr().String()); err == nil {
		t.Fatal("unavailable proxy reported success")
	}
	target.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	conn, err := target.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("proxy failure connected directly to target")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal(err)
	}
}
