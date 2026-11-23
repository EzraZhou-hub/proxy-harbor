package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRelayForwardsOnlyThroughSelectedUpstream(t *testing.T) {
	for _, protocol := range []string{"http", "https", "socks5"} {
		for _, auth := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/auth=%v", protocol, auth), func(t *testing.T) {
				upstream := labUpstream(protocol)
				if auth {
					upstream.Username, upstream.Password = "fixture-user", "fixture-secret"
				}
				var serverTLS *tls.Config
				if protocol == "https" {
					cert, roots := labCertificate(t)
					upstream.TLS = &tls.Config{RootCAs: roots}
					upstream.Profile.Host = "proxy.proxy-harbor.invalid"
					upstream.BootstrapIPv4 = netip.MustParseAddr("127.0.0.1")
					serverTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
				}
				upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
					if serverTLS != nil {
						conn = tls.Server(conn, serverTLS)
					}
					if protocol == "socks5" {
						return socksFixture(conn, upstream.Username, upstream.Password)
					}
					return httpFixture(conn, upstream.Username, upstream.Password, 200)
				}, false)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				gate := openTestGate(t, upstream, 64)
				client := labUpstream("socks5")
				client.dialContext = pipeDialer(t, func(conn net.Conn) error { (Relay{Upstream: gate}).serveConnection(ctx, conn); return nil }, false)
				assertTunnel(t, client)
				cancel()
			})
		}
	}
}

func TestRelayRejectsUDPIPv6AndInvalidHandshakesBeforeDial(t *testing.T) {
	for name, request := range map[string][]byte{
		"udp":          {5, 3, 0, 1, 127, 0, 0, 1, 0, 53},
		"bind":         {5, 2, 0, 1, 127, 0, 0, 1, 0, 80},
		"ipv6":         {5, 1, 0, 4},
		"reserved":     {5, 1, 1, 1},
		"empty-domain": {5, 1, 0, 3, 0},
	} {
		t.Run(name, func(t *testing.T) {
			upstream := labUpstream("http")
			upstream.dialContext = func(context.Context, string, string) (net.Conn, error) {
				t.Error("invalid request dialed upstream")
				return nil, io.EOF
			}
			client, server := net.Pipe()
			client.SetDeadline(time.Now().Add(time.Second))
			defer client.Close()
			done := make(chan struct{})
			go func() { (Relay{Upstream: upstream}).serveConnection(context.Background(), server); close(done) }()
			writeAll(client, []byte{5, 1, 0})
			var method [2]byte
			if _, err := io.ReadFull(client, method[:]); err != nil || method != [2]byte{5, 0} {
				t.Fatalf("greeting: %v", err)
			}
			// net.Pipe writes are synchronous, so send only the parsed header for
			// commands that are rejected before their address is consumed.
			if name == "udp" || name == "bind" {
				request = request[:4]
			}
			writeAll(client, request)
			result, _ := io.ReadAll(client)
			if len(result) > 1 && result[1] == 0 {
				t.Fatal("invalid request succeeded")
			}
			<-done
		})
	}
}

func TestRelayCancellationStopsStalledClients(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { (Relay{Upstream: labUpstream("http")}).serveConnection(ctx, server); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop a stalled client")
	}
}
