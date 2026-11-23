package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func labDNSQuery() []byte {
	return []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1}
}

func labDNSAnswer() []byte {
	answer := labDNSQuery()
	answer[2], answer[3], answer[7] = 0x81, 0x80, 1
	return append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7)
}

func dnsFixture(conn net.Conn, answer []byte) error {
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return err
	}
	data := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	if _, err := io.ReadFull(conn, data); err != nil {
		return err
	}
	if !bytes.Equal(data, labDNSQuery()) {
		return errors.New("DNS query was not forwarded verbatim")
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
	return writeAll(conn, append(size[:], answer...))
}

func TestDNSForwarderUsesOnlyProxyTransport(t *testing.T) {
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
					upstream.Profile.Host = "proxy.proxy-harbor.invalid"
					upstream.BootstrapIPv4 = netip.MustParseAddr("127.0.0.1")
					upstream.TLS = &tls.Config{RootCAs: roots}
					serverTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
				}
				upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
					if serverTLS != nil {
						conn = tls.Server(conn, serverTLS)
					}
					tunnel := func(conn net.Conn) error { return dnsFixture(conn, labDNSAnswer()) }
					if protocol == "socks5" {
						return socksFixtureTunnel(conn, upstream.Username, upstream.Password, "", tunnel)
					}
					return httpFixtureTunnel(conn, upstream.Username, upstream.Password, 200, "", tunnel)
				}, false)
				forwarder := DNSForwarder{Upstream: openTestGate(t, upstream, 64), Resolver: "no-local-dns.proxy-harbor.invalid:443"}
				answer, err := forwarder.RoundTrip(context.Background(), labDNSQuery())
				if err != nil || !bytes.Equal(answer, labDNSAnswer()) {
					t.Fatalf("DNS exchange: %x %v", answer, err)
				}
			})
		}
	}
}

func TestDNSForwarderRejectsInvalidQueriesBeforeDial(t *testing.T) {
	for _, query := range [][]byte{nil, {1, 2}, bytes.Repeat([]byte{0}, 12), {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}} {
		upstream := labUpstream("http")
		upstream.dialContext = func(context.Context, string, string) (net.Conn, error) {
			t.Error("invalid DNS query dialed")
			return nil, io.EOF
		}
		if _, err := (DNSForwarder{Upstream: upstream, Resolver: "resolver.invalid:53"}).RoundTrip(context.Background(), query); err == nil {
			t.Fatal("Invalid DNS query succeeded")
		}
	}
}

func TestDNSForwarderRejectsMismatchedAndTruncatedResponses(t *testing.T) {
	for _, field := range []string{"id", "question", "not-response", "truncated"} {
		t.Run(field, func(t *testing.T) {
			answer := labDNSAnswer()
			switch field {
			case "id":
				answer[0]++
			case "question":
				answer[13] = 'x'
			case "not-response":
				answer[2] &^= 0x80
			case "truncated":
				answer[2] |= 2
			}
			upstream := labUpstream("http")
			upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
				return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error { return dnsFixture(conn, answer) })
			}, false)
			if _, err := (DNSForwarder{Upstream: upstream, Resolver: "no-local-dns.proxy-harbor.invalid:443"}).RoundTrip(context.Background(), labDNSQuery()); err == nil {
				t.Fatal("Invalid DNS response succeeded")
			}
		})
	}
}

func TestDNSForwarderPreservesNegativeAnswersAndNeverFallsBack(t *testing.T) {
	answer := labDNSQuery()
	answer[2], answer[3] = 0x81, 0x83 // NXDOMAIN.
	upstream := labUpstream("http")
	var calls atomic.Int32
	dial := pipeDialer(t, func(conn net.Conn) error {
		return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error { return dnsFixture(conn, answer) })
	}, false)
	upstream.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		return dial(ctx, network, address)
	}
	actual, err := (DNSForwarder{Upstream: upstream, Resolver: "no-local-dns.proxy-harbor.invalid:443"}).RoundTrip(context.Background(), labDNSQuery())
	if err != nil || !bytes.Equal(actual, answer) || calls.Load() != 1 {
		t.Fatalf("Negative DNS response retried or changed: %v", err)
	}
	upstream.dialContext = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("fixture unavailable")
	}
	if _, err := (DNSForwarder{Upstream: upstream, Resolver: "resolver.invalid:53"}).RoundTrip(context.Background(), labDNSQuery()); err == nil || calls.Load() != 2 {
		t.Fatal("Unavailable upstream did not fail without retry")
	}
}

func TestDNSForwarderTimesOutAnUnresponsiveResolver(t *testing.T) {
	upstream := labUpstream("http")
	upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
		return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error { _, err := io.Copy(io.Discard, conn); return err })
	}, false)
	start := time.Now()
	if _, err := (DNSForwarder{Upstream: upstream, Resolver: "no-local-dns.proxy-harbor.invalid:443", Timeout: 30 * time.Millisecond}).RoundTrip(context.Background(), labDNSQuery()); err == nil {
		t.Fatal("Unresponsive DNS resolver succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("DNS resolver timeout was not enforced")
	}
}
