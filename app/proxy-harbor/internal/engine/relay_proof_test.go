package engine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRelayProofAndSOCKSTunnel(t *testing.T) {
	key := bytes.Repeat([]byte{0x63}, 32)
	upstream := labUpstream("http")
	upstream.dialContext = pipeDialer(t, func(c net.Conn) error { return httpFixture(c, "", "", 200) }, false)
	client := labUpstream("socks5")
	client.RelayProofKey = key
	client.dialContext = pipeDialer(t, func(c net.Conn) error {
		(Relay{Upstream: upstream, PeerProofKey: key}).serveConnection(context.Background(), c)
		return nil
	}, false)
	assertTunnel(t, client)
}

func TestRelayProofRejectsImpersonationAndReplayBeforeSOCKS(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, scenario := range []string{"wrong-key", "old-challenge", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			client := labUpstream("socks5")
			client.RelayProofKey = key
			client.dialContext = pipeDialer(t, func(c net.Conn) error {
				var challenge [40]byte
				if _, err := io.ReadFull(c, challenge[:]); err != nil {
					return err
				}
				macKey := key
				if scenario == "wrong-key" {
					macKey = bytes.Repeat([]byte{0x43}, 32)
				}
				message := challenge[:]
				if scenario == "old-challenge" {
					message = append(append([]byte(nil), relayProofMagic[:]...), make([]byte, 32)...)
				}
				mac := hmac.New(sha256.New, macKey)
				mac.Write(message)
				response := mac.Sum(nil)
				if scenario == "truncated" {
					return writeAll(c, response[:16])
				}
				if err := writeAll(c, response); err != nil {
					return err
				}
				c.SetReadDeadline(time.Now().Add(time.Second))
				var data [1]byte
				n, _ := c.Read(data[:])
				if n != 0 {
					t.Error("Impersonating listener received SOCKS data after invalid proof")
				}
				return nil
			}, false)
			if connection, err := client.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443"); err == nil {
				connection.Close()
				t.Fatal("Untrusted relay listener accepted")
			}
		})
	}
}

func TestRelayProofMismatchAndMissingProofNeverDialUpstream(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing", false: "wrong"}[missing], func(t *testing.T) {
			var calls atomic.Int32
			upstream := labUpstream("http")
			upstream.dialContext = func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, io.EOF }
			client := labUpstream("socks5")
			if !missing {
				client.RelayProofKey = bytes.Repeat([]byte{0x22}, 32)
			}
			client.dialContext = pipeDialer(t, func(c net.Conn) error {
				(Relay{Upstream: upstream, PeerProofKey: bytes.Repeat([]byte{0x11}, 32), HandshakeTimeout: 50 * time.Millisecond}).serveConnection(context.Background(), c)
				return nil
			}, false)
			if connection, err := client.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443"); err == nil {
				connection.Close()
				t.Fatal("Unauthenticated local relay connection accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("Failed proof opened upstream")
			}
		})
	}
}

func TestRelayProofRejectsInvalidScopeBeforeDial(t *testing.T) {
	for _, scenario := range []string{"short-key", "long-key", "remote-address", "http-protocol"} {
		t.Run(scenario, func(t *testing.T) {
			client := labUpstream("socks5")
			client.RelayProofKey = make([]byte, 32)
			switch scenario {
			case "short-key":
				client.RelayProofKey = make([]byte, 31)
			case "long-key":
				client.RelayProofKey = make([]byte, 33)
			case "remote-address":
				client.Profile.Host = "198.51.100.7"
			case "http-protocol":
				client.Profile.Protocol = "http"
			}
			client.dialContext = func(context.Context, string, string) (net.Conn, error) {
				t.Error("Invalid local proof configuration dialed a socket")
				return nil, io.EOF
			}
			if c, err := client.DialContext(context.Background(), "tcp4", "no-local-dns.proxy-harbor.invalid:443"); err == nil {
				c.Close()
				t.Fatal("Invalid proof scope accepted")
			}
		})
	}
}
