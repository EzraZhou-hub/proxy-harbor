package engine

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

const gateTarget = "no-local-dns.proxy-harbor.invalid:443"

func openTestGate(t *testing.T, upstream Upstream, limit int) *TransportGate {
	t.Helper()
	gate := NewTransportGate(upstream, limit)
	t.Cleanup(gate.Close)
	if err := gate.Open(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	return gate
}

func waitGateSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("transport operation did not reach its checkpoint")
	}
}

func TestTransportGateDefaultsClosedAndRejectsInvalidLeases(t *testing.T) {
	upstream := labUpstream("http")
	var calls atomic.Int32
	upstream.dialContext = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, io.EOF
	}
	gate := NewTransportGate(upstream, 1)
	defer gate.Close()
	if _, err := gate.DialContext(context.Background(), "tcp4", gateTarget); !errors.Is(err, ErrTransportClosed) {
		t.Fatalf("default gate: %v", err)
	}
	for _, duration := range []time.Duration{0, -time.Second, MaxTransportLease + time.Second} {
		if err := gate.Open(context.Background(), time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := gate.Open(context.Background(), duration); err == nil || gate.Status().State != "closed" {
			t.Fatal("invalid lease retained the previous permission")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.Open(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lease accepted: %v", err)
	}
	if err := gate.Open(nil, time.Minute); err == nil {
		t.Fatal("nil lease accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("closed gate contacted an upstream")
	}
}

func TestTransportGateRevokesLiveConnections(t *testing.T) {
	for _, mode := range []string{"close", "replace", "cancel", "expire"} {
		t.Run(mode, func(t *testing.T) {
			upstream := labUpstream("http")
			upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
				return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error {
					_, err := io.Copy(io.Discard, conn)
					return err
				})
			}, true)
			gate := NewTransportGate(upstream, 1)
			defer gate.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			duration := time.Minute
			if mode == "expire" {
				duration = 80 * time.Millisecond
			}
			if err := gate.Open(ctx, duration); err != nil {
				t.Fatal(err)
			}
			conn, err := gate.DialContext(context.Background(), "tcp4", gateTarget)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if gate.Status().Connections != 1 {
				t.Fatal("live tunnel not tracked")
			}
			readResult := make(chan error, 1)
			go func() { _, err := conn.Read(make([]byte, 1)); readResult <- err }()
			switch mode {
			case "close":
				gate.Close()
			case "replace":
				if err := gate.Open(context.Background(), time.Minute); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			select {
			case err := <-readResult:
				if !errors.Is(err, ErrTransportClosed) {
					t.Fatalf("revoked read: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("revocation did not close the established tunnel")
			}
			if n, err := conn.Write([]byte("stale")); n != 0 || !errors.Is(err, ErrTransportClosed) {
				t.Fatalf("old connection usable after revocation: %d %v", n, err)
			}
			if mode != "replace" {
				if _, err := gate.DialContext(context.Background(), "tcp4", gateTarget); !errors.Is(err, ErrTransportClosed) {
					t.Fatalf("revoked gate reopened: %v", err)
				}
			}
		})
	}
}

func TestTransportGateCancelsPendingDialAndHandshake(t *testing.T) {
	for _, mode := range []string{"dial", "handshake"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			upstream := labUpstream("http")
			if mode == "dial" {
				upstream.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
			} else {
				upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
					if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
						return err
					}
					close(entered)
					_, err := io.Copy(io.Discard, conn)
					return err
				}, true)
			}
			gate := openTestGate(t, upstream, 1)
			result := make(chan error, 1)
			go func() { _, err := gate.DialContext(context.Background(), "tcp4", gateTarget); result <- err }()
			waitGateSignal(t, entered)
			if gate.Status().Pending != 1 {
				t.Fatal("pending connection not accounted for")
			}
			if _, err := gate.DialContext(context.Background(), "tcp4", gateTarget); !errors.Is(err, ErrTransportLimit) {
				t.Fatalf("stalled handshake bypassed capacity limit: %v", err)
			}
			gate.Close()
			select {
			case err := <-result:
				if !errors.Is(err, ErrTransportClosed) {
					t.Fatalf("pending operation returned: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("pending operation survived revocation")
			}
			if gate.Status().Pending != 0 {
				t.Fatal("pending slot leaked")
			}
		})
	}
}

// A handshake can finish exactly as its lease is replaced. Delay the final
// deadline reset after CONNECT succeeded to exercise registration, not merely
// an error from an interrupted socket.
type delayedReadyConn struct {
	net.Conn
	ready   chan struct{}
	release chan struct{}
}

func (c *delayedReadyConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		close(c.ready)
		<-c.release
	}
	return c.Conn.SetDeadline(deadline)
}

func TestTransportGateRejectsLateHandshakeFromReplacedLease(t *testing.T) {
	upstream := labUpstream("http")
	ready, release := make(chan struct{}), make(chan struct{})
	dial := pipeDialer(t, func(conn net.Conn) error {
		return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error {
			_, err := io.Copy(io.Discard, conn)
			return err
		})
	}, true)
	upstream.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		return &delayedReadyConn{Conn: conn, ready: ready, release: release}, err
	}
	gate := openTestGate(t, upstream, 1)
	result := make(chan error, 1)
	go func() {
		conn, err := gate.DialContext(context.Background(), "tcp4", gateTarget)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	waitGateSignal(t, ready)
	before := gate.Status().Generation
	if err := gate.Open(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	// Reopening must not free the old pending slot before its dial returns.
	if _, err := gate.DialContext(context.Background(), "tcp4", gateTarget); !errors.Is(err, ErrTransportLimit) {
		t.Fatalf("replacement bypassed the shared pending limit: %v", err)
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, ErrTransportClosed) {
			t.Fatalf("stale successful handshake accepted: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late handshake did not complete")
	}
	status := gate.Status()
	if status.Generation <= before || status.Connections != 0 || status.Pending != 0 || status.State != "open" {
		t.Fatalf("stale operation changed replacement state: %+v", status)
	}
}

func TestTransportGateLiveLimitAndSlotRecovery(t *testing.T) {
	upstream := labUpstream("http")
	upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
		return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error {
			_, err := io.Copy(io.Discard, conn)
			return err
		})
	}, true)
	gate := openTestGate(t, upstream, 1)
	for range 2 {
		conn, err := gate.DialContext(context.Background(), "tcp4", gateTarget)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gate.DialContext(context.Background(), "tcp4", gateTarget); !errors.Is(err, ErrTransportLimit) {
			t.Fatalf("live tunnel bypassed limit: %v", err)
		}
		conn.Close()
		conn.Close()
		if gate.Status().Connections != 0 {
			t.Fatal("closed tunnel retained capacity")
		}
	}
}

func TestTransportGateRevokesPendingDNSResponse(t *testing.T) {
	querySent := make(chan struct{})
	upstream := labUpstream("http")
	upstream.dialContext = pipeDialer(t, func(conn net.Conn) error {
		return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error {
			frame := make([]byte, 2+len(labDNSQuery()))
			if _, err := io.ReadFull(conn, frame); err != nil {
				return err
			}
			close(querySent)
			_, err := io.Copy(io.Discard, conn)
			return err
		})
	}, true)
	gate := openTestGate(t, upstream, 2)
	result := make(chan error, 1)
	go func() {
		answer, err := (DNSForwarder{Upstream: gate, Resolver: gateTarget}).RoundTrip(context.Background(), labDNSQuery())
		if len(answer) != 0 {
			t.Error("revoked DNS returned a response")
		}
		result <- err
	}()
	waitGateSignal(t, querySent)
	if err := gate.Open(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("old DNS exchange survived lease replacement")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old DNS exchange was not interrupted")
	}
}

// Deliver bytes just before a revoke, then let Read finish after replacement.
// This models completion racing cancellation even when Close cannot recall an
// already completed socket read.
type delayedReadConn struct {
	net.Conn
	armed   atomic.Bool
	ready   chan struct{}
	release chan struct{}
}

func (c *delayedReadConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 && c.armed.CompareAndSwap(true, false) {
		close(c.ready)
		<-c.release
	}
	return n, err
}

func TestTransportGateDiscardsLateReadAfterReplacement(t *testing.T) {
	upstream := labUpstream("http")
	payload := make(chan struct{})
	dial := pipeDialer(t, func(conn net.Conn) error {
		return httpFixtureTunnel(conn, "", "", 200, "", func(conn net.Conn) error {
			<-payload
			return writeAll(conn, []byte("late"))
		})
	}, true)
	raw := &delayedReadConn{ready: make(chan struct{}), release: make(chan struct{})}
	upstream.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		raw.Conn = conn
		return raw, err
	}
	gate := openTestGate(t, upstream, 1)
	conn, err := gate.DialContext(context.Background(), "tcp4", gateTarget)
	if err != nil {
		t.Fatal(err)
	}
	raw.armed.Store(true)
	close(payload)
	result := make(chan error, 1)
	go func() {
		n, err := conn.Read(make([]byte, 4))
		if n != 0 {
			t.Error("late payload returned after lease replacement")
		}
		result <- err
	}()
	waitGateSignal(t, raw.ready)
	if err := gate.Open(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	close(raw.release)
	select {
	case err := <-result:
		if !errors.Is(err, ErrTransportClosed) {
			t.Fatalf("late read: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late read did not return")
	}
}

func TestMissingProxyTransportFailsClosed(t *testing.T) {
	if _, err := (DNSForwarder{Resolver: gateTarget}).RoundTrip(context.Background(), labDNSQuery()); err == nil {
		t.Fatal("DNS accepted an absent proxy transport")
	}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { (Relay{}).serveConnection(context.Background(), server); close(done) }()
	waitGateSignal(t, done)
	if _, err := client.Write([]byte{5, 1, 0}); err == nil {
		t.Fatal("relay accepted an absent proxy transport")
	}
}
