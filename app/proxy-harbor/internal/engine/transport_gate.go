package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ProxyTransport is the common proxy-only path for relay traffic and DNS.
// The private marker prevents accidentally assigning a plain net.Dialer.
type ProxyTransport interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	proxyOnly()
}

func (*TransportGate) proxyOnly() {}

var (
	ErrTransportClosed = errors.New("P0 转发许可未开放、已撤销或已到期")
	ErrTransportLimit  = errors.New("P0 转发连接数已达到上限")
)

const MaxTransportLease = 5 * time.Minute

type TransportGateStatus struct {
	State       string
	Generation  uint64
	Pending     int
	Connections int
	ExpiresAt   time.Time
}

// TransportGate is a P0 laboratory primitive, not a safety-report verifier or
// an OS firewall. Open explicitly permits only this proxy transport for a
// bounded interval; it does not certify application protection. The desktop
// adapter remains unavailable. The upstream is fixed for the gate's lifetime.
type TransportGate struct {
	mu          sync.Mutex
	upstream    Upstream
	limit       int
	pending     int
	generation  uint64
	lease       *transportLease
	connections map[*transportConn]struct{}
}

type transportLease struct {
	ctx     context.Context
	cancel  context.CancelFunc
	stop    func() bool
	expires time.Time
}

// NewTransportGate starts closed. Pending handshakes and live tunnels share
// one limit, so stalled upstreams cannot create an unbounded dialing queue.
func NewTransportGate(upstream Upstream, maxConnections int) *TransportGate {
	if maxConnections <= 0 {
		maxConnections = 64
	}
	if upstream.TLS != nil {
		upstream.TLS = upstream.TLS.Clone()
	}
	return &TransportGate{upstream: upstream, limit: maxConnections, connections: make(map[*transportConn]struct{})}
}

// Open replaces the previous lease, including its pending and live traffic.
// Reopening never revives an old operation. Invalid grants close the gate.
// No network checks or automatic renewals occur here; the P0 caller owns the
// explicit laboratory permission. Production admission still requires P0.
func (g *TransportGate) Open(ctx context.Context, duration time.Duration) error {
	if ctx == nil || duration <= 0 || duration > MaxTransportLease {
		g.Close()
		return errors.New("P0 转发许可需要有效上下文及不超过五分钟的正时长")
	}
	if err := ctx.Err(); err != nil {
		g.Close()
		return err
	}
	g.mu.Lock()
	old := g.revokeLocked()
	leaseCtx, cancel := context.WithTimeout(ctx, duration)
	expires, _ := leaseCtx.Deadline()
	lease := &transportLease{ctx: leaseCtx, cancel: cancel, expires: expires}
	g.lease = lease
	lease.stop = context.AfterFunc(leaseCtx, func() { g.closeLease(lease) })
	g.mu.Unlock()
	closeTransportConnections(old)
	return nil
}

// revokeLocked invalidates ownership before sockets are closed outside mu.
func (g *TransportGate) revokeLocked() []*transportConn {
	if g.lease != nil {
		g.lease.cancel()
		g.lease.stop()
		g.lease = nil
	}
	g.generation++
	old := make([]*transportConn, 0, len(g.connections))
	for conn := range g.connections {
		old = append(old, conn)
	}
	g.connections = make(map[*transportConn]struct{})
	return old
}

func closeTransportConnections(connections []*transportConn) {
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (g *TransportGate) Close() {
	g.mu.Lock()
	old := g.revokeLocked()
	g.mu.Unlock()
	closeTransportConnections(old)
}

func (g *TransportGate) closeLease(lease *transportLease) {
	g.mu.Lock()
	if g.lease != lease {
		g.mu.Unlock()
		return
	}
	old := g.revokeLocked()
	g.mu.Unlock()
	closeTransportConnections(old)
}

func (g *TransportGate) validLocked(lease *transportLease) bool {
	return lease != nil && g.lease == lease && lease.ctx.Err() == nil && time.Now().Before(lease.expires)
}

func (g *TransportGate) Status() TransportGateStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	status := TransportGateStatus{State: "closed", Generation: g.generation, Pending: g.pending}
	if g.validLocked(g.lease) {
		status.State = "open"
		status.Connections = len(g.connections)
		status.ExpiresAt = g.lease.expires
	}
	return status
}

func (g *TransportGate) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	g.mu.Lock()
	lease := g.lease
	if !g.validLocked(lease) {
		g.mu.Unlock()
		return nil, ErrTransportClosed
	}
	if g.pending+len(g.connections) >= g.limit {
		g.mu.Unlock()
		return nil, ErrTransportLimit
	}
	g.pending++
	op, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(lease.ctx, cancel)
	g.mu.Unlock()
	defer func() { stop(); cancel() }()

	conn, err := g.upstream.DialContext(op, network, address)
	g.mu.Lock()
	g.pending--
	if !g.validLocked(lease) {
		err = ErrTransportClosed
	} else if op.Err() != nil {
		err = op.Err()
	}
	if err != nil {
		g.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	wrapped := &transportConn{Conn: conn, gate: g, lease: lease}
	g.connections[wrapped] = struct{}{}
	g.mu.Unlock()
	return wrapped, nil
}

type transportConn struct {
	net.Conn
	gate  *TransportGate
	lease *transportLease
	once  sync.Once
	err   error
}

func (c *transportConn) valid() bool {
	c.gate.mu.Lock()
	defer c.gate.mu.Unlock()
	return c.gate.validLocked(c.lease)
}

func (c *transportConn) Read(data []byte) (int, error) {
	if !c.valid() {
		_ = c.Close()
		return 0, ErrTransportClosed
	}
	n, err := c.Conn.Read(data)
	// A late DNS/TCP response cannot be returned under a replacement lease.
	if !c.valid() {
		_ = c.Close()
		return 0, ErrTransportClosed
	}
	return n, err
}

func (c *transportConn) Write(data []byte) (int, error) {
	if !c.valid() {
		_ = c.Close()
		return 0, ErrTransportClosed
	}
	n, err := c.Conn.Write(data)
	if !c.valid() {
		_ = c.Close()
		return n, ErrTransportClosed
	}
	return n, err
}

func (c *transportConn) CloseWrite() error {
	if !c.valid() {
		_ = c.Close()
		return ErrTransportClosed
	}
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *transportConn) Close() error {
	c.once.Do(func() {
		_ = c.Conn.SetDeadline(time.Now())
		c.err = c.Conn.Close()
		c.gate.mu.Lock()
		delete(c.gate.connections, c)
		c.gate.mu.Unlock()
	})
	return c.err
}
