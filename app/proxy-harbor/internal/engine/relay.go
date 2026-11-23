package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Relay accepts explicit SOCKS5 CONNECT requests on one IPv4 loopback listener.
// It forwards only through Upstream, without target DNS or direct fallback.
// This is a P0 transport component, not transparent application interception.
type Relay struct {
	Upstream         ProxyTransport
	PeerProofKey     []byte // optional 32-byte process-local listener proof key
	HandshakeTimeout time.Duration
	MaxConnections   int
}

func (r Relay) Serve(ctx context.Context, listener net.Listener) error {
	if r.Upstream == nil {
		return errors.New("relay requires an explicit proxy transport")
	}
	if len(r.PeerProofKey) != 0 && len(r.PeerProofKey) != 32 {
		return errors.New("relay proof requires exactly 32 key bytes")
	}
	r.PeerProofKey = append([]byte(nil), r.PeerProofKey...)
	endpoint, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil || endpoint.Addr() != netip.MustParseAddr("127.0.0.1") || listener.Addr().Network() != "tcp" {
		return errors.New("relay requires an IPv4 127.0.0.1 TCP listener")
	}
	ctx, cancel := context.WithCancel(ctx)
	var clients sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	defer func() { cancel(); listener.Close(); clients.Wait() }()
	limit := r.MaxConnections
	if limit <= 0 {
		limit = 64
	}
	slots := make(chan struct{}, limit)
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		peer, err := netip.ParseAddrPort(client.RemoteAddr().String())
		if err != nil || !peer.Addr().IsLoopback() {
			client.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-slots }()
				r.serveConnection(ctx, client)
			}()
		default:
			client.Close()
		}
	}
}

func (r Relay) serveConnection(ctx context.Context, client net.Conn) {
	defer client.Close()
	if r.Upstream == nil {
		return
	}
	stopClient := context.AfterFunc(ctx, func() { client.Close() })
	defer stopClient()
	timeout := r.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	if len(r.PeerProofKey) != 0 {
		if err := relayProofServer(client, r.PeerProofKey); err != nil {
			return
		}
	}
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting[0] != 5 || greeting[1] == 0 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0
	}
	if !noAuth {
		writeAll(client, []byte{5, 255})
		return
	}
	if err := writeAll(client, []byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(client, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	if request[1] != 1 {
		relayReply(client, 7) // BIND and UDP ASSOCIATE are never enabled.
		return
	}
	var host string
	switch request[3] {
	case 1:
		var address [4]byte
		if _, err := io.ReadFull(client, address[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(address).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil || length[0] == 0 {
			return
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, name); err != nil {
			return
		}
		host = string(name)
	default:
		relayReply(client, 8) // Includes IPv6: the strict first version is IPv4.
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(client, port[:]); err != nil {
		return
	}
	handshake, cancel := context.WithTimeout(ctx, timeout)
	remote, err := r.Upstream.DialContext(handshake, "tcp4", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))))
	cancel()
	if err != nil {
		relayReply(client, 1) // Never send upstream errors or credentials to a client.
		return
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	if err := relayReply(client, 0); err != nil {
		return
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	// Preserve TCP half-close: a client can finish its request and still read
	// the complete response. An error or cancellation closes both directions.
	done := make(chan struct{}, 2)
	copyStream := func(destination net.Conn, source net.Conn) {
		_, err := io.Copy(destination, source)
		if err == nil {
			if half, ok := destination.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			}
		}
		if err != nil {
			client.Close()
			remote.Close()
		}
		done <- struct{}{}
	}
	go copyStream(remote, client)
	go copyStream(client, remote)
	<-done
	<-done
}

func relayReply(client net.Conn, status byte) error {
	return writeAll(client, []byte{5, status, 0, 1, 127, 0, 0, 1, 0, 0})
}
