package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"proxyharbor/internal/domain"
	"strconv"
	"time"
)

// Upstream is a TCP transport for the P0 laboratory. It is not an application
// interceptor and does not imply DNS interception or operating-system protection.
// Credentials remain in memory; callers must never persist or log this value.
type Upstream struct {
	Profile       domain.ProxyProfile
	BootstrapIPv4 netip.Addr
	Username      string
	Password      string
	TLS           *tls.Config
	Timeout       time.Duration
	dialContext   func(context.Context, string, string) (net.Conn, error)
	RelayProofKey []byte // optional proof, restricted to a local SOCKS5 relay
}

func (Upstream) proxyOnly() {}

type StageError struct {
	Stage string
	Cause error
}

func (e *StageError) Error() string { return fmt.Sprintf("代理%s失败: %v", e.Stage, e.Cause) }
func (e *StageError) Unwrap() error { return e.Cause }

func stageError(stage string, err error) error { return &StageError{Stage: stage, Cause: err} }

// DialContext connects only to the configured IPv4 proxy. Target domain names
// are sent verbatim to CONNECT/SOCKS5 and never passed to the local resolver.
// A domain proxy entrance requires an explicit bootstrap IPv4, preserving its
// domain for TLS certificate/SNI checks. No branch retries a direct target.
func (u Upstream) DialContext(ctx context.Context, network, address string) (result net.Conn, resultErr error) {
	if network != "tcp" && network != "tcp4" {
		return nil, stageError("配置", errors.New("当前仅提供 IPv4 TCP 上游传输"))
	}
	if err := domain.ValidateProfile(u.Profile); err != nil {
		return nil, stageError("配置", err)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, stageError("配置", errors.New("目标地址需要域名或 IPv4 及端口"))
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, stageError("配置", errors.New("目标端口无效"))
	}
	target := domain.ProxyProfile{Name: "target", Protocol: "http", Host: host, Port: port}
	if err := domain.ValidateProfile(target); err != nil {
		return nil, stageError("配置", errors.New("目标域名、IPv4 或端口无效"))
	}
	ip, err := netip.ParseAddr(u.Profile.Host)
	if err != nil {
		ip = u.BootstrapIPv4
	}
	if !ip.IsValid() || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, stageError("配置", errors.New("代理入口需要明确的 IPv4；域名入口需预配置引导 IPv4"))
	}
	if len(u.RelayProofKey) != 0 && (len(u.RelayProofKey) != 32 || u.Profile.Protocol != "socks5" || ip != netip.MustParseAddr("127.0.0.1")) {
		return nil, stageError("配置", errors.New("入口证明仅允许 32 字节密钥及本地 SOCKS5 中转"))
	}
	if len(u.Username) > 255 || len(u.Password) > 255 || (u.Username == "" && u.Password != "") {
		return nil, stageError("配置", errors.New("代理认证字段无效"))
	}
	if u.Profile.Protocol == "https" && u.TLS != nil && u.TLS.InsecureSkipVerify {
		return nil, stageError("配置", errors.New("HTTPS 代理必须验证证书"))
	}
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := u.dialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(handshakeCtx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(u.Profile.Port)))
	if err != nil {
		return nil, stageError("入口连接", err)
	}
	rawConn := conn
	defer func() {
		if resultErr != nil {
			conn.Close()
		}
	}()
	deadline, _ := handshakeCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, stageError("入口连接", err)
	}
	stop := context.AfterFunc(handshakeCtx, func() { rawConn.Close() })
	defer stop()
	if u.Profile.Protocol == "https" {
		config := &tls.Config{}
		if u.TLS != nil {
			config = u.TLS.Clone()
		}
		config.ServerName = u.Profile.Host
		if config.MinVersion < tls.VersionTLS12 {
			config.MinVersion = tls.VersionTLS12
		}
		secured := tls.Client(conn, config)
		if err := secured.HandshakeContext(handshakeCtx); err != nil {
			return nil, stageError("TLS", err)
		}
		conn = secured
	}
	if u.Profile.Protocol == "socks5" {
		if len(u.RelayProofKey) != 0 {
			if err := relayProofClient(conn, u.RelayProofKey); err != nil {
				return nil, stageError("入口证明", err)
			}
		}
		if err := u.socksConnect(conn, host, port); err != nil {
			return nil, err
		}
		result = conn
	} else {
		result, err = u.httpConnect(conn, net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
	}
	if !stop() {
		return nil, stageError("握手", handshakeCtx.Err())
	}
	if err := handshakeCtx.Err(); err != nil {
		return nil, stageError("握手", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, stageError("握手", err)
	}
	return result, nil
}

type headerLimitedConn struct {
	net.Conn
	remaining int
}

func (c *headerLimitedConn) Read(data []byte) (int, error) {
	if c.remaining == 0 {
		return 0, errors.New("proxy header limit exceeded")
	}
	if c.remaining > 0 && len(data) > c.remaining {
		data = data[:c.remaining]
	}
	n, err := c.Conn.Read(data)
	if c.remaining > 0 {
		c.remaining -= n
	}
	return n, err
}

type bufferedTunnel struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedTunnel) Read(data []byte) (int, error) { return c.reader.Read(data) }

func (c *bufferedTunnel) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}

func (u Upstream) httpConnect(conn net.Conn, address string) (net.Conn, error) {
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if u.Username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(u.Username + ":" + u.Password))
		request.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := request.Write(conn); err != nil {
		return nil, stageError("CONNECT", err)
	}
	limited := &headerLimitedConn{Conn: conn, remaining: 64 * 1024}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, stageError("CONNECT", errors.New("代理响应无效或超出大小限制"))
	}
	if response.StatusCode == http.StatusProxyAuthRequired {
		return nil, stageError("认证", errors.New("代理拒绝认证"))
	}
	if response.StatusCode != http.StatusOK {
		return nil, stageError("CONNECT", fmt.Errorf("代理返回 HTTP %d", response.StatusCode))
	}
	// Keep any tunnel bytes coalesced with the CONNECT response, and remove the
	// header-only limit before returning the streaming connection.
	limited.remaining = -1
	return &bufferedTunnel{Conn: conn, reader: reader}, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (u Upstream) socksConnect(conn net.Conn, host string, port int) error {
	method := byte(0)
	if u.Username != "" {
		method = 2
	}
	if err := writeAll(conn, []byte{5, 1, method}); err != nil {
		return stageError("SOCKS5", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return stageError("SOCKS5", err)
	}
	if reply[0] != 5 || reply[1] != method {
		return stageError("认证", errors.New("SOCKS5 代理未接受请求的认证方式"))
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(u.Username))}, []byte(u.Username)...)
		auth = append(auth, byte(len(u.Password)))
		auth = append(auth, []byte(u.Password)...)
		if err := writeAll(conn, auth); err != nil {
			return stageError("认证", err)
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			return stageError("认证", err)
		}
		if reply[0] != 1 || reply[1] != 0 {
			return stageError("认证", errors.New("SOCKS5 代理拒绝认证"))
		}
	}
	request := []byte{5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		address := ip.As4()
		request = append(request, 1)
		request = append(request, address[:]...)
	} else {
		if len(host) > 255 {
			return stageError("配置", errors.New("SOCKS5 目标域名过长"))
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	request = append(request, byte(port>>8), byte(port))
	if err := writeAll(conn, request); err != nil {
		return stageError("SOCKS5", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return stageError("SOCKS5", err)
	}
	if response[0] != 5 || response[2] != 0 || response[1] != 0 {
		return stageError("SOCKS5", errors.New("代理拒绝目标连接或响应无效"))
	}
	size := 0
	switch response[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return stageError("SOCKS5", err)
		}
		if length[0] == 0 {
			return stageError("SOCKS5", errors.New("代理绑定地址无效"))
		}
		size = int(length[0])
	default:
		return stageError("SOCKS5", errors.New("代理绑定地址类型无效"))
	}
	if _, err := io.CopyN(io.Discard, conn, int64(size+2)); err != nil {
		return stageError("SOCKS5", err)
	}
	return nil
}
