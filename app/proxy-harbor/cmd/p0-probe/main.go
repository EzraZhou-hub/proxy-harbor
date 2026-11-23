// p0-probe is a disposable laboratory client, never a Claude/Codex launcher.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"strings"
	"time"
)

func main() {
	network := flag.String("network", "tcp4", "tcp4, tcp6, udp4 or udp6")
	address := flag.String("address", "127.0.0.1:9", "loopback test endpoint")
	protocol := flag.String("proxy-protocol", "", "optional http, https or socks5 upstream")
	proxy := flag.String("proxy", "127.0.0.1:7890", "IPv4 proxy endpoint")
	target := flag.String("target", "p0.proxy-harbor.invalid:443", "unresolved target passed to the proxy")
	wait := flag.Bool("wait-for-input", false, "fixture: wait for a continue line after connecting, before echo")
	dns := flag.String("dns-message", "", "optional hex DNS query, sent only through the explicit proxy")
	transparent := flag.String("transparent-target", "", "guest-only: normal TCP APIs for a fixed .invalid or TEST-NET target")
	resolveAPI := flag.String("resolve-api", "winsock", "guest-only resolver API fixture")
	spawnDepth := flag.Int("spawn-depth", 0, "guest-only: launch this same probe through up to two child generations")
	helper := flag.Bool("use-helper", false, "guest-only: launch the fixed helper in a different path")
	dnsAudit := flag.String("dns-audit", "", "guest-only fixed DNS coverage scenario")
	dnsAuditName := flag.String("dns-audit-name", "", "guest-only unique .p0-dns-audit.invalid name")
	payloadSize := flag.Int("payload-size", 2, "guest-only bounded echo payload size, 2..60000")
	publicCheck := flag.Bool("public-check", false, "guest-only fixed anonymous HTTPS check, no proxy flags")
	publicWire := flag.Bool("public-wire", false, "guest-only fixed public DNS wire baseline")
	lifecycle := flag.Bool("lifecycle", false, "guest-only bounded interactive connection fixture")
	flag.Parse()
	if *payloadSize < 2 || *payloadSize > 60000 {
		emit(false, "invalid echo payload size")
		return
	}
	if *payloadSize != 2 {
		working, _ := os.Getwd()
		if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
			emit(false, "large echo payload requires the disposable guest")
			return
		}
	}
	if os.Getenv("P0_REQUIRE_APP_CONTAINER") == "1" && !verifiedAppContainer() {
		emit(false, "required zero-capability AppContainer token was not inherited")
		return
	}
	if *publicCheck {
		runPublicCheck()
		return
	}
	if *lifecycle {
		runLifecycle()
		return
	}
	if *publicWire {
		runPublicWire(*network, *address)
		return
	}
	if *dnsAudit != "" {
		runDNSAudit(*dnsAudit, *dnsAuditName)
		return
	}
	if *spawnDepth < 0 || *spawnDepth > 2 || (*spawnDepth != 0 && *transparent == "") {
		emit(false, "child fixture requires transparent mode and depth 0..2")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	if *transparent != "" {
		working, _ := os.Getwd()
		if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" ||
			(*transparent != "no-local-dns.proxy-harbor.invalid:443" && *transparent != "198.51.100.7:443") {
			emit(false, "transparent fixture mode requires the isolated guest and an allowlisted test target")
			return
		}
		if *spawnDepth > 0 {
			runChildFixture(*spawnDepth, *transparent, *resolveAPI, *helper)
			return
		}
		endpoint := *transparent
		if *resolveAPI != "winsock" {
			endpoint, err = resolveTransparent(*resolveAPI, endpoint)
			if errors.Is(err, errAsyncDNSBlocked) {
				emit(true, "resolver request ended without a connection")
				return
			}
			if err != nil {
				emit(false, err.Error())
				return
			}
		}
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp4", endpoint)
	} else if *protocol != "" {
		endpoint, parseErr := netip.ParseAddrPort(*proxy)
		if parseErr != nil {
			emit(false, "invalid proxy endpoint")
			return
		}
		transport := engine.Upstream{Profile: domain.ProxyProfile{Name: "P0 fixture", Protocol: *protocol, Host: endpoint.Addr().String(), Port: int(endpoint.Port())}}
		if value := os.Getenv("P0_RELAY_PROOF_KEY"); value != "" && *protocol == "socks5" {
			key, err := hex.DecodeString(value)
			if err != nil || len(key) != 32 {
				emit(false, "invalid temporary relay proof key")
				return
			}
			transport.RelayProofKey = key
		}
		if *dns != "" {
			query, err := hex.DecodeString(*dns)
			if err != nil {
				emit(false, "invalid fixture DNS query")
				return
			}
			answer, err := (engine.DNSForwarder{Upstream: transport, Resolver: *target}).RoundTrip(ctx, query)
			if err != nil {
				emit(false, err.Error())
				return
			}
			json.NewEncoder(os.Stdout).Encode(map[string]any{"success": true, "response": hex.EncodeToString(answer)})
			return
		}
		conn, err = transport.DialContext(ctx, "tcp4", *target)
	} else {
		if *dns != "" {
			emit(false, "DNS fixture requires an explicit proxy")
			return
		}
		endpoint, parseErr := netip.ParseAddrPort(*address)
		if parseErr != nil || !endpoint.Addr().IsLoopback() {
			emit(false, "fixture direct probes are restricted to loopback")
			return
		}
		switch *network {
		case "tcp-mapped":
			working, _ := os.Getwd()
			if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" || endpoint.Addr().Unmap() != netip.MustParseAddr("127.0.0.1") {
				emit(false, "mapped IPv4 fixture requires fixed guest loopback")
				return
			}
			ok, err := mappedIPv4Echo(int(endpoint.Port()))
			if err != nil {
				emit(false, err.Error())
			} else {
				emit(ok, "native IPv6 dual-stack mapped IPv4 echo")
			}
			return
		case "tcp4", "tcp6", "udp4", "udp6":
		default:
			emit(false, "unsupported network")
			return
		}
		conn, err = (&net.Dialer{}).DialContext(ctx, *network, *address)
	}
	if err != nil {
		emit(false, err.Error())
		return
	}
	defer conn.Close()
	if *wait {
		json.NewEncoder(os.Stdout).Encode(map[string]bool{"ready": true})
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil || line != "continue\n" {
			emit(false, "fixture continuation was absent")
			return
		}
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	payload := make([]byte, *payloadSize)
	copy(payload, "P0")
	for i := 2; i < len(payload); i++ {
		payload[i] = byte(i % 251)
	}
	if _, err := conn.Write(payload); err != nil {
		emit(false, err.Error())
		return
	}
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, data); err != nil {
		emit(false, err.Error())
		return
	}
	emit(bytes.Equal(data, payload), "echo observation")
}

func emit(success bool, detail string) {
	json.NewEncoder(os.Stdout).Encode(map[string]any{"success": success, "detail": detail, "pids": []int{os.Getpid()}, "zeroCapabilityAppContainer": verifiedAppContainer()})
	if !success {
		os.Exit(1)
	}
}
