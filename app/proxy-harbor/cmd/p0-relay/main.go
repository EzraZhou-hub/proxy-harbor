// p0-relay is a loopback laboratory transport, never an installed-app launcher.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"strings"
	"time"
)

func main() {
	protocol := flag.String("protocol", "http", "http, https or socks5 upstream")
	entrance := flag.String("upstream", "", "explicit loopback IPv4 laboratory proxy")
	host := flag.String("tls-name", "proxy.proxy-harbor.invalid", "fixture TLS server name")
	certificatePath := flag.String("fixture-ca", "", "temporary fixture certificate, not installed in Windows")
	lease := flag.Duration("lease", engine.MaxTransportLease, "explicit P0 transport permission, at most 5m; never automatically renewed")
	listenPort := flag.Int("listen-port", 0, "guest-only fixed relay port recovery fixture; default ephemeral")
	flag.Parse()
	var proofKey []byte
	if value := os.Getenv("P0_RELAY_PROOF_KEY"); value != "" {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			fail("Invalid temporary relay proof key")
		}
		proofKey = decoded
	}
	if *listenPort != 0 {
		working, _ := os.Getwd()
		executable, _ := os.Executable()
		if *listenPort < 1024 || *listenPort > 65535 || !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" || !strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-relay.exe`) {
			fail("Fixed relay port recovery requires the exact disposable guest fixture")
		}
	}
	if *lease <= 0 || *lease > engine.MaxTransportLease {
		fail("P0 transport lease must be positive and at most 5m")
	}
	ip, err := netip.ParseAddrPort(*entrance)
	if err != nil || ip.Addr() != netip.MustParseAddr("127.0.0.1") || ip.Port() == 0 {
		fail("P0 relay requires an explicit 127.0.0.1 fixture upstream")
	}
	upstream := engine.Upstream{Profile: domain.ProxyProfile{Name: "P0 relay upstream", Protocol: *protocol, Host: ip.Addr().String(), Port: int(ip.Port())}, Username: os.Getenv("P0_PROXY_USER"), Password: os.Getenv("P0_PROXY_PASSWORD")}
	if *protocol == "https" {
		upstream.Profile.Host = *host
		upstream.BootstrapIPv4 = ip.Addr()
		pem, err := os.ReadFile(*certificatePath)
		if err != nil {
			fail("Cannot read the temporary fixture certificate")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			fail("Invalid fixture certificate")
		}
		upstream.TLS = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	if err := domain.ValidateProfile(upstream.Profile); err != nil {
		fail("Invalid fixture upstream profile")
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *listenPort))
	if err != nil {
		fail("Cannot bind the P0 relay listener")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	gate := engine.NewTransportGate(upstream, 64)
	defer gate.Close()
	if err := gate.Open(ctx, *lease); err != nil {
		listener.Close()
		fail("Cannot open the P0 transport lease")
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String(), "transportExpiresAt": gate.Status().ExpiresAt.UTC().Format(time.RFC3339Nano)})
	if err := (engine.Relay{Upstream: gate, PeerProofKey: proofKey}).Serve(ctx, listener); err != nil {
		fail("P0 relay listener stopped unexpectedly")
	}
}

func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
