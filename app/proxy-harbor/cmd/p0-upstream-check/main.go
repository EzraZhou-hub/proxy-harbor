// p0-upstream-check checks the existing local client through the project's
// transport. It installs no policy, launches no applications and has no direct
// target connection or system-proxy fallback.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"time"
)

const checkURL = "https://api.ipify.org?format=json"

type report struct {
	CheckedAtUTC          string `json:"checkedAtUtc"`
	Protocol              string `json:"protocol"`
	Entrance              string `json:"entrance"`
	Target                string `json:"target"`
	Passed                bool   `json:"passed"`
	TargetTLSVerified     bool   `json:"targetTLSVerified"`
	ObservedExitIPv4      string `json:"observedExitIPv4,omitempty"`
	ApplicationProtection bool   `json:"applicationProtectionVerified"`
	FailureStage          string `json:"failureStage,omitempty"`
	Error                 string `json:"error,omitempty"`
}

func check(ctx context.Context, protocol, entrance string) (result report) {
	result = report{CheckedAtUTC: time.Now().UTC().Format(time.RFC3339), Protocol: protocol, Entrance: entrance, Target: checkURL}
	fail := func(stage string, err error) report {
		var upstreamError *engine.StageError
		if errors.As(err, &upstreamError) {
			stage = upstreamError.Stage
		}
		result.FailureStage, result.Error = stage, err.Error()
		return result
	}
	address, err := netip.ParseAddrPort(entrance)
	if err != nil || address.Addr() != netip.MustParseAddr("127.0.0.1") || address.Port() == 0 || (protocol != "http" && protocol != "socks5") {
		return fail("configuration", errors.New("requires an explicit 127.0.0.1:port HTTP or SOCKS5 local client"))
	}
	upstream := engine.Upstream{
		Profile: domain.ProxyProfile{Name: "P0 local client check", Protocol: protocol, Host: address.Addr().String(), Port: int(address.Port())},
		Timeout: 8 * time.Second,
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "api.ipify.org:443" {
				return nil, errors.New("unexpected destination; connection refused")
			}
			return upstream.DialContext(ctx, "tcp4", address)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    8 * time.Second,
		ResponseHeaderTimeout:  8 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 * 1024,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return fail("request", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fail("request_or_target_tls", err)
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return fail("target_tls", errors.New("target certificate was not verified"))
	}
	result.TargetTLSVerified = true
	if response.StatusCode != http.StatusOK {
		return fail("http", fmt.Errorf("unexpected HTTP status: %d", response.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil {
		return fail("response", err)
	}
	if len(body) > 1024 {
		return fail("response", errors.New("response exceeds 1024 bytes"))
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fail("response", errors.New("invalid IP response JSON"))
	}
	exit, err := netip.ParseAddr(payload.IP)
	if err != nil || !exit.Is4() || !exit.IsGlobalUnicast() || exit.IsPrivate() {
		return fail("response", errors.New("response did not contain a public IPv4"))
	}
	result.Passed, result.ObservedExitIPv4 = true, exit.String()
	return result
}

func main() {
	protocol := flag.String("protocol", "http", "local client protocol: http or socks5")
	entrance := flag.String("upstream", "", "explicit local client 127.0.0.1:port")
	flag.Parse()
	result := check(context.Background(), *protocol, *entrance)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
	if !result.Passed {
		os.Exit(1)
	}
}
