package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A regular HTTPS client, with no explicit application proxy. Only the
// injected transparent path can make this work in the offline guest.
func runPublicCheck() {
	working, _ := os.Getwd()
	executable, _ := os.Executable()
	if !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" || !strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-probe.exe`) {
		emit(false, "public fixture requires exact disposable guest probe")
		return
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxResponseHeaderBytes: 16384}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("public fixture refuses redirects") }}
	response, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		emit(false, err.Error())
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		emit(false, "public HTTPS response or certificate verification failed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) > 1024 {
		emit(false, "bounded public response failed")
		return
	}
	var result struct{ IP string }
	if json.Unmarshal(body, &result) != nil {
		emit(false, "invalid public IP response")
		return
	}
	ip, err := netip.ParseAddr(result.IP)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		emit(false, "response is not a public IPv4")
		return
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"success": true, "publicCheck": true, "tlsVerified": true, "observedExitIPv4": ip.String(), "zeroCapabilityAppContainer": verifiedAppContainer(), "pid": os.Getpid()})
}
