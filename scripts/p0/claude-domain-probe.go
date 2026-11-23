//go:build windows

// Disposable guest probe for catalog HTTPS access under the Claude session policy.
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
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const proxy = "127.0.0.1:10808"

var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$`)

type entry struct {
	Domain       string      `json:"domain"`
	Group        string      `json:"group"`
	TCPPeer      string      `json:"tcpPeer,omitempty"`
	LocalPort    int         `json:"localPort,omitempty"`
	ConnectCode  int         `json:"connectCode,omitempty"`
	TLSVerified  bool        `json:"tlsVerified"`
	LocalDNS     bool        `json:"localDNS"`
	HTTPStatus   int         `json:"httpStatus,omitempty"`
	RedirectHost string      `json:"redirectHost,omitempty"`
	TargetSawIP  bool        `json:"targetSawIP,omitempty"`
	ExitMatched  bool        `json:"exitMatched,omitempty"`
	Error        string      `json:"error,omitempty"`
	PublicDNS    []dnsResult `json:"publicDNS,omitempty"`
}

type dnsResult struct {
	Type    string `json:"type"`
	RCode   *int   `json:"rcode,omitempty"`
	Answers int    `json:"addresses"`
	Error   string `json:"error,omitempty"`
}

func proxyConnection(ctx context.Context, address string) (net.Conn, error) {
	if address != proxy {
		return nil, errors.New("socket destination outside the fixed proxy")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp4", address)
}

// The public resolver is a separate diagnosis for names that could not
// complete HTTPS. It receives only the public hostname over the same proxy.
func publicDNS(domain, kind string, code int) dnsResult {
	result := dnsResult{Type: kind}
	target := url.URL{Scheme: "https", Host: "dns.google", Path: "/resolve",
		RawQuery: url.Values{"name": {domain}, "type": {kind}}.Encode()}
	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxy}),
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return proxyConnection(ctx, address)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 32 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(target.String())
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		result.Error = fmt.Sprintf("resolver HTTP status %d or unverified TLS", response.StatusCode)
		return result
	}
	var answer struct {
		Status *int
		Answer []struct{ Type int }
	}
	if json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&answer) != nil || answer.Status == nil {
		result.Error = "invalid DNS response"
		return result
	}
	result.RCode = answer.Status
	for _, record := range answer.Answer {
		if record.Type == code {
			result.Answers++
		}
	}
	return result
}

func probe(row entry, method string, traceIP bool, expectedIP string) entry {
	var mu sync.Mutex
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			mu.Lock()
			defer mu.Unlock()
			row.LocalDNS = true
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			row.TLSVerified = err == nil && len(state.VerifiedChains) > 0
		},
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxy}),
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			conn, err := proxyConnection(ctx, address)
			if err == nil {
				mu.Lock()
				row.TCPPeer = conn.RemoteAddr().String()
				row.LocalPort = conn.LocalAddr().(*net.TCPAddr).Port
				mu.Unlock()
			}
			return conn, err
		},
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, response *http.Response) error {
			mu.Lock()
			defer mu.Unlock()
			row.ConnectCode = response.StatusCode
			return nil
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 * 1024,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 42 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	path := "/"
	if traceIP {
		method, path = http.MethodGet, "/cdn-cgi/trace"
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), method, "https://"+row.Domain+path, nil)
	if err == nil {
		req.Header.Set("User-Agent", "ProxyHarbor sandbox HTTPS validation")
		if method == http.MethodGet && !traceIP {
			req.Header.Set("Range", "bytes=0-255")
		}
		var response *http.Response
		response, err = client.Do(req)
		if err == nil {
			mu.Lock()
			row.HTTPStatus = response.StatusCode
			if redirect, redirectErr := response.Location(); redirectErr == nil && response.StatusCode >= 300 && response.StatusCode < 400 {
				row.RedirectHost = redirect.Scheme + "://" + redirect.Hostname()
			}
			mu.Unlock()
			if traceIP && response.StatusCode == 200 && response.Header.Get("Cf-Ray") != "" {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
				if readErr == nil && len(body) <= 4096 {
					var host, address string
					for _, line := range strings.Split(string(body), "\n") {
						field, value, _ := strings.Cut(strings.TrimSpace(line), "=")
						switch field {
						case "h":
							host = value
						case "ip":
							address = value
						}
					}
					mu.Lock()
					row.TargetSawIP = row.TLSVerified && host == row.Domain && net.ParseIP(address) != nil
					row.ExitMatched = row.TargetSawIP && net.ParseIP(address).Equal(net.ParseIP(expectedIP))
					mu.Unlock()
				}
			}
			response.Body.Close()
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		row.Error = err.Error()
	}
	return row
}

func run() error {
	const root = `C:\P0Lab`
	image, _ := os.Executable()
	profile, _ := os.Getwd()
	accountPattern := regexp.MustCompile(`(?i)^c:\\users\\ph_[0-9a-f]{16}(\.[a-z0-9.-]+)?$`)
	if !strings.EqualFold(image, filepath.Join(root, "domain-probe.exe")) || !accountPattern.MatchString(profile) ||
		os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		return errors.New("managed domain probe requires the disposable guest and temporary session account")
	}
	flag.String("user-data-dir", "", "guardian profile flag")
	proxyFlag := flag.String("proxy-server", "", "guardian explicit proxy flag")
	flag.String("proxy-bypass-list", "", "guardian bypass flag")
	flag.Parse()
	if *proxyFlag != "http://"+proxy {
		return errors.New("unexpected guardian proxy")
	}
	var catalog struct {
		Groups []struct {
			Name    string
			Domains []string
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "claude-code-domains.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return err
	}
	var rows []entry
	seen := make(map[string]bool)
	for _, group := range catalog.Groups {
		for _, domain := range group.Domains {
			if len(domain) > 253 || !domainPattern.MatchString(domain) || seen[domain] {
				return fmt.Errorf("invalid or repeated catalog domain %q", domain)
			}
			seen[domain] = true
			rows = append(rows, entry{Domain: domain, Group: group.Name})
		}
	}
	if len(rows) == 0 || len(rows) > 40 {
		return errors.New("unexpected catalog size")
	}
	var manifest struct {
		ExpectedProxyIPv4 string `json:"expectedProxyIPv4"`
		SelectedDomains   []string
	}
	data, err = os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return err
	}
	if json.Unmarshal([]byte(strings.TrimPrefix(string(data), "\uFEFF")), &manifest) != nil || net.ParseIP(manifest.ExpectedProxyIPv4).To4() == nil {
		return errors.New("invalid fixed IPv4 in guest manifest")
	}
	method := http.MethodHead
	if len(manifest.SelectedDomains) > 0 {
		selected := make(map[string]bool)
		for _, name := range manifest.SelectedDomains {
			if !seen[name] || selected[name] {
				return errors.New("retry targets outside the catalog or repeated")
			}
			selected[name] = true
		}
		filtered := make([]entry, 0, len(selected))
		for _, row := range rows {
			if selected[row.Domain] {
				filtered = append(filtered, row)
			}
		}
		rows, method = filtered, http.MethodGet
	}
	var workers sync.WaitGroup
	j := make(chan int)
	for range 4 {
		workers.Go(func() {
			for i := range j {
				rows[i] = probe(rows[i], method, false, "")
				if method == http.MethodGet && !rows[i].TLSVerified {
					rows[i].PublicDNS = []dnsResult{publicDNS(rows[i].Domain, "A", 1), publicDNS(rows[i].Domain, "AAAA", 28)}
				}
				result, err := json.Marshal(rows[i])
				if err == nil {
					os.WriteFile(filepath.Join(profile, fmt.Sprintf("domain-%02d.json", i)), result, 0600)
				}
			}
		})
	}
	for i := range rows {
		j <- i
	}
	close(j)
	workers.Wait()
	if method == http.MethodHead {
		for _, domain := range []string{"claude.ai", "claude.com", "anthropic.com"} {
			if !seen[domain] {
				continue
			}
			workers.Go(func() {
				row := probe(entry{Domain: domain}, http.MethodGet, true, manifest.ExpectedProxyIPv4)
				if data, err := json.Marshal(row); err == nil {
					os.WriteFile(filepath.Join(profile, "trace-"+domain+".json"), data, 0600)
				}
			})
		}
		workers.Wait()
	}
	if err := os.WriteFile(filepath.Join(profile, "domains-ready"), []byte("ready\n"), 0600); err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(root, "direct-negative")); err == nil {
			conn, err := net.DialTimeout("tcp4", "127.0.0.1:18085", 3*time.Second)
			if conn != nil {
				conn.Close()
			}
			// Remain alive for the guardian's blocked-event supervision.
			status := fmt.Sprintf("connected=%t error=%v\n", conn != nil, err)
			os.WriteFile(filepath.Join(profile, "direct-result.txt"), []byte(status), 0600)
			time.Sleep(15 * time.Second)
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("missing explicit guest direct-connect control")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
