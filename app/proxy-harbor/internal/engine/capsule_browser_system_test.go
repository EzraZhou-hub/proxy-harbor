//go:build p0system && windows

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestP0CapsuleBrowser(t *testing.T) {
	testP0CapsuleBrowser(t, false)
}
func copyCapsuleChrome(t *testing.T) {
	t.Helper()
	source := `C:\P0Lab\chrome`
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("Reparse source refused")
		}
		rel, _ := filepath.Rel(source, path)
		target := filepath.Join(capsuleAppDir, "chrome", rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		r, e := os.Open(path)
		if e != nil {
			return e
		}
		w, e := os.Create(target)
		if e != nil {
			r.Close()
			return e
		}
		_, e = io.Copy(w, r)
		r.Close()
		closeErr := w.Close()
		if e != nil {
			return e
		}
		return closeErr
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestP0UserCapsuleBrowser(t *testing.T) {
	testP0CapsuleBrowser(t, true)
}
func testP0CapsuleBrowser(t *testing.T, user bool) {
	prepareCapsuleFixtures(t)
	root := `C:\P0Lab\.local\p0`
	bin := filepath.Join(root, "bin")
	runner := filepath.Join(bin, "p0-capsule.exe")
	rules, reportName := float64(6), "capsule-browser-report.json"
	if user {
		runner = filepath.Join(bin, "p0-user-capsule.exe")
		rules = 8
		reportName = "user-capsule-browser-report.json"
	}
	checks := map[string]bool{}
	report := map[string]any{"schemaVersion": 1, "scope": "Actual Chrome in zero-capability AppContainer; SID policy; no debug loopback exception or Chromium certificate bypass", "checks": checks, "cleanup": "pending"}
	if user {
		report["scope"] = "Actual Chrome under a dedicated ordinary user with inherited WFP rules; browser sandbox and certificate validation enabled"
	}
	defer func() {
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, reportName), data, 0600)
	}()
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("Capsule browser: %s", name)
		}
	}
	source := `C:\P0Lab\chrome`
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("Reparse source refused")
		}
		rel, _ := filepath.Rel(source, path)
		target := filepath.Join(capsuleAppDir, "chrome", rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		r, e := os.Open(path)
		if e != nil {
			return e
		}
		defer r.Close()
		w, e := os.Create(target)
		if e != nil {
			return e
		}
		_, e = io.Copy(w, r)
		closeErr := w.Close()
		if e != nil {
			return e
		}
		return closeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Round    string `json:"publicBridgeRound"`
		Enabled  bool   `json:"chromeSessionChecks"`
		Expected string `json:"expectedProxyIPv4"`
	}
	data, _ := os.ReadFile(`C:\P0Lab\manifest.json`)
	if json.Unmarshal(data, &manifest) != nil || !manifest.Enabled {
		t.Fatal("Explicit browser public package required")
	}
	log, _ := os.Create(filepath.Join(root, "capsule-bridge.jsonl"))
	defer log.Close()
	bridge := exec.Command(`C:\P0Lab\node.exe`, `scripts\p0\codex-file-bridge.mjs`, "guest", `C:\P0Results\proxy-bridge-`+manifest.Round, "900000")
	bridge.Stdout = log
	bridge.Stderr = log
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { bridge.Process.Kill(); bridge.Wait() }()
	upstream := ""
	for i := 0; i < 150; i++ {
		out, _ := os.ReadFile(log.Name())
		var row struct{ Address string }
		if json.Unmarshal(bytes.SplitN(out, []byte{'\n'}, 2)[0], &row) == nil && row.Address != "" {
			upstream = row.Address
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if upstream == "" {
		t.Fatal("Bridge readiness failed")
	}
	relay, stop := systemRelay(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream, "", false)
	defer stop()
	_, port, _ := strings.Cut(relay, ":")
	guard := filepath.Join(bin, "p0-port-guard.exe")
	check("port_reserved", systemGuard(t, guard, "reserve-fixture-only", port)["rulesPresent"] == float64(4))
	defer systemGuard(t, guard, "remove-fixture-only")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	proxyURL, _ := url.Parse("socks5://" + relay)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	expected := manifest.Expected
	if expected != "" {
		report["baselineSource"] = "explicit manifest reference, separately verified through host's existing proxy; browser must still perform actual TLS request"
	} else {
		request, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org/", nil)
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		expected = strings.TrimSpace(string(body))
		if response.StatusCode != 200 {
			t.Fatal("Proxy baseline status invalid")
		}
	}
	if net.ParseIP(expected) == nil {
		t.Fatal("Proxy exit reference invalid")
	}
	report["expectedProxyExit"] = expected
	for phase := 0; phase < 2; phase++ {
		label := fmt.Sprintf("%016x", time.Now().UnixNano())
		if phase == 1 {
			stop()
		}
		command := exec.Command(runner, "chrome", label, port, "P0")
		out, e := command.CombinedOutput()
		report[fmt.Sprintf("phase%dOutput", phase)] = string(out)
		var ready, result map[string]any
		for _, line := range bytes.Split(out, []byte{'\n'}) {
			row := map[string]any{}
			if json.Unmarshal(line, &row) == nil {
				if row["capsuleReady"] == true {
					ready = row
				}
				if row["capsuleResult"] == true {
					result = row
				}
			}
		}
		prefix := fmt.Sprintf("phase%d_", phase)
		check(prefix+"native_completed", e == nil && result["error"] == float64(0))
		check(prefix+"container_armed_without_debug_exception", ready["capsuleReady"] == true && ready["debugLoopback"] == false && ready["rules"] == rules)
		check(prefix+"job_and_identity_clean", result["jobEmpty"] == true && result["profileDeleted"] == true && result["policyRestored"] == true)
		if phase == 0 {
			check(prefix+"real_https_exit_matches", strings.Contains(string(out), expected) && result["exitCode"] == float64(0))
		} else {
			check(prefix+"no_exit_when_forwarder_dead", !strings.Contains(string(out), expected))
			check(prefix+"proxy_error_reported", strings.Contains(string(out), "ERR_PROXY_CONNECTION_FAILED") || strings.Contains(string(out), "ERR_SOCKS_CONNECTION_FAILED") || strings.Contains(string(out), "ERR_CONNECTION_REFUSED"))
		}
		inspector := filepath.Join(bin, "p0-isolation-inspect.exe")
		if user {
			inspector = runner
		}
		inv, err := systemGuardResult(inspector, "inspect")
		check(prefix+"independent_rules_zero", err == nil && inv["rulesPresent"] == float64(0))
	}
	report["cleanup"] = "verified"
	for key, value := range checks {
		if strings.Contains(key, "clean") || strings.Contains(key, "rules_zero") {
			if !value {
				report["cleanup"] = "failed"
			}
		}
	}
}
