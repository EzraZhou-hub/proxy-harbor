//go:build p0system && windows

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dnsAuditProbe struct {
	Success  bool   `json:"success"`
	Scenario string `json:"scenario"`
	Name     string `json:"name"`
	PID      int    `json:"pid"`
	Entries  []struct {
		Status    uint32 `json:"status"`
		Address   string `json:"address"`
		Records   bool   `json:"records"`
		Callbacks int32  `json:"callbacks"`
		Connected bool   `json:"connected"`
	} `json:"entries"`
}

type dnsWireEvent struct {
	Name     string `json:"name"`
	Network  string `json:"network"`
	OwnerPID uint32 `json:"ownerPid"`
}

type dnsCoverageCase struct {
	ID      string          `json:"id"`
	Outcome string          `json:"outcome"`
	Probe   dnsAuditProbe   `json:"probe"`
	Wire    []dnsWireEvent  `json:"wire"`
	Checks  map[string]bool `json:"checks"`
}

type dnsIsolationResult struct {
	IsolationResult       bool   `json:"isolationResult"`
	Mode                  string `json:"mode"`
	Launched              bool   `json:"launched"`
	Error                 uint32 `json:"error"`
	ChildExitCode         uint32 `json:"childExitCode"`
	TimedOut              bool   `json:"timedOut"`
	IsAppContainer        uint32 `json:"isAppContainer"`
	IsLPAC                uint32 `json:"isLPAC"`
	CapabilityCount       uint32 `json:"capabilityCount"`
	SID                   string `json:"sid"`
	ACLRestored           bool   `json:"aclRestored"`
	RelayACLRestored      bool   `json:"relayAclRestored"`
	PackageRulesInstalled uint32 `json:"packageRulesInstalled"`
	PackagePolicyRestored bool   `json:"packagePolicyRestored"`
	ProfileDeleted        bool   `json:"profileDeleted"`
	LPACVerification      string `json:"lpacVerification"`
	PackageSIDAccess      bool   `json:"packageSidAccess"`
	AllPackagesAccess     bool   `json:"allApplicationPackagesAccess"`
	LoopbackEnabled       bool   `json:"loopbackEnabled"`
	LoopbackRestored      bool   `json:"loopbackRestored"`
	ProxyAttempted        bool   `json:"proxyAttempted"`
	ProxyChildExitCode    uint32 `json:"proxyChildExitCode"`
}

type dnsIsolationCase struct {
	Mode              string             `json:"mode"`
	Outcome           string             `json:"outcome"`
	Probe             dnsAuditProbe      `json:"probe"`
	Isolation         dnsIsolationResult `json:"isolation"`
	Wire              []dnsWireEvent     `json:"wire"`
	Checks            map[string]bool    `json:"checks"`
	ProxyUsable       bool               `json:"proxyUsable"`
	CandidateDecision string             `json:"candidateDecision"`
	ProxyDetail       string             `json:"proxyDetail,omitempty"`
}

// UDP source attribution is sampled before replying, while the requesting
// socket is still open. A failed lookup is recorded as unknown (PID 0).
func dnsUDPOwner(port int) uint32 {
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedUdpTable")
	var size uint32
	status, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 1, 0)
	if status != 122 || size < 4 || size > 1<<20 {
		return 0
	}
	data := make([]byte, size)
	status, _, _ = proc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 1, 0)
	if status != 0 {
		return 0
	}
	count := int(binary.LittleEndian.Uint32(data[:4]))
	for i := 0; i < count && 4+(i+1)*12 <= len(data); i++ {
		row := data[4+i*12 : 4+(i+1)*12]
		if int(binary.BigEndian.Uint16(row[4:6])) == port {
			return binary.LittleEndian.Uint32(row[8:12])
		}
	}
	return 0
}

func dnsServiceStatus() (uint32, uint32, string) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, 0, err.Error()
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString("Dnscache")
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, 0, err.Error()
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var size uint32
	if err := windows.QueryServiceStatusEx(service, 0, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &size); err != nil {
		return 0, 0, err.Error()
	}
	return status.ProcessId, status.CurrentState, ""
}

// Only the offline guest can bind these fixed local observers. No system DNS
// setting is changed and only the audit .invalid zone receives an answer.
func dnsCoverageObserver(t *testing.T) func(string) []dnsWireEvent {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	tcp, err := net.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	var mu sync.Mutex
	events := []dnsWireEvent{}
	response := func(query []byte, network string, owner uint32) []byte {
		end, err := dnsQuestionEnd(query)
		if err != nil {
			return nil
		}
		var labels []string
		for p := 12; p < end-4 && query[p] != 0; {
			n := int(query[p])
			labels = append(labels, string(query[p+1:p+1+n]))
			p += n + 1
		}
		name := strings.Join(labels, ".")
		if !strings.HasSuffix(name, ".p0-dns-audit.invalid") {
			return nil
		}
		mu.Lock()
		events = append(events, dnsWireEvent{Name: name, Network: network, OwnerPID: owner})
		mu.Unlock()
		answer := append([]byte(nil), query[:end]...)
		answer[2], answer[3] = 0x81, 0x80
		binary.BigEndian.PutUint16(answer[6:8], 1)
		binary.BigEndian.PutUint16(answer[8:10], 0)
		binary.BigEndian.PutUint16(answer[10:12], 0)
		return append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 77)
	}
	go func() {
		for {
			var data [4096]byte
			n, peer, err := udp.ReadFromUDP(data[:])
			if err != nil {
				return
			}
			answer := response(data[:n], "udp4", dnsUDPOwner(peer.Port))
			if answer != nil {
				udp.WriteToUDP(answer, peer)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				answer := response(query, "tcp4", 0)
				if answer != nil {
					binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
					writeAll(conn, append(size[:], answer...))
				}
			}()
		}
	}()
	return func(name string) []dnsWireEvent {
		mu.Lock()
		defer mu.Unlock()
		found := []dnsWireEvent{}
		for _, event := range events {
			if event.Name == name {
				found = append(found, event)
			}
		}
		return found
	}
}

func TestP0DNSCoverage(t *testing.T) {
	working, err := os.Getwd()
	if err != nil || !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		t.Fatal("DNS coverage is restricted to the offline disposable guest")
	}
	bin := filepath.Join(working, ".local", "p0", "bin")
	guard := filepath.Join(bin, "p0-relay-guard.exe")
	probe := filepath.Join(bin, "proxy-harbor-p0-probe.exe")
	control := filepath.Join(working, ".local", "p0", "control", "proxy-harbor-p0-probe.exe")
	candidate := filepath.Join(bin, "transparent", "proxychains_win32_x64.exe")
	if status := systemGuard(t, guard, "inspect"); status["elevated"] != true || status["rulesPresent"] != float64(0) {
		t.Fatal("DNS audit requires a clean elevated guest")
	}
	wire := dnsCoverageObserver(t)
	servicePID, serviceState, serviceError := dnsServiceStatus()
	observerChecks := map[string]bool{}
	cases := []*dnsCoverageCase{}
	isolationCases := []*dnsIsolationCase{}
	cleanup := "not_needed"
	defer func() {
		report := map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "Fixed guest fixtures and loopback DNS observer; not complete system DNS coverage", "dnsServicePid": servicePID, "dnsServiceState": serviceState, "dnsServiceStatusError": serviceError, "observerChecks": observerChecks, "cases": cases, "isolationCandidates": isolationCases, "cleanup": cleanup, "systemCacheCoverage": "not_verified", "sharedServiceCoverage": "not_accepted", "applicationProtectionVerified": false}
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(working, ".local", "p0", "dns-coverage-report.json"), data, 0600)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	// Validate both observation paths with real DNS messages independently of
	// the Windows resolver. A non-working system baseline cannot turn silence
	// at a broken observer into a passing protection result.
	for _, network := range []string{"udp4", "tcp4"} {
		name := "0000000000000001.p0-dns-audit.invalid"
		query := []byte{0x50, 0x30, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, label := range strings.Split(name, ".") {
			query = append(query, byte(len(label)))
			query = append(query, []byte(label)...)
		}
		query = append(query, 0, 0, 1, 0, 1)
		conn, err := net.DialTimeout(network, "127.0.0.1:53", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		frame := query
		if network == "tcp4" {
			frame = append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
		}
		err = writeAll(conn, frame)
		var answer []byte
		if err == nil {
			if network == "tcp4" {
				var size [2]byte
				_, err = io.ReadFull(conn, size[:])
				if err == nil {
					answer = make([]byte, int(binary.BigEndian.Uint16(size[:])))
					_, err = io.ReadFull(conn, answer)
				}
			} else {
				answer = make([]byte, 4096)
				var n int
				n, err = conn.Read(answer)
				answer = answer[:n]
			}
		}
		conn.Close()
		ok := err == nil && len(answer) > 4 && bytes.Equal(answer[len(answer)-4:], []byte{198, 51, 100, 77})
		observerChecks[network] = ok
		if !ok {
			t.Fatalf("DNS observer %s did not return its controlled answer: %v", network, err)
		}
	}
	upstream, cert, targets, stopUpstream := systemProxy(t, "http", false)
	defer stopUpstream()
	address, stopRelay, pid := systemRelayWithPID(t, filepath.Join(bin, "proxy-harbor-p0-relay.exe"), "http", upstream, cert, false)
	defer stopRelay()
	_, port, _ := net.SplitHostPort(address)
	config := "strict_chain\nproxy_dns\nremote_dns_subnet_cidr_v4 198.18.0.0/15\nuse_fake_ip_when_hostname_not_matched 1\nresolve_locally_if_match_hosts 0\nmap_resolved_ip_to_host 0\nsearch_for_host_by_resolved_ip 0\nfirst_tunnel_uses_ipv4 1\nfirst_tunnel_uses_ipv6 0\ndefault_target PROXY\ntcp_connect_time_out 1000\ntcp_read_time_out 1000\nlog_level 200\n[ProxyList]\nsocks5 127.0.0.1 " + port + "\n"
	configPath := filepath.Join(t.TempDir(), "dns-audit.conf")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(id, scenario, executable string, hooked bool) *dnsCoverageCase {
		var token [8]byte
		if _, err := rand.Read(token[:]); err != nil {
			t.Fatal(err)
		}
		host := hex.EncodeToString(token[:]) + ".p0-dns-audit.invalid"
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		args := []string{"-dns-audit", scenario, "-dns-audit-name", host}
		if hooked {
			args = append([]string{"-q", "-f", configPath, executable}, args...)
			executable = candidate
		}
		command := exec.CommandContext(ctx, executable, args...)
		command.Env = append(os.Environ(), fmt.Sprintf("P0_EXPECTED_RELAY_PID=%d", pid))
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		item := &dnsCoverageCase{ID: id, Checks: map[string]bool{}, Wire: []dnsWireEvent{}}
		cases = append(cases, item)
		for _, line := range bytes.Split(output, []byte{'\n'}) {
			var parsed dnsAuditProbe
			if json.Unmarshal(line, &parsed) == nil && parsed.Success && parsed.Name == host {
				item.Probe = parsed
			}
		}
		if err != nil || !item.Probe.Success {
			t.Fatalf("DNS audit %s failed: %v stdout=%s stderr=%s", id, err, output, stderr.Bytes())
		}
		time.Sleep(30 * time.Millisecond)
		item.Wire = wire(host)
		return item
	}
	// Baseline and deliberately unhooked target measure the shared-service gap.
	// A negative observation is not accepted as proof that shared DNS is covered.
	classifyService := func(item *dnsCoverageCase) {
		item.Outcome = "not_observed_in_fixture"
		if len(item.Wire) > 0 {
			item.Outcome = "dns_wire_observed"
			for _, event := range item.Wire {
				if event.OwnerPID != 0 && event.OwnerPID == servicePID && event.OwnerPID != uint32(item.Probe.PID) {
					item.Outcome = "shared_dns_service_wire_observed"
				}
			}
		}
	}
	classifyService(invoke("unprotected_system_api_baseline", "ex-custom-server", control, false))
	defer func() {
		removed, err := systemGuardResult(guard, "remove-fixture-only")
		if err != nil || removed["rulesPresent"] != float64(0) {
			cleanup = "failed"
			t.Error("DNS audit policy cleanup failed")
		} else {
			cleanup = "verified"
		}
	}()
	if installed := systemGuard(t, guard, "install-fixture-only", port); installed["rulesPresent"] != float64(4) {
		t.Fatal("DNS audit guard installation failed")
	}
	cleanup = "pending"
	classifyService(invoke("guard_without_hooks_service_boundary", "ex-custom-server", probe, false))
	for _, scenario := range []string{"w", "a", "utf8", "ex-sync", "ex-async", "repeat", "w-cache-only", "ex-cache-only", "w-return-message", "ex-return-message", "w-tcp-only", "a-multicast-only", "ex-unknown-option", "ex-interface", "ex-version3", "ex-aaaa", "ex-txt", "ex-https", "ex-async-cache-only", "ex-custom-server"} {
		t.Run(scenario, func(t *testing.T) {
			item := invoke("hooked_"+scenario, scenario, probe, true)
			check := func(name string, ok bool) {
				item.Checks[name] = ok
				if !ok {
					t.Errorf("DNS contract %s/%s failed: %+v", scenario, name, item)
				}
			}
			check("no_observed_loopback_dns_wire", len(item.Wire) == 0)
			positive := scenario == "w" || scenario == "a" || scenario == "utf8" || scenario == "ex-sync" || scenario == "ex-async" || scenario == "repeat"
			if positive {
				item.Outcome = "confined_mapping_and_proxy_connection"
				expected := 1
				if scenario == "repeat" {
					expected = 2
				}
				check("entry_count", len(item.Probe.Entries) == expected)
				for i, entry := range item.Probe.Entries {
					ip := net.ParseIP(entry.Address)
					prefix := ip != nil && ip.To4() != nil && ip.To4()[0] == 198 && ip.To4()[1] >= 18 && ip.To4()[1] <= 19
					check(fmt.Sprintf("entry%d_synthetic_ipv4_and_echo", i), entry.Status == 0 && entry.Records && prefix && entry.Connected)
					callbacks := int32(0)
					if scenario == "ex-async" {
						callbacks = 1
					}
					check(fmt.Sprintf("entry%d_callbacks", i), entry.Callbacks == callbacks)
					select {
					case target := <-targets:
						check(fmt.Sprintf("entry%d_original_domain_preserved", i), target == item.Probe.Name+":443")
					case <-time.After(time.Second):
						check("missing_upstream_target", false)
					}
				}
			} else {
				item.Outcome = "rejected_unsupported"
				expected := uint32(50)
				if scenario == "ex-version3" {
					expected = 87
				}
				check("one_rejection", len(item.Probe.Entries) == 1)
				for _, entry := range item.Probe.Entries {
					check("explicit_status_without_records_or_callback", entry.Status == expected && !entry.Records && !entry.Connected && entry.Callbacks == 0)
				}
				select {
				case <-targets:
					check("no_upstream_target", false)
				case <-time.After(30 * time.Millisecond):
					check("no_upstream_target", true)
				}
			}
		})
	}
	for _, mode := range []string{"appcontainer", "lpac", "appcontainer-loopback", "lpac-loopback"} {
		t.Run("isolation_"+mode, func(t *testing.T) {
			var token [8]byte
			if _, err := rand.Read(token[:]); err != nil {
				t.Fatal(err)
			}
			label := hex.EncodeToString(token[:])
			host := label + ".p0-dns-audit.invalid"
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			baseMode := strings.TrimSuffix(mode, "-loopback")
			loopback := baseMode != mode
			args := []string{baseMode, label}
			if loopback {
				args = append(args, port)
			}
			command := exec.CommandContext(ctx, filepath.Join(bin, "p0-dns-isolation.exe"), args...)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			output, err := command.Output()
			item := &dnsIsolationCase{Mode: mode, Outcome: "not_verified", CandidateDecision: "not_evaluated_without_proxy", Checks: map[string]bool{}, Wire: []dnsWireEvent{}}
			isolationCases = append(isolationCases, item)
			for _, line := range bytes.Split(output, []byte{'\n'}) {
				var probe dnsAuditProbe
				if json.Unmarshal(line, &probe) == nil && probe.Success && probe.Name == host {
					item.Probe = probe
				}
				var native dnsIsolationResult
				if json.Unmarshal(line, &native) == nil && native.IsolationResult {
					item.Isolation = native
				}
				var echo struct {
					Success bool
					Detail  string
				}
				if json.Unmarshal(line, &echo) == nil && echo.Success && echo.Detail == "echo observation" {
					item.ProxyUsable = true
				}
				if echo.Detail != "" {
					item.ProxyDetail = echo.Detail
				}
			}
			check := func(name string, ok bool) {
				item.Checks[name] = ok
				if !ok {
					t.Errorf("Isolation %s/%s failed: err=%v stdout=%s stderr=%s", mode, name, err, output, stderr.Bytes())
				}
			}
			check("fixture_completed", err == nil && item.Probe.Success && item.Isolation.Launched && item.Isolation.Error == 0 && item.Isolation.ChildExitCode == 0 && !item.Isolation.TimedOut)
			check("appcontainer_token_verified", item.Isolation.IsAppContainer == 1)
			expectedLPAC := uint32(0)
			if baseMode == "lpac" {
				expectedLPAC = 1
			}
			check("lpac_access_semantics_match_request", item.Isolation.IsLPAC == expectedLPAC)
			check("access_semantics_verified", item.Isolation.LPACVerification == "access_check_pair" && item.Isolation.PackageSIDAccess && item.Isolation.AllPackagesAccess == (expectedLPAC == 0))
			check("no_capabilities", item.Isolation.CapabilityCount == 0)
			check("acl_restored", item.Isolation.ACLRestored)
			check("profile_deleted", item.Isolation.ProfileDeleted)
			check("loopback_scope_and_cleanup", item.Isolation.LoopbackEnabled == loopback && item.Isolation.LoopbackRestored)
			if loopback && baseMode == "appcontainer" {
				check("proxy_probe_completed", item.Isolation.ProxyAttempted && item.Isolation.ProxyChildExitCode == 0 && item.ProxyUsable)
				select {
				case target := <-targets:
					check("proxy_original_domain_preserved", target == host+":443")
				case <-time.After(time.Second):
					check("proxy_original_domain_preserved", false)
				}
			} else if loopback {
				// Zero-capability LPAC was evaluated and rejected: Winsock cannot
				// initialize. Preserve that negative control rather than accepting
				// its DNS error as evidence of usable protection.
				item.CandidateDecision = "rejected_transport_unavailable"
				check("rejected_candidate_transport_failure_preserved", item.Isolation.ProxyAttempted && item.Isolation.ProxyChildExitCode != 0 && !item.ProxyUsable)
				select {
				case <-targets:
					check("rejected_candidate_no_upstream_target", false)
				case <-time.After(30 * time.Millisecond):
					check("rejected_candidate_no_upstream_target", true)
				}
			}
			time.Sleep(30 * time.Millisecond)
			item.Wire = wire(host)
			if item.Probe.Success && item.Isolation.Error == 0 && item.Isolation.ChildExitCode == 0 && len(item.Probe.Entries) == 1 {
				if len(item.Wire) > 0 {
					item.Outcome = "dns_wire_bypass_observed"
				} else if item.Probe.Entries[0].Status == 5 && !item.Probe.Entries[0].Records {
					item.Outcome = "dns_access_denied_in_isolated_fixture"
				} else if item.Probe.Entries[0].Status != 0 && !item.Probe.Entries[0].Records {
					item.Outcome = "dns_api_error_no_observed_wire"
				}
			}
			if loopback && baseMode == "appcontainer" {
				check("known_service_query_denied_with_working_proxy", item.Outcome == "dns_access_denied_in_isolated_fixture" && item.ProxyUsable)
				item.CandidateDecision = "bounded_fixture_passed_not_application_accepted"
			}
		})
	}
	classifyService(invoke("unprotected_observer_still_works_after_guard", "ex-custom-server", control, false))
}
