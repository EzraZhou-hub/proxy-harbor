//go:build p0system && windows

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type portRebootJournal struct {
	Owner      string `json:"owner"`
	Port       int    `json:"port"`
	ToolSHA256 string `json:"toolSHA256"`
}

func TestP0BatchRecoveryPreparation(t *testing.T) {
	recoveryGuest(t)
	guard := `C:\P0Lab\.local\p0\bin\p0-port-guard.exe`
	if r := systemGuard(t, guard, "inspect"); r["rulesPresent"] != float64(0) {
		t.Fatal("Clean reservation policy required")
	}
	data, err := os.ReadFile(guard)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	journal, _ := json.Marshal(portRebootJournal{"proxy-harbor-p0-batch", 48731, hex.EncodeToString(hash[:])})
	if err := os.WriteFile(`C:\P0Lab\.local\p0\port-reboot-session.json`, journal, 0600); err != nil {
		t.Fatal(err)
	}
	TestP0RecoveryPreparation(t)
	if r := systemGuard(t, guard, "reserve-fixture-only", "48731"); r["rulesPresent"] != float64(4) {
		t.Fatal("Reservation preparation failed")
	}
	// Deliberately retained until the separately authorized guest restart.
}

func TestP0BatchRecoveryAfterBoot(t *testing.T) {
	recoveryGuest(t)
	guard := `C:\P0Lab\.local\p0\bin\p0-port-guard.exe`
	var journal portRebootJournal
	data, err := os.ReadFile(`C:\P0Lab\.local\p0\port-reboot-session.json`)
	if err != nil || json.Unmarshal(data, &journal) != nil || journal.Owner != "proxy-harbor-p0-batch" || journal.Port != 48731 {
		t.Fatal("Invalid reservation recovery journal")
	}
	binary, err := os.ReadFile(guard)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	if hex.EncodeToString(hash[:]) != journal.ToolSHA256 {
		t.Fatal("Recovery tool changed; refusing policy cleanup")
	}
	checks := map[string]bool{}
	cleanup := "pending"
	defer func() {
		encoded, _ := json.MarshalIndent(map[string]any{"schemaVersion": 1, "overall": "not_accepted", "scope": "12 persistent fixture rules after guest restart; startup task runs after Windows services, not earliest boot proof", "checks": checks, "cleanup": cleanup}, "", "  ")
		os.WriteFile(`C:\P0Lab\.local\p0\batch-reboot-policy-report.json`, encoded, 0600)
	}()
	check := func(id string, ok bool) {
		t.Helper()
		checks[id] = ok
		if !ok {
			t.Fatal(id)
		}
	}
	check("four_reservation_rules_survived", systemGuard(t, guard, "inspect")["rulesPresent"] == float64(4))
	check("no_relay_proof_key_implicitly_restored", os.Getenv("P0_RELAY_PROOF_KEY") == "")
	// This validates the earlier 8 application rules, corrupt-journal refusal,
	// explicit release and restored connectivity with this batch's binaries.
	TestP0RecoveryAfterBoot(t)
	port := strconv.Itoa(journal.Port)
	bind := func(network string) error {
		host := "127.0.0.1"
		if strings.HasSuffix(network, "6") {
			host = "::1"
		}
		address := net.JoinHostPort(host, port)
		if strings.HasPrefix(network, "udp") {
			p, e := net.ListenPacket(network, address)
			if p != nil {
				p.Close()
			}
			return e
		}
		l, e := net.Listen(network, address)
		if l != nil {
			l.Close()
		}
		return e
	}
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		check("replacement_after_boot_denied_"+network, errors.Is(bind(network), syscall.Errno(10013)))
	}
	upstream, cert, _, stop := systemProxy(t, "http", false)
	defer stop()
	address, stopRelay, _ := systemRelayWithPID(t, `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-relay.exe`, "http", upstream, cert, false, "-listen-port", port)
	check("trusted_relay_recovers_reserved_port_after_boot", systemProbe(t, `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-probe.exe`, "-proxy-protocol", "socks5", "-proxy", address))
	stopRelay()
	check("explicit_reservation_release", systemGuard(t, guard, "remove-fixture-only")["rulesPresent"] == float64(0))
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		check("reservation_binding_restored_"+network, bind(network) == nil)
	}
	check("recovery_guard_path_is_fixture", strings.EqualFold(filepath.Clean(guard), `C:\P0Lab\.local\p0\bin\p0-port-guard.exe`))
	cleanup = "verified"
}
