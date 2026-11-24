package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"proxyharbor/internal/domain"
	"testing"
	"time"
)

func TestRejectProtectedAndUnrelatedExecutables(t *testing.T) {
	folder := t.TempDir()
	exe := filepath.Join(folder, "chrome.exe")
	os.WriteFile(exe, []byte("placeholder, never executed"), 0600)
	if _, err := CollectImages("unknown", exe); err == nil {
		t.Fatal("Unknown application must be rejected")
	}
	if _, err := CollectImages("codex", exe); err == nil {
		t.Fatal("Wrong application image accepted")
	}
	// CollectImages is metadata only; these placeholders must never execute.
	os.WriteFile(filepath.Join(folder, "helper.exe"), []byte("placeholder"), 0600)
	images, err := CollectImages("chrome", exe)
	if err != nil || len(images) != 2 || images[0] != exe {
		t.Fatalf("Components: %v %v", images, err)
	}
}
func TestInvalidOrStaleSessionNeverReportsMonitoring(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"state":"monitoring","guardianPid":4294967295,"updatedAt":"2000-01-01T00:00:00Z"}`), 0600)
	r := &Runtime{current: dir, helper: "absent"}
	if r.Status().State != "cleanup_required" {
		t.Fatal("Stale status accepted")
	}
	os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{`), 0600)
	if r.Status().State != "cleanup_required" {
		t.Fatal("Corrupt status accepted")
	}
}
func TestUnverifiedHelperCannotCreateSession(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "unverified.exe")
	os.WriteFile(helper, []byte("unverified placeholder; never executed"), 0600)
	r := &Runtime{root: filepath.Join(dir, "sessions"), helper: helper}
	_, err := r.Start("chrome", filepath.Join(dir, "chrome.exe"), ProxyEndpoint{})
	if err == nil || r.Status().Available {
		t.Fatal("Unverified binary reached launch")
	}
	if _, err := os.Stat(r.root); !os.IsNotExist(err) {
		t.Fatal("Unverified helper created session records")
	}
}

func TestQuarantineOverridesMatchingFingerprintAndAcceptance(t *testing.T) {
	const fixture = `{"accepted":true,"quarantined":true,"guardianSha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`
	if accepted, hash := parseAdmission([]byte(fixture)); accepted || hash != "" {
		t.Fatal("Quarantined fingerprint became eligible for launch")
	}
}
func TestReusedPIDCannotReportMonitoring(t *testing.T) {
	created, err := currentCreation()
	if err != nil {
		t.Skip("Windows process identity check")
	}
	dir := t.TempDir()
	state := domain.ManagedSession{State: "monitoring", GuardianPID: uint32(os.Getpid()), GuardianCreated: created + 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	data, _ := json.Marshal(state)
	os.WriteFile(filepath.Join(dir, "status.json"), data, 0600)
	r := &Runtime{current: dir, helper: "absent"}
	if r.Status().State != "cleanup_required" {
		t.Fatal("Different process creation time accepted")
	}
}

func TestTerminalSessionCannotHidePendingRecovery(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "sessions")
	old := filepath.Join(root, "11111111-1111-1111-1111-111111111111")
	newer := filepath.Join(root, "22222222-2222-2222-2222-222222222222")
	for _, dir := range []string{old, newer} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"state":"stopped","filterCount":0}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(old, "identity.txt"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if state := New(base).Status(); state.Directory != old || state.State != "cleanup_required" {
		t.Fatalf("Recovery hidden: %+v", state)
	}
}
func TestInvalidStatusIsActionable(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{`{}`, `{"state":"idle"}`, `{"state":"unrecognized"}`, `{"state":"preparing","updatedAt":"2099-01-01T00:00:00Z"}`, `{"state":"stopped","filterCount":1}`} {
		if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if got := readSessionState(dir); got.State != "cleanup_required" {
			t.Errorf("%s accepted: %+v", body, got)
		}
	}
}

func TestTakeoverRecoveryRecordKeepsSessionActionable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"state":"stopped","filterCount":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "takeover.bin"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readSessionState(dir); got.State != "cleanup_required" || got.Reason != "incomplete_session" {
		t.Fatalf("Pending takeover cleanup hidden: %+v", got)
	}
}
func TestProxyExitMustBeIndependentPublicIPv4(t *testing.T) {
	for _, ip := range []string{"", "127.0.0.1", "10.0.0.1", "192.0.2.8", "203.0.113.1", "100.64.0.1", "198.19.0.1", "240.0.0.1", "224.0.0.1", "::ffff:1.1.1.1", "1.1.1.1\n", "01.1.1.1"} {
		if validExit(ip) {
			t.Errorf("Accepted %q", ip)
		}
	}
	if !validExit("131.103.130.202") {
		t.Fatal("Expected a valid IP")
	}
}

func TestRefreshSeesSessionsCreatedAfterStartup(t *testing.T) {
	base := t.TempDir()
	r := New(base)
	if state := r.Status(); state.State != "idle" || state.Directory != "" {
		t.Fatalf("Unexpected initial state: %+v", state)
	}
	dir := filepath.Join(base, "sessions", "33333333-3333-3333-3333-333333333333")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"state":"stopped","reason":"user_stopped","filterCount":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	// A resident caller must observe sessions started by the desktop bindings
	// after it was constructed, without restarting the process.
	if state := r.Refresh(); state.Directory != dir || state.State != "stopped" {
		t.Fatalf("Refresh missed the new session: %+v", state)
	}
}
