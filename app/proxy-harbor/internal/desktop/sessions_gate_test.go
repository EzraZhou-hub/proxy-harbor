package desktop

import (
	"proxyharbor/internal/session"
	"testing"
)

func TestRetiredChromeLaunchIsRejected(t *testing.T) {
	service := &DesktopService{managed: session.New(t.TempDir())}
	if service.ManagedStatus().Available {
		t.Fatal("Missing or unverified helper unexpectedly enabled")
	}
	// No client or executable is supplied: rejection must precede application
	// lookup, process launch and any system-policy mutation.
	_, err := service.StartManagedApplication("chrome")
	expected := desktopSessionRequired
	if nativeSessionsAllowed() {
		expected = "当前版本未开放该应用的会话保护"
	}
	if err == nil || err.Error() != expected {
		t.Fatalf("Chrome launch rejection = %v, want %q", err, expected)
	}
}
