package desktop

import (
	"proxyharbor/internal/session"
	"testing"
)

func TestMissingGuardianRejectsLaunch(t *testing.T) {
	service := &DesktopService{managed: session.New(t.TempDir())}
	if service.ManagedStatus().Available {
		t.Fatal("Missing or unverified helper unexpectedly enabled")
	}
	// No client or executable is supplied: rejection must precede application
	// lookup, process launch and any system-policy mutation.
	status, err := service.StartManagedApplication("chrome")
	if err == nil || status.Available {
		t.Fatal("Desktop launch did not reject before side effects")
	}
}
