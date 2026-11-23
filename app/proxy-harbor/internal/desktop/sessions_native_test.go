//go:build windows && amd64 && !server

package desktop

import "testing"

func TestWindowsDesktopAllowsLocalSessionTrial(t *testing.T) {
	if !nativeSessionsAllowed() {
		t.Fatal("Windows x64 desktop session trial is disabled")
	}
}
