//go:build windows && !server

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestFlashCookieCleanupScope(t *testing.T) {
	roaming := t.TempDir()
	flash := []string{
		filepath.Join(roaming, roamingFlashObjects, `a\example.test\state.sol`),
		filepath.Join(roaming, roamingFlashObjects, `b\example.test\state.SOL`),
	}
	preserved := []string{
		filepath.Join(roaming, `Macromedia\Flash Player\macromedia.com\support\flashplayer\sys\settings.sol`),
		filepath.Join(roaming, roamingFlashObjects, `a\example.test\readme.txt`),
	}
	for _, group := range [][]string{flash, preserved} {
		for _, file := range group {
			writeCookieFixture(t, file)
		}
	}
	files, err := flashCookieFiles(roaming)
	if err != nil || !slices.Equal(files, flash) {
		t.Fatalf("Flash files = %q, %v, want %q", files, err, flash)
	}
	count, err := deleteCookieFiles(files, func() error { return nil })
	if err != nil || count != len(flash) {
		t.Fatalf("Flash cleanup = %d, %v", count, err)
	}
	files, err = flashCookieFiles(roaming)
	if err != nil || len(files) != 0 {
		t.Fatalf("Flash retry found %q, %v", files, err)
	}
	for _, file := range preserved {
		assertCookieFixture(t, file)
	}
}

func TestCookieCleanupPreflightLeavesEveryFileUntouched(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a.sol")
	second := filepath.Join(root, "b.sol")
	files := []string{first, second}
	for _, file := range files {
		writeCookieFixture(t, file)
	}
	locked, err := os.Open(second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { locked.Close() })
	if count, err := deleteCookieFiles(files, func() error { return nil }); count != 0 || err == nil {
		t.Fatalf("cleanup with a busy file = %d, %v", count, err)
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	processStarted := errors.New("Flash started during preflight")
	if count, err := deleteCookieFiles(files, func() error { return processStarted }); count != 0 || !errors.Is(err, processStarted) {
		t.Fatalf("cleanup with a running Flash process = %d, %v", count, err)
	}
	for _, file := range files {
		assertCookieFixture(t, file)
	}
}

func TestCookieCleanupRequiresConfirmation(t *testing.T) {
	service := &DesktopService{}
	if count, err := service.ClearBrowserCookies("flash", false); count != 0 || err == nil {
		t.Fatalf("unconfirmed Flash cleanup = %d, %v", count, err)
	}
	if count, err := service.ClearBrowserCookies("chrome", true); count != 0 || err == nil || err.Error() != "未知的清理类型" {
		t.Fatalf("retired Chrome cleanup = %d, %v", count, err)
	}
}

func writeCookieFixture(t *testing.T, file string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertCookieFixture(t *testing.T, file string) {
	t.Helper()
	if data, err := os.ReadFile(file); err != nil || string(data) != "fixture" {
		t.Fatalf("fixture %q changed: %q, %v", file, data, err)
	}
}
