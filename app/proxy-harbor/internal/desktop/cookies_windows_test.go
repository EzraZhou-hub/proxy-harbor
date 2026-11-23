//go:build windows && !server

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBrowserCookieCleanupScope(t *testing.T) {
	local, roaming := t.TempDir(), t.TempDir()
	chrome := filepath.Join(local, chromeUserData)
	cookies := []string{
		filepath.Join(chrome, `Default\Network\Cookies`),
		filepath.Join(chrome, `Default\Network\Cookies-wal`),
		filepath.Join(chrome, `Profile 2\Cookies`),
		filepath.Join(chrome, `Profile 2\Cookies-journal`),
	}
	flash := []string{
		filepath.Join(roaming, roamingFlashObjects, `a\example.test\state.sol`),
		filepath.Join(chrome, "Default", chromeFlashObjects, `b\example.test\state.SOL`),
	}
	preserved := []string{
		filepath.Join(roaming, `Macromedia\Flash Player\macromedia.com\support\flashplayer\sys\settings.sol`),
		filepath.Join(roaming, roamingFlashObjects, `a\example.test\readme.txt`),
		filepath.Join(chrome, `Default\History`),
		filepath.Join(chrome, `Default\Network\Cookies-backup`),
		filepath.Join(chrome, `Profile 2\Login Data`),
		filepath.Join(chrome, `Unrelated\Network\Cookies`),
	}
	for _, group := range [][]string{cookies, flash, preserved} {
		for _, file := range group {
			writeCookieFixture(t, file)
		}
	}
	for _, action := range []struct {
		kind string
		want []string
	}{{"chrome", cookies}, {"flash", flash}} {
		kind, want := action.kind, action.want
		files, err := browserCookieFiles(local, roaming, kind)
		if err != nil || !slices.Equal(files, want) {
			t.Fatalf("%s files = %q, %v, want %q", kind, files, err, want)
		}
		count, err := deleteCookieFiles(files, func() error { return nil })
		if err != nil || count != len(want) {
			t.Fatalf("%s cleanup = %d, %v", kind, count, err)
		}
		files, err = browserCookieFiles(local, roaming, kind)
		if err != nil || len(files) != 0 {
			t.Fatalf("%s retry found %q, %v", kind, files, err)
		}
		if kind == "chrome" {
			for _, file := range flash {
				assertCookieFixture(t, file)
			}
		}
	}
	for _, file := range preserved {
		assertCookieFixture(t, file)
	}
}

func TestCookieCleanupPreflightLeavesEveryFileUntouched(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "Cookies")
	journal := filepath.Join(root, "Cookies-wal")
	files := []string{database, journal}
	for _, file := range files {
		writeCookieFixture(t, file)
	}
	locked, err := os.Open(journal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { locked.Close() })
	if count, err := deleteCookieFiles(files, func() error { return nil }); count != 0 || err == nil {
		t.Fatalf("cleanup with a busy journal = %d, %v", count, err)
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	processStarted := errors.New("browser started during preflight")
	if count, err := deleteCookieFiles(files, func() error { return processStarted }); count != 0 || !errors.Is(err, processStarted) {
		t.Fatalf("cleanup with a running browser = %d, %v", count, err)
	}
	for _, file := range files {
		assertCookieFixture(t, file)
	}
}

func TestCookieCleanupRequiresConfirmation(t *testing.T) {
	service := &DesktopService{}
	for _, kind := range []string{"chrome", "flash"} {
		if count, err := service.ClearBrowserCookies(kind, false); count != 0 || err == nil {
			t.Fatalf("unconfirmed %s cleanup = %d, %v", kind, count, err)
		}
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
