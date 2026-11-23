//go:build !server

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopInstanceIdentityUsesTheDataDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Profile")
	first := singleInstanceOptions(path)
	same := singleInstanceOptions(strings.ToUpper(path))
	other := singleInstanceOptions(path + "-isolated")
	if first.UniqueID == "" || first.UniqueID != same.UniqueID || first.UniqueID == other.UniqueID {
		t.Fatal("same data directory must reuse its instance identity, isolated data must stay separate")
	}
	if first.OnSecondInstanceLaunch == nil {
		t.Fatal("desktop must bring the existing window forward")
	}
}
