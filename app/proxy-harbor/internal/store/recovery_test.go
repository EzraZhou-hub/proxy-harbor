package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"proxyharbor/internal/domain"
	"testing"
)

func TestStaleStoreCannotOverwriteAnotherInstance(t *testing.T) {
	dir := t.TempDir()
	first, second := New(dir), New(dir)
	a, err := first.Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Load()
	if err != nil {
		t.Fatal(err)
	}
	a.Profiles = []domain.ProxyProfile{{ID: "first", Name: "First", Protocol: "http", Host: "127.0.0.1", Port: 7890}}
	if err := first.Save(a); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(first.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Save(b); !errors.Is(err, domain.ErrConfigChanged) {
		t.Fatalf("stale save must fail: %v", err)
	}
	after, err := os.ReadFile(first.Path())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("stale writer changed the configuration")
	}
	b, err = second.Load()
	if err != nil {
		t.Fatal(err)
	}
	b.Profiles = append(b.Profiles, domain.ProxyProfile{ID: "second", Name: "Second", Protocol: "http", Host: "127.0.0.1", Port: 7891})
	if err := second.Save(b); err != nil {
		t.Fatal(err)
	}
	loaded, err := first.Load()
	if err != nil || len(loaded.Profiles) != 2 {
		t.Fatal("reloading must allow a save retaining both entries")
	}
}

func TestConfigLockIsExclusiveAndReusable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.lock")
	release, err := lockConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := lockConfig(path)
	if err == nil {
		second()
		release()
		t.Fatal("two writers acquired the same lock")
	}
	release()
	release, err = lockConfig(path)
	if err != nil {
		t.Fatalf("a leftover lock file must not block new writers: %v", err)
	}
	release()
}

func TestBackupAndResetPreservesExactOriginal(t *testing.T) {
	repo := New(t.TempDir())
	original := []byte("{ broken configuration\r\n")
	if err := os.WriteFile(repo.Path(), original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Load(); !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("expected recoverable error: %v", err)
	}
	backup, err := repo.BackupAndReset()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(backup)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("backup differs from original")
	}
	config, err := repo.Load()
	if err != nil || len(config.Profiles) != 0 || config.SelectedProfileID != "" {
		t.Fatalf("defaults not restored: %v", err)
	}
	if err := repo.Save(config); err != nil {
		t.Fatalf("restored configuration cannot be saved: %v", err)
	}
}

func TestResetRefusesAChangedOriginal(t *testing.T) {
	dir := t.TempDir()
	repo := New(dir)
	if err := os.WriteFile(repo.Path(), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Load(); err == nil {
		t.Fatal("expected invalid configuration")
	}
	changed := []byte("changed by another program")
	if err := os.WriteFile(repo.Path(), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BackupAndReset(); !errors.Is(err, domain.ErrConfigChanged) {
		t.Fatalf("changed original must not be reset: %v", err)
	}
	data, err := os.ReadFile(repo.Path())
	if err != nil || !bytes.Equal(data, changed) {
		t.Fatal("new original was modified")
	}
	backups, err := filepath.Glob(filepath.Join(dir, "config.backup-*.json"))
	if err != nil || len(backups) != 0 {
		t.Fatal("reset created a backup without fresh confirmation")
	}
}
