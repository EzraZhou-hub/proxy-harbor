package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"proxyharbor/internal/store"
	"testing"
)

func TestRecoveryBlocksNormalSavesAndRequiresConfirmation(t *testing.T) {
	repo := store.New(t.TempDir())
	original := []byte("not json")
	if err := os.WriteFile(repo.Path(), original, 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(repo, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	state := manager.Snapshot()
	if state.Startup.Error == "" || !state.Startup.CanReset || state.Protection.CanStart {
		t.Fatal("invalid config must open in recovery mode")
	}
	if _, err := manager.SaveProxy(profile()); err == nil {
		t.Fatal("recovery must block ordinary configuration writes")
	}
	if _, err := manager.ResetConfiguration(false); err == nil {
		t.Fatal("reset must require explicit confirmation")
	}
	data, err := os.ReadFile(repo.Path())
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("unconfirmed recovery changed the original")
	}
	state, err = manager.ResetConfiguration(true)
	if err != nil {
		t.Fatal(err)
	}
	if state.Startup.Error != "" || state.Startup.BackupPath == "" || state.Startup.CanReset {
		t.Fatal("recovery did not return to normal state")
	}
	data, err = os.ReadFile(state.Startup.BackupPath)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("original configuration not backed up")
	}
	if _, err := manager.ResetConfiguration(true); err == nil {
		t.Fatal("healthy config must not be reset through the recovery action")
	}
	if _, err := manager.SaveProxy(profile()); err != nil {
		t.Fatal(err)
	}
}

func TestReloadAcceptsManualRepairWithoutReset(t *testing.T) {
	repo := store.New(t.TempDir())
	if err := os.WriteFile(repo.Path(), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(repo, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	config := domain.DefaultConfig()
	config.Profiles = []domain.ProxyProfile{{ID: "repaired", Name: "Repaired", Protocol: "http", Host: "127.0.0.1", Port: 7890}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repo.Path(), data, 0600); err != nil {
		t.Fatal(err)
	}
	state := manager.ReloadConfiguration()
	if state.Startup.Error != "" || state.Startup.BackupPath != "" || len(state.Config.Profiles) != 1 {
		t.Fatal("manually repaired configuration was not loaded")
	}
}

type failedRecoveryRepository struct{}

func (failedRecoveryRepository) Path() string { return "test-config" }
func (failedRecoveryRepository) Load() (domain.Config, error) {
	return domain.Config{}, domain.ErrInvalidConfig
}
func (failedRecoveryRepository) Save(domain.Config) error { return errors.New("must not save") }
func (failedRecoveryRepository) BackupAndReset() (string, error) {
	return "", errors.New("backup unavailable")
}

func TestBackupFailureKeepsRecoveryActive(t *testing.T) {
	manager, err := New(failedRecoveryRepository{}, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ResetConfiguration(true); err == nil {
		t.Fatal("backup failure must be reported")
	}
	if manager.Snapshot().Startup.Error == "" {
		t.Fatal("failed recovery must remain blocked")
	}
}
