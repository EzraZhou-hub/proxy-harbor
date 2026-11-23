package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"proxyharbor/internal/store"
	"testing"
)

func profile() domain.ProxyProfile {
	return domain.ProxyProfile{Name: "开发代理", Protocol: "http", Host: "127.0.0.1", Port: 7890}
}

func TestFixedExitPersistsAndRejectsInvalidReplacement(t *testing.T) {
	repo := store.New(t.TempDir())
	manager, err := New(repo, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	// Legacy configs omit the new optional setting.
	if manager.Snapshot().Config.ExpectedProxyIPv4 != "" {
		t.Fatal("Unexpected default exit")
	}
	if _, err = manager.SaveExpectedProxyIPv4(" 131.103.130.202 "); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"127.0.0.1", "192.168.1.1", "203.0.113.1", "https://1.1.1.1", "::1"} {
		if _, err = manager.SaveExpectedProxyIPv4(value); err == nil {
			t.Fatalf("Accepted %s", value)
		}
	}
	restarted, err := New(repo, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Snapshot().Config.ExpectedProxyIPv4 != "131.103.130.202" {
		t.Fatal("Stored exit changed or was lost")
	}
	if _, err = restarted.SaveExpectedProxyIPv4(""); err != nil {
		t.Fatal(err)
	}
	again, err := New(repo, engine.Unavailable{})
	if err != nil || again.Snapshot().Config.ExpectedProxyIPv4 != "" {
		t.Fatal("Cleared setting not persisted")
	}
}

func TestConfigurationSurvivesRestartAndDeletion(t *testing.T) {
	repo := store.New(t.TempDir())
	manager, err := New(repo, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"http", "https", "socks5"} {
		p := profile()
		p.Protocol = protocol
		if _, err = manager.SaveProxy(p); err != nil {
			t.Fatal(err)
		}
	}
	first := manager.Snapshot().Config.Profiles[0]
	first.Name = "已编辑"
	if _, err = manager.SaveProxy(first); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "desktop.exe")
	if err = os.WriteFile(executable, []byte("not executed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.ConfigureApplication("chrome", executable); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(repo, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := restarted.Snapshot()
	if len(snapshot.Config.Profiles) != 3 || snapshot.Config.Profiles[0].Name != "已编辑" || snapshot.Config.Applications[1].Executable != executable {
		t.Fatal("persisted configuration was lost")
	}
	snapshot.Config.Profiles[0].Name = "external mutation"
	if restarted.Snapshot().Config.Profiles[0].Name != "已编辑" {
		t.Fatal("snapshot exposes mutable configuration")
	}
	if _, err = restarted.DeleteProxy(first.ID); err != nil {
		t.Fatal(err)
	}
	saved, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Profiles) != 2 || saved.SelectedProfileID != "" {
		t.Fatal("deleting active profile must clear selection")
	}
}

func TestLegacyConfigDropsRetiredApplicationOnSave(t *testing.T) {
	repo := store.New(t.TempDir())
	legacy := domain.DefaultConfig()
	legacy.ExpectedProxyIPv4 = "131.103.130.202"
	legacy.Applications = append(legacy.Applications[:1], domain.TargetApplication{
		ID: "codex", Name: "Codex", Compatibility: "unverified",
	})
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repo.Path(), data, 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(repo, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if snapshot.Startup.Error != "" || snapshot.Config.ExpectedProxyIPv4 != legacy.ExpectedProxyIPv4 ||
		len(snapshot.Config.Applications) != 2 || snapshot.Config.Applications[0].ID != "claude" ||
		snapshot.Config.Applications[1].ID != "chrome" {
		t.Fatalf("unexpected desktop configuration: %+v", snapshot.Config)
	}
	unchanged, err := os.ReadFile(repo.Path())
	if err != nil || string(unchanged) != string(data) {
		t.Fatal("opening a legacy config rewrote the original file")
	}
	if _, err := manager.SaveExpectedProxyIPv4("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	saved, err := repo.Load()
	if err != nil || len(saved.Applications) != 2 || saved.Applications[1].ID != "chrome" {
		t.Fatalf("unexpected saved applications: %+v, %v", saved.Applications, err)
	}
}

type failingRepository struct{ config domain.Config }

func (r failingRepository) Path() string                 { return "test-config" }
func (r failingRepository) Load() (domain.Config, error) { return r.config, nil }
func (r failingRepository) Save(domain.Config) error     { return errors.New("disk unavailable") }

func TestFailedSaveDoesNotMutateLiveConfiguration(t *testing.T) {
	config := domain.DefaultConfig()
	p := profile()
	p.ID = "existing"
	config.Profiles = []domain.ProxyProfile{p}
	config.SelectedProfileID = p.ID
	manager, err := New(failingRepository{config}, engine.Unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "unsaved"
	if _, err = manager.SaveProxy(p); err == nil {
		t.Fatal("expected save failure")
	}
	if manager.Snapshot().Config.Profiles[0].Name != "开发代理" {
		t.Fatal("unsaved state escaped into live configuration")
	}
}

type unverifiedEngine struct{ called bool }

func (e *unverifiedEngine) Describe() domain.EngineStatus {
	return domain.EngineStatus{Available: true, Capabilities: domain.Capabilities{ForwardTCP: true, RemoteDNS: true, BlockIPv6: true, BlockUDP: true, FailClosed: true}}
}
func (e *unverifiedEngine) Prepare(context.Context, engine.Plan) error { e.called = true; return nil }

func TestScaffoldCannotStartProtectionEvenWithClaimedCapabilities(t *testing.T) {
	adapter := &unverifiedEngine{}
	manager, err := New(store.New(t.TempDir()), adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.StartProtection(); !errors.Is(err, engine.ErrUnavailable) {
		t.Fatal("unverified protection was not refused")
	}
	state := manager.Snapshot()
	if state.Protection.CanStart || state.Protection.State != "unavailable" || adapter.called {
		t.Fatal("scaffold must not activate an engine")
	}
	for _, check := range state.Checks {
		if check.Status != "not_run" {
			t.Fatal("unperformed checks must not look successful")
		}
	}
}

func TestInvalidProfilesNeverReachDisk(t *testing.T) {
	for _, host := range []string{"http://127.0.0.1", "user:secret@proxy.example.com", "::1", "host/secret", ""} {
		t.Run(host, func(t *testing.T) {
			repo := store.New(t.TempDir())
			manager, err := New(repo, engine.Unavailable{})
			if err != nil {
				t.Fatal(err)
			}
			p := profile()
			p.Host = host
			if _, err = manager.SaveProxy(p); err == nil {
				t.Fatal("invalid endpoint accepted")
			}
			if _, err = os.Stat(repo.Path()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid configuration reached disk")
			}
		})
	}
}
