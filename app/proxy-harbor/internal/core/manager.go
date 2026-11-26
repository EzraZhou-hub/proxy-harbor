package core

import (
	"crypto/rand"
	"errors"
	"fmt"
	"proxyharbor/internal/control"
	"proxyharbor/internal/diagnostics"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"strings"
	"sync"
	"time"
)

type Repository interface {
	Path() string
	Load() (domain.Config, error)
	Save(domain.Config) error
}
type recoveryRepository interface {
	BackupAndReset() (string, error)
}
type Manager struct {
	mu          sync.Mutex
	repository  Repository
	engine      engine.Adapter
	config      domain.Config
	environment domain.Environment
	logs        []domain.LogEntry
	loadError   error
	backupPath  string
}

var _ control.Client = (*Manager)(nil)

func New(repository Repository, adapter engine.Adapter) (*Manager, error) {
	if adapter == nil {
		return nil, errors.New("缺少内核适配器")
	}
	m := &Manager{repository: repository, engine: adapter, environment: diagnostics.CollectLocal(), logs: []domain.LogEntry{}}
	m.loadConfigLocked()
	m.record("info", "基础框架已就绪；网络保护未开启，未修改系统网络。")
	return m, nil
}
func (m *Manager) loadConfigLocked() {
	config, err := m.repository.Load()
	if err == nil {
		if validationErr := domain.ValidateConfig(config); validationErr != nil {
			err = fmt.Errorf("%w: %v", domain.ErrInvalidConfig, validationErr)
		}
	}
	m.loadError = err
	if err != nil {
		m.config = domain.DefaultConfig()
		m.record("warning", "配置加载失败，原文件已保留；等待用户恢复。")
		return
	}
	m.config = config
	if m.config.V2rayNHTTPPort == 0 {
		m.config.V2rayNHTTPPort = domain.DefaultV2rayNHTTPPort
	}
	m.config.Applications = nil
	for _, app := range config.Applications {
		if app.ID == "claude" {
			m.config.Applications = append(m.config.Applications, app)
		}
	}
}
func (m *Manager) record(level, message string) {
	m.logs = append(m.logs, domain.LogEntry{Time: time.Now().Format(time.RFC3339), Level: level, Message: message})
	if len(m.logs) > 100 {
		m.logs = append([]domain.LogEntry{}, m.logs[len(m.logs)-100:]...)
	}
}
func (m *Manager) snapshotLocked() domain.Snapshot {
	config := m.config
	config.Profiles = append([]domain.ProxyProfile{}, config.Profiles...)
	config.Applications = append([]domain.TargetApplication{}, config.Applications...)
	blockers := []string{"保护内核尚未完成接入与泄露验证", "应用联网组件尚未完成兼容性验证"}
	if config.SelectedProfileID == "" {
		blockers = append(blockers, "尚未选择代理配置")
	}
	startup := domain.StartupStatus{BackupPath: m.backupPath}
	if m.loadError != nil {
		startup.Error = m.loadError.Error()
		_, recoverable := m.repository.(recoveryRepository)
		startup.CanReset = recoverable && errors.Is(m.loadError, domain.ErrInvalidConfig)
	}
	return domain.Snapshot{Version: "1.2.5", Startup: startup, Config: config, ConfigPath: m.repository.Path(), Engine: m.engine.Describe(),
		Protection: domain.ProtectionStatus{State: "unavailable", CanStart: false, Blockers: blockers}, Environment: m.environment,
		Checks: diagnostics.PendingChecks(), Logs: append([]domain.LogEntry{}, m.logs...)}
}
func (m *Manager) Snapshot() domain.Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}
func (m *Manager) commit(next domain.Config, message string) (domain.Snapshot, error) {
	if m.loadError != nil {
		return domain.Snapshot{}, errors.New("配置尚未恢复，不能保存或覆盖原文件")
	}
	if err := m.repository.Save(next); err != nil {
		return domain.Snapshot{}, fmt.Errorf("保存失败，配置未更改: %w", err)
	}
	m.config = next
	m.record("info", message)
	return m.snapshotLocked(), nil
}
func (m *Manager) ReloadConfiguration() domain.Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadConfigLocked()
	return m.snapshotLocked()
}
func (m *Manager) ResetConfiguration(confirmed bool) (domain.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !confirmed {
		return domain.Snapshot{}, errors.New("请先确认备份并重置配置")
	}
	if m.loadError == nil || !errors.Is(m.loadError, domain.ErrInvalidConfig) {
		return domain.Snapshot{}, errors.New("当前配置不允许重置，请先重新读取配置")
	}
	repository, ok := m.repository.(recoveryRepository)
	if !ok {
		return domain.Snapshot{}, errors.New("当前存储不支持配置恢复")
	}
	backup, err := repository.BackupAndReset()
	if err != nil {
		return domain.Snapshot{}, err
	}
	m.backupPath = backup
	m.loadConfigLocked()
	if m.loadError != nil {
		return domain.Snapshot{}, fmt.Errorf("备份已保留于 %s，但重新加载失败: %w", backup, m.loadError)
	}
	m.record("info", "已备份原配置并恢复默认配置。")
	return m.snapshotLocked(), nil
}
func (m *Manager) SaveProxy(profile domain.ProxyProfile) (domain.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	profile.Name = strings.TrimSpace(profile.Name)
	profile.Host = strings.TrimSpace(profile.Host)
	if err := domain.ValidateProfile(profile); err != nil {
		return domain.Snapshot{}, err
	}
	next := m.config
	next.Profiles = append([]domain.ProxyProfile{}, m.config.Profiles...)
	if profile.ID == "" {
		id := make([]byte, 12)
		if _, err := rand.Read(id); err != nil {
			return domain.Snapshot{}, err
		}
		profile.ID = fmt.Sprintf("proxy-%x", id)
		next.Profiles = append(next.Profiles, profile)
		if next.SelectedProfileID == "" {
			next.SelectedProfileID = profile.ID
		}
	} else {
		found := false
		for index, item := range next.Profiles {
			if item.ID == profile.ID {
				next.Profiles[index] = profile
				found = true
				break
			}
		}
		if !found {
			return domain.Snapshot{}, errors.New("代理配置不存在")
		}
	}
	return m.commit(next, "代理配置已保存，尚未验证联网能力。")
}

func (m *Manager) SaveSessionNetwork(value string, port int) (domain.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value = strings.TrimSpace(value)
	if value != "" {
		if err := domain.ValidateExpectedProxyIPv4(value); err != nil {
			return domain.Snapshot{}, err
		}
	}
	if err := domain.ValidateV2rayNHTTPPort(port); err != nil {
		return domain.Snapshot{}, err
	}
	next := m.config
	next.ExpectedProxyIPv4 = value
	next.V2rayNHTTPPort = port
	return m.commit(next, "已保存固定出口 IPv4 和 v2rayN HTTP 入口。")
}
func (m *Manager) DeleteProxy(id string) (domain.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.config
	next.Profiles = []domain.ProxyProfile{}
	found := false
	for _, p := range m.config.Profiles {
		if p.ID == id {
			found = true
		} else {
			next.Profiles = append(next.Profiles, p)
		}
	}
	if !found {
		return domain.Snapshot{}, errors.New("代理配置不存在")
	}
	if next.SelectedProfileID == id {
		next.SelectedProfileID = ""
	}
	return m.commit(next, "代理配置已删除。")
}
func (m *Manager) SelectProxy(id string) (domain.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for _, p := range m.config.Profiles {
		if p.ID == id {
			found = true
		}
	}
	if !found {
		return domain.Snapshot{}, errors.New("代理配置不存在")
	}
	next := m.config
	next.SelectedProfileID = id
	return m.commit(next, "已选择代理配置，网络保护仍未开启。")
}
func (m *Manager) RefreshEnvironment() domain.Snapshot {
	env := diagnostics.CollectLocal()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.environment = env
	m.record("info", "已刷新本机网卡与运行信息，没有发起外部连接。")
	return m.snapshotLocked()
}
func (m *Manager) StartProtection() error {
	// P0 is mandatory: no launch or policy mutation is available in the scaffold.
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("warning", "启动保护已拒绝：内核与应用覆盖范围尚未验证。")
	return engine.ErrUnavailable
}
