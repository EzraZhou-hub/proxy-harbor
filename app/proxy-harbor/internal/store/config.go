package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"proxyharbor/internal/domain"
	"sync"
)

type ConfigStore struct {
	mu       sync.Mutex
	path     string
	loaded   bool
	exists   bool
	revision [32]byte
}

func New(directory string) *ConfigStore {
	return &ConfigStore{path: filepath.Join(directory, "config.json")}
}
func (s *ConfigStore) Path() string { return s.path }
func (s *ConfigStore) Load() (domain.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.loaded, s.exists, s.revision = true, false, sha256.Sum256(nil)
		return domain.DefaultConfig(), nil
	}
	if err != nil {
		return domain.Config{}, err
	}
	s.loaded, s.exists, s.revision = true, true, sha256.Sum256(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config domain.Config
	if err = decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("%w: 配置格式无效: %v", domain.ErrInvalidConfig, err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return config, fmt.Errorf("%w: 配置包含多余内容", domain.ErrInvalidConfig)
	}
	if err := domain.ValidateConfig(config); err != nil {
		return config, fmt.Errorf("%w: %v", domain.ErrInvalidConfig, err)
	}
	return config, nil
}
func (s *ConfigStore) Save(config domain.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := domain.ValidateConfig(config); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	unlock, err := lockConfig(s.path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := s.unchanged(); err != nil {
		return err
	}
	return s.write(data)
}

// unchanged runs while the cross-process lock is held, so checking the revision
// and replacing the file form one operation for all application instances.
func (s *ConfigStore) unchanged() ([]byte, error) {
	data, err := os.ReadFile(s.path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if (!s.loaded && exists) || (s.loaded && (s.exists != exists || s.revision != sha256.Sum256(data))) {
		return nil, domain.ErrConfigChanged
	}
	return data, nil
}

func (s *ConfigStore) write(data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".config-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err := replaceFile(temp.Name(), s.path); err != nil {
		return err
	}
	s.loaded, s.exists, s.revision = true, true, sha256.Sum256(append(data, '\n'))
	return nil
}

// BackupAndReset never replaces the original until a complete backup has been
// written and synced. A changed file must be re-read and confirmed again.
func (s *ConfigStore) BackupAndReset() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockConfig(s.path + ".lock")
	if err != nil {
		return "", err
	}
	defer unlock()
	data, err := s.unchanged()
	if err != nil {
		return "", err
	}
	if !s.loaded || !s.exists {
		return "", errors.New("没有可备份的配置，请重新读取配置")
	}
	backup, err := os.CreateTemp(filepath.Dir(s.path), "config.backup-*.json")
	if err != nil {
		return "", fmt.Errorf("无法创建备份，原配置未更改: %w", err)
	}
	defer backup.Close()
	if _, err := backup.Write(data); err != nil {
		return "", fmt.Errorf("备份失败，原配置未更改: %w", err)
	}
	if err := backup.Sync(); err != nil {
		return "", fmt.Errorf("备份失败，原配置未更改: %w", err)
	}
	if err := backup.Close(); err != nil {
		return "", err
	}
	defaults, err := json.MarshalIndent(domain.DefaultConfig(), "", "  ")
	if err != nil {
		return "", err
	}
	if err := s.write(defaults); err != nil {
		return "", fmt.Errorf("重置失败，备份保留于 %s: %w", backup.Name(), err)
	}
	return backup.Name(), nil
}
