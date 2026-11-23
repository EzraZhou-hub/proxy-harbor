package desktop

import (
	"fmt"
	"github.com/wailsapp/wails/v3/pkg/application"
	"os"
	"path/filepath"
	"proxyharbor/internal/control"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/session"
)

type DesktopService struct {
	client  control.Client
	managed *session.Runtime
}

const desktopSessionRequired = "会话保护仅在 Windows x64 桌面版开放。"

func New(client control.Client) *DesktopService {
	service := &DesktopService{client: client, managed: session.New(filepath.Dir(client.Snapshot().ConfigPath))}
	if nativeSessionsAllowed() && service.managed.Status().Available {
		snapshot := client.Snapshot()
		if snapshot.Startup.Error == "" {
			for _, app := range snapshot.Config.Applications {
				if app.ID == "chrome" && app.Executable == "" {
					path := `C:\Program Files\Google\Chrome\Application\chrome.exe`
					if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
						client.ConfigureApplication("chrome", path)
					}
					break
				}
			}
		}
	}
	return service
}
func (s *DesktopService) ManagedStatus() domain.ManagedSession {
	status := s.managed.Status()
	if !nativeSessionsAllowed() {
		status.Available = false
		status.TakeoverAvailable = false
		switch status.State {
		case "monitoring", "preparing", "blocking":
			status.State, status.Reason = "unavailable", "desktop_locked"
		}
		status.Detail = desktopSessionRequired
	}
	return status
}
func (s *DesktopService) StartManagedApplication(id string) (domain.ManagedSession, error) {
	if !nativeSessionsAllowed() {
		return s.ManagedStatus(), fmt.Errorf("%s", desktopSessionRequired)
	}
	if id != "chrome" && (id != "claude" || !session.DesktopAdmitted()) {
		return s.ManagedStatus(), fmt.Errorf("当前版本未开放该应用的会话保护")
	}
	status := s.managed.Status()
	if !status.Available {
		return status, fmt.Errorf("%s", status.Detail)
	}
	snapshot := s.client.Snapshot()
	if snapshot.Startup.Error != "" {
		return s.managed.Status(), fmt.Errorf("请先恢复配置")
	}
	for _, app := range snapshot.Config.Applications {
		if app.ID == id {
			endpoint, err := s.managed.V2rayNEndpoint(snapshot.Config.ExpectedProxyIPv4)
			if err != nil {
				return status, err
			}
			return s.managed.Start(id, app.Executable, endpoint)
		}
	}
	return s.managed.Status(), fmt.Errorf("目标应用未登记")
}
func (s *DesktopService) StopManagedApplication() (domain.ManagedSession, error) {
	if !nativeSessionsAllowed() {
		return s.ManagedStatus(), fmt.Errorf("%s", desktopSessionRequired)
	}
	return s.managed.Stop()
}
func (s *DesktopService) RecoverManagedSession() (domain.ManagedSession, error) {
	if !nativeSessionsAllowed() {
		return s.ManagedStatus(), fmt.Errorf("%s", desktopSessionRequired)
	}
	return s.managed.Recover()
}
func (s *DesktopService) Snapshot() domain.Snapshot            { return s.client.Snapshot() }
func (s *DesktopService) ReloadConfiguration() domain.Snapshot { return s.client.ReloadConfiguration() }
func (s *DesktopService) ResetConfiguration(confirmed bool) (domain.Snapshot, error) {
	return s.client.ResetConfiguration(confirmed)
}
func (s *DesktopService) OpenConfigDirectory() error {
	return application.Get().Env.OpenFileManager(filepath.Dir(s.client.Snapshot().ConfigPath), false)
}
func (s *DesktopService) SaveProxy(p domain.ProxyProfile) (domain.Snapshot, error) {
	return s.client.SaveProxy(p)
}
func (s *DesktopService) SaveExpectedProxyIPv4(value string) (domain.Snapshot, error) {
	return s.client.SaveExpectedProxyIPv4(value)
}
func (s *DesktopService) DeleteProxy(id string) (domain.Snapshot, error) {
	return s.client.DeleteProxy(id)
}
func (s *DesktopService) SelectProxy(id string) (domain.Snapshot, error) {
	return s.client.SelectProxy(id)
}
func (s *DesktopService) ConfigureApplication(id, path string) (domain.Snapshot, error) {
	return s.client.ConfigureApplication(id, path)
}
func (s *DesktopService) RefreshEnvironment() domain.Snapshot { return s.client.RefreshEnvironment() }
func (s *DesktopService) StartProtection() error              { return s.client.StartProtection() }
func (s *DesktopService) ChooseExecutable() (string, error) {
	return application.Get().Dialog.OpenFile().SetTitle("选择应用程序").AddFilter("Windows 应用", "*.exe").PromptForSingleSelection()
}
