//go:build !windows || server

package desktop

import "fmt"

func (s *DesktopService) CookieCleanupAvailable() bool { return false }

func (s *DesktopService) ClearBrowserCookies(kind string, confirmed bool) (int, error) {
	return 0, fmt.Errorf("浏览器数据清理仅在 Windows 桌面版开放")
}
