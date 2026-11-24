//go:build !server

package main

import (
	_ "embed"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/session"
)

// trayIcon is the notification-area image: shield glyph in 16-64 px frames.
//
//go:embed build/tray.ico
var trayIcon []byte

const (
	// visibilityEvent tells the interface whether the window is on screen so it
	// can stop the one-second status poll while the program sits in the tray.
	visibilityEvent = "tray:visibility"
	trayPollDelay   = 3 * time.Second
	hiddenHintDelay = 6 * time.Second
)

// resident keeps the desktop process alive after the window is closed. The
// guardian binds a managed session to this process: if it exits, the guardian
// reports "desktop_exited" and ends the protected application, so closing the
// window must hide it instead of destroying it.
type resident struct {
	app     *application.App
	window  *application.WebviewWindow
	tray    *application.SystemTray
	managed *session.Runtime
	status  *application.MenuItem
	login   *application.MenuItem

	quitting atomic.Bool
	mu       sync.Mutex
	badge    string
	hint     bool
}

// residentApp lets the single-instance callback raise the hidden window.
var residentApp *resident

func attachResident(app *application.App, window *application.WebviewWindow, dataDir string) {
	r := &resident{app: app, window: window, managed: session.New(dataDir)}
	window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		if r.quitting.Load() {
			return
		}
		event.Cancel()
		r.hide()
	})

	menu := application.NewMenu()
	menu.Add("打开主界面").OnClick(func(*application.Context) { r.show() })
	menu.AddSeparator()
	r.status = menu.Add("状态：正在读取")
	r.status.SetEnabled(false)
	menu.AddSeparator()
	r.login = menu.AddCheckbox("登录时启动（最小化到托盘）", r.loginEnabled())
	r.login.OnClick(func(context *application.Context) { r.setLogin(context.IsChecked()) })
	menu.AddSeparator()
	menu.Add("退出 Proxy Harbor").OnClick(func(*application.Context) { r.requestQuit() })

	r.tray = app.SystemTray.New()
	r.tray.SetIcon(trayIcon)
	r.tray.SetTooltip("Proxy Harbor · 正在读取会话状态")
	r.tray.SetMenu(menu)
	r.tray.OnClick(r.show)
	r.tray.OnDoubleClick(r.show)
	residentApp = r
	r.refresh()
	go r.watch()
}

func (r *resident) show() {
	if r.window.IsMinimised() {
		r.window.UnMinimise()
	}
	r.window.Show()
	r.window.Focus()
	r.app.Event.Emit(visibilityEvent, true)
}

func (r *resident) hide() {
	r.window.Hide()
	r.app.Event.Emit(visibilityEvent, false)
	r.mu.Lock()
	r.hint = true
	r.mu.Unlock()
	r.tray.SetTooltip("Proxy Harbor · 已收起到托盘，保护仍在后台运行")
	time.AfterFunc(hiddenHintDelay, func() {
		r.mu.Lock()
		r.hint = false
		badge := r.badge
		r.mu.Unlock()
		r.tray.SetTooltip("Proxy Harbor · " + badge)
	})
}

func (r *resident) watch() {
	ticker := time.NewTicker(trayPollDelay)
	defer ticker.Stop()
	for range ticker.C {
		r.refresh()
	}
}

func (r *resident) refresh() {
	badge := badgeOf(r.managed.Refresh())
	r.mu.Lock()
	changed := badge != r.badge
	hinted := r.hint
	r.badge = badge
	r.mu.Unlock()
	if !changed {
		return
	}
	r.status.SetLabel("状态：" + badge)
	if !hinted {
		r.tray.SetTooltip("Proxy Harbor · " + badge)
	}
}

func (r *resident) requestQuit() {
	if activeSession(r.managed.Refresh()) {
		r.show()
		r.app.Dialog.Question().
			SetTitle("退出 Proxy Harbor").
			SetMessage("当前有受保护的会话正在运行。退出程序后，守护程序会结束该会话并清理网络限制。\n\n只想关闭窗口时，请点击窗口右上角的关闭按钮：窗口会收起到托盘，保护继续运行。\n\n仍要退出吗？").
			AddButtons([]*application.Button{
				{Label: "继续保护", IsCancel: true, IsDefault: true},
				{Label: "结束会话并退出", Callback: r.quit},
			}).
			Show()
		return
	}
	r.quit()
}

func (r *resident) quit() {
	r.quitting.Store(true)
	r.app.Quit()
}

func (r *resident) loginEnabled() bool {
	enabled, err := r.app.Autostart.IsEnabled()
	return err == nil && enabled
}

func (r *resident) setLogin(checked bool) {
	var err error
	if checked {
		err = r.app.Autostart.EnableWithOptions(application.AutostartOptions{Arguments: []string{trayArgument}})
	} else {
		err = r.app.Autostart.Disable()
	}
	if err == nil {
		return
	}
	// Put the checkbox back: the registry did not change.
	r.login.SetChecked(!checked)
	r.app.Dialog.Error().SetTitle("无法更新登录启动").SetMessage(err.Error()).Show()
}

func activeSession(status domain.ManagedSession) bool {
	switch status.State {
	case "monitoring", "preparing", "blocking":
		return true
	}
	return false
}

func badgeOf(status domain.ManagedSession) string {
	if !status.Available {
		return "保护不可用"
	}
	switch status.State {
	case "monitoring":
		if status.ProxyExit != "" {
			return "会话保护中 · 出口 " + status.ProxyExit
		}
		return "会话保护中"
	case "preparing":
		return "正在准备保护"
	case "blocking":
		return "正在阻断并结束"
	case "cleanup_required":
		return "需要恢复"
	case "failed":
		return "启动失败"
	case "stopped":
		return "会话已停止"
	}
	return "未启动保护"
}
