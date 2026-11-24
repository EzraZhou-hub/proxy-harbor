package main

import (
	"embed"
	"github.com/wailsapp/wails/v3/pkg/application"
	"log"
	"os"
	"path/filepath"
	"proxyharbor/internal/core"
	"proxyharbor/internal/desktop"
	"proxyharbor/internal/engine"
	"proxyharbor/internal/store"
)

//go:embed all:frontend/dist
var assets embed.FS

// trayArgument marks a silent start from the optional login entry. The window
// is created hidden and the program only appears in the notification area.
const trayArgument = "--tray"

func main() {
	dataDir := os.Getenv("PROXY_HARBOR_DATA_DIR")
	if dataDir == "" {
		userDir, err := os.UserConfigDir()
		if err != nil {
			log.Fatal("无法定位配置目录: ", err)
		}
		dataDir = filepath.Join(userDir, "ProxyHarbor")
	}
	manager, err := core.New(store.New(dataDir), engine.Unavailable{})
	if err != nil {
		log.Fatal("无法加载配置，原文件已保留: ", err)
	}
	// The login entry starts the program with a hidden window so it only
	// appears in the notification area.
	startHidden := false
	for _, argument := range os.Args[1:] {
		if argument == trayArgument {
			startHidden = true
		}
	}
	app := application.New(application.Options{
		Name: "Proxy Harbor", Description: "应用专属代理启动器",
		Services:       []application.Service{application.NewService(desktop.New(manager))},
		Assets:         application.AssetOptions{Handler: application.AssetFileServerFS(assets)},
		SingleInstance: singleInstanceOptions(dataDir),
	})
	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:  "main",
		Title: "Proxy Harbor · 专属代理启动器", Width: 1280, Height: 850,
		MinWidth: 960, MinHeight: 680, BackgroundColour: application.NewRGB(246, 248, 250), URL: "/",
		Hidden: startHidden,
	})
	attachResident(app, window, dataDir)
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
