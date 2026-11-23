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
	app := application.New(application.Options{
		Name: "Proxy Harbor", Description: "应用专属代理启动器",
		Services:       []application.Service{application.NewService(desktop.New(manager))},
		Assets:         application.AssetOptions{Handler: application.AssetFileServerFS(assets)},
		SingleInstance: singleInstanceOptions(dataDir),
	})
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:  "main",
		Title: "Proxy Harbor · 专属代理启动器", Width: 1280, Height: 850,
		MinWidth: 960, MinHeight: 680, BackgroundColour: application.NewRGB(246, 248, 250), URL: "/",
	})
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
