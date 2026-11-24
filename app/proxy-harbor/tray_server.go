//go:build server

package main

import "github.com/wailsapp/wails/v3/pkg/application"

// The integration host has no notification area; window close keeps its
// existing behaviour.
func attachResident(*application.App, *application.WebviewWindow, string) {}
