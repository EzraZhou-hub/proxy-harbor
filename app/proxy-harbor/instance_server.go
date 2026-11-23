//go:build server

package main

import "github.com/wailsapp/wails/v3/pkg/application"

// Integration hosts may run separately; the store still refuses stale writes.
func singleInstanceOptions(string) *application.SingleInstanceOptions { return nil }
