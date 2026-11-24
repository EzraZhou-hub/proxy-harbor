//go:build !server

package main

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
)

func singleInstanceOptions(dataDir string) *application.SingleInstanceOptions {
	absolute, err := filepath.Abs(dataDir)
	if err != nil {
		absolute = filepath.Clean(dataDir)
	}
	// Separate test data directories may run independently. On Windows paths
	// differing only in case must still identify the same desktop instance.
	id := sha256.Sum256([]byte(strings.ToLower(absolute)))
	return &application.SingleInstanceOptions{
		UniqueID: fmt.Sprintf("local.proxyharbor.%x", id[:16]),
		OnSecondInstanceLaunch: func(application.SecondInstanceData) {
			// The window is usually hidden in the notification area; reuse the
			// resident path so the interface resumes its status poll.
			if residentApp != nil {
				residentApp.show()
				return
			}
			if window, ok := application.Get().Window.GetByName("main"); ok {
				if window.IsMinimised() {
					window.UnMinimise()
				}
				window.Show()
				window.Focus()
			}
		},
	}
}
