//go:build !server

package desktop

import "runtime"

func nativeSessionsAllowed() bool { return runtime.GOOS == "windows" && runtime.GOARCH == "amd64" }
