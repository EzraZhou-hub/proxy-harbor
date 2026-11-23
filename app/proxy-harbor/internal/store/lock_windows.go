package store

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
)

func lockConfig(path string) (func(), error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// The handle is exclusive and automatically released even if the process
	// crashes. The file may remain on disk; its existence is not the lock.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return nil, errors.New("另一个窗口正在保存配置，请稍后重试")
	}
	if err != nil {
		return nil, fmt.Errorf("无法锁定配置: %w", err)
	}
	return func() { windows.CloseHandle(handle) }, nil
}
