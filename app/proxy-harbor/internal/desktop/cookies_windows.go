//go:build windows && !server

package desktop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const roamingFlashObjects = `Macromedia\Flash Player\#SharedObjects`

var cookieCleanupMu sync.Mutex

func (s *DesktopService) CookieCleanupAvailable() bool { return true }

func (s *DesktopService) ClearBrowserCookies(kind string, confirmed bool) (int, error) {
	if !confirmed {
		return 0, fmt.Errorf("请先确认清理范围")
	}
	if kind != "flash" {
		return 0, fmt.Errorf("未知的清理类型")
	}
	cookieCleanupMu.Lock()
	defer cookieCleanupMu.Unlock()
	if err := checkFlashProcesses(); err != nil {
		return 0, err
	}
	roaming, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return 0, fmt.Errorf("无法定位当前用户的漫游应用数据目录：%w", err)
	}
	files, err := flashCookieFiles(roaming)
	if err != nil {
		return 0, fmt.Errorf("无法检查待清理的文件：%w", err)
	}
	return deleteCookieFiles(files, checkFlashProcesses)
}

func checkFlashProcesses() error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("无法检查 Flash 运行状态：%w", err)
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if name == "flashplayer.exe" || strings.HasPrefix(name, "flashplayerplugin") {
			return fmt.Errorf("请关闭仍在运行的 Flash 程序，然后重试")
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("无法检查 Flash 运行状态：%w", err)
	}
	return nil
}

func flashCookieFiles(roaming string) ([]string, error) {
	path, err := cookieDirectory(roaming, roamingFlashObjects)
	if err != nil || path == "" {
		return nil, err
	}
	var files []string
	err = filepath.WalkDir(path, func(file string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() && strings.EqualFold(filepath.Ext(file), ".sol") {
			files = append(files, file)
		}
		return err
	})
	return files, err
}

func cookieDirectory(base, relative string) (string, error) {
	path := base
	for _, part := range strings.Split(relative, `\`) {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("Flash 数据目录包含重定向或非目录项：%s", part)
		}
	}
	return path, nil
}

func deleteCookieFiles(files []string, checkProcesses func() error) (int, error) {
	if len(files) == 0 {
		return 0, nil
	}
	// Open every file exclusively before deleting any of them.
	handles := make([]windows.Handle, 0, len(files))
	defer func() {
		for i := len(handles) - 1; i >= 0; i-- {
			windows.CloseHandle(handles[i])
		}
	}()
	for _, file := range files {
		handle, err := openCookieForDeletion(file)
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return 0, fmt.Errorf("待清理的文件仍在使用。请关闭 Flash 程序后重试")
		}
		if err != nil {
			return 0, fmt.Errorf("无法打开待清理的文件：%w", err)
		}
		handles = append(handles, handle)
	}
	if err := checkProcesses(); err != nil {
		return 0, err
	}
	deleteFile := byte(1)
	for index, handle := range handles {
		if err := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, 1); err != nil {
			return index, fmt.Errorf("已清理 %d 个文件，清理中断：%w", index, err)
		}
	}
	return len(handles), nil
}

func openCookieForDeletion(file string) (windows.Handle, error) {
	path := file
	if strings.HasPrefix(path, `\\`) {
		path = `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	} else {
		path = `\\?\` + path
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, windows.DELETE|windows.FILE_READ_ATTRIBUTES, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	if err := checkCookieHandle(handle, path); err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

func checkCookieHandle(handle windows.Handle, path string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	const unsupported = windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_READONLY
	if info.FileAttributes&unsupported != 0 || info.NumberOfLinks != 1 {
		return fmt.Errorf("待清理的文件是链接、只读文件或不受支持的类型")
	}
	// Recheck the full path on the locked handle in case a parent directory
	// was redirected after the scan.
	resolved := make([]uint16, len(path)+1)
	length, err := windows.GetFinalPathNameByHandle(handle, &resolved[0], uint32(len(resolved)), 0)
	if err != nil {
		return err
	}
	if length >= uint32(len(resolved)) || !strings.EqualFold(windows.UTF16ToString(resolved), path) {
		return fmt.Errorf("待清理的文件路径已重定向")
	}
	return nil
}
