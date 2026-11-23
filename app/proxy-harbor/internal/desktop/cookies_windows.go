//go:build windows && !server

package desktop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const chromeUserData = `Google\Chrome\User Data`
const roamingFlashObjects = `Macromedia\Flash Player\#SharedObjects`
const chromeFlashObjects = `Pepper Data\Shockwave Flash\WritableRoot\#SharedObjects`

var chromeProfileName = regexp.MustCompile(`(?i)^(Default|Profile [0-9]+)$`)
var cookieCleanupMu sync.Mutex

func (s *DesktopService) CookieCleanupAvailable() bool { return true }

func (s *DesktopService) ClearBrowserCookies(kind string, confirmed bool) (int, error) {
	if !confirmed {
		return 0, fmt.Errorf("请先确认清理范围")
	}
	if kind != "chrome" && kind != "flash" {
		return 0, fmt.Errorf("未知的清理类型")
	}
	cookieCleanupMu.Lock()
	defer cookieCleanupMu.Unlock()
	if err := checkCookieProcesses(kind); err != nil {
		return 0, err
	}
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return 0, fmt.Errorf("无法定位当前用户的本地应用数据目录：%w", err)
	}
	var roaming string
	if kind == "flash" {
		roaming, err = windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, windows.KF_FLAG_DONT_VERIFY)
		if err != nil {
			return 0, fmt.Errorf("无法定位当前用户的漫游应用数据目录：%w", err)
		}
	}
	files, err := browserCookieFiles(local, roaming, kind)
	if err != nil {
		return 0, fmt.Errorf("无法检查待清理的文件：%w", err)
	}
	return deleteCookieFiles(files, func() error { return checkCookieProcesses(kind) })
}

func checkCookieProcesses(kind string) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("无法检查浏览器运行状态：%w", err)
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if name == "chrome.exe" {
			return fmt.Errorf("请完全退出 Google Chrome（包括后台进程），然后重试")
		}
		if kind == "flash" && (name == "flashplayer.exe" || strings.HasPrefix(name, "flashplayerplugin")) {
			return fmt.Errorf("请关闭仍在运行的 Flash 程序，然后重试")
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("无法检查浏览器运行状态：%w", err)
	}
	return nil
}

func browserCookieFiles(local, roaming, kind string) ([]string, error) {
	var files []string
	if kind == "flash" {
		if err := collectFlashObjects(roaming, roamingFlashObjects, &files); err != nil {
			return nil, err
		}
	}
	dataDir, err := cookieDirectory(local, chromeUserData)
	if err != nil || dataDir == "" {
		return files, err
	}
	profiles, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		if !chromeProfileName.MatchString(profile.Name()) {
			continue
		}
		if kind == "flash" {
			if err := collectFlashObjects(dataDir, filepath.Join(profile.Name(), chromeFlashObjects), &files); err != nil {
				return nil, err
			}
			continue
		}
		for _, dir := range []string{profile.Name(), filepath.Join(profile.Name(), "Network")} {
			path, err := cookieDirectory(dataDir, dir)
			if err != nil {
				return nil, err
			}
			if path == "" {
				continue
			}
			for _, name := range []string{"Cookies", "Cookies-wal", "Cookies-shm", "Cookies-journal"} {
				file := filepath.Join(path, name)
				info, err := os.Lstat(file)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return nil, err
				}
				if !info.Mode().IsRegular() {
					return nil, fmt.Errorf("Chrome Cookie 文件类型不受支持")
				}
				files = append(files, file)
			}
		}
	}
	return files, nil
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
			return "", fmt.Errorf("浏览器数据目录包含重定向或非目录项：%s", part)
		}
	}
	return path, nil
}

func collectFlashObjects(base, relative string, files *[]string) error {
	path, err := cookieDirectory(base, relative)
	if err != nil || path == "" {
		return err
	}
	return filepath.WalkDir(path, func(file string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() && strings.EqualFold(filepath.Ext(file), ".sol") {
			*files = append(*files, file)
		}
		return err
	})
}

func deleteCookieFiles(files []string, checkProcesses func() error) (int, error) {
	if len(files) == 0 {
		return 0, nil
	}
	// Lock the database and its sidecars before deleting any of them. Close
	// the handles in reverse order so SQLite cannot reopen the database while
	// its sidecars are still pending deletion.
	handles := make([]windows.Handle, 0, len(files))
	defer func() {
		for i := len(handles) - 1; i >= 0; i-- {
			windows.CloseHandle(handles[i])
		}
	}()
	for _, file := range files {
		handle, err := openCookieForDeletion(file)
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return 0, fmt.Errorf("待清理的文件仍在使用。请关闭浏览器或 Flash 程序后重试")
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
