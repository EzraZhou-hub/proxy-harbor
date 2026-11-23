//go:build windows

package session

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

func lockedFile(path string, access, share, disposition uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, access, share, nil, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
func openHelper(path string) (*os.File, error) {
	return lockedFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, windows.OPEN_EXISTING)
}
func startLock(path string) (*os.File, error) {
	return lockedFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, windows.OPEN_ALWAYS)
}

func privateDirectory(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func currentCreation() (uint64, error) {
	return processCreation(windows.CurrentProcess())
}
func processCreation(handle windows.Handle) (uint64, error) {
	var c, e, k, u windows.Filetime
	err := windows.GetProcessTimes(handle, &c, &e, &k, &u)
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), err
}

func startTakeoverWorker(helper, folder string) (*os.Process, error) {
	cmd := exec.Command(helper, "claude-takeover-worker", folder)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go cmd.Wait()
	pid := uint32(cmd.Process.Pid)
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err == nil {
		var created uint64
		created, err = processCreation(handle)
		windows.CloseHandle(handle)
		if err == nil {
			record := []byte(fmt.Sprintf("%d %d\n", pid, created))
			err = os.WriteFile(filepath.Join(folder, "takeover-worker.txt"), record, 0600)
		}
	}
	if err != nil {
		cmd.Process.Kill()
		return nil, err
	}
	return cmd.Process, nil
}
func processAlive(pid uint32) bool {
	if pid == 0 {
		return true
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	result, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && result == uint32(windows.WAIT_TIMEOUT)
}
func processMatches(pid uint32, created uint64) bool {
	if pid == 0 || created == 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(handle, &c, &e, &k, &u) != nil {
		return false
	}
	actual := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
	result, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && result == uint32(windows.WAIT_TIMEOUT) && actual == created
}
func elevate(helper, action, folder string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(helper)
	parameters, _ := windows.UTF16PtrFromString(action + " " + syscall.EscapeArg(folder))
	result, _, _ := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(parameters)), 0, 0)
	if result <= 32 {
		return fmt.Errorf("无法启动会话守护程序，管理员授权可能被取消（%d）", result)
	}
	return nil
}
