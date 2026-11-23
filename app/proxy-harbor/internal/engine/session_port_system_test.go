//go:build p0system && windows

package engine

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestP0BindPortFixture(t *testing.T) {
	port := os.Getenv("PH_P0_BIND_PORT")
	if port == "" {
		t.Skip("Fixed child fixture entry only")
	}
	number, e := strconv.Atoi(port)
	image, _ := os.Executable()
	cwd, _ := os.Getwd()
	if e != nil || number < 1024 || number > 65535 || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" || !strings.EqualFold(image, `C:\P0Lab\.local\p0\bin\p0-policy-tests.exe`) || !strings.HasPrefix(strings.ToLower(cwd), `c:\users\ph_`) {
		t.Fatal("Guest child scope required")
	}
	os.WriteFile(filepath.Join(cwd, "bind-stage.json"), []byte(`{"stage":"binding"}`), 0600)
	listener, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if listener != nil {
		listener.Close()
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"success": err == nil, "accessDenied": errors.Is(err, syscall.Errno(10013)), "detail": detail, "sid": user.User.Sid.String()})
	os.WriteFile(filepath.Join(cwd, "bind-stage.json"), []byte(`{"stage":"finished"}`), 0600)
}

func pauseOwnedGuestGuardian(t *testing.T, pid, supervisorThread uint32) func() {
	t.Helper()
	recoveryGuest(t)
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(process)
	var path [512]uint16
	size := uint32(len(path))
	if windows.QueryFullProcessImageName(process, 0, &path[0], &size) != nil || !strings.EqualFold(windows.UTF16ToString(path[:]), `C:\P0Lab\.local\p0\bin\proxy-harbor-guardian.exe`) {
		t.Fatal("Refuse to suspend a non-fixture process")
	}
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(snapshot)
	suspend := windows.NewLazySystemDLL("kernel32.dll").NewProc("SuspendThread")
	threadPID := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIdOfThread")
	handles := []windows.Handle{}
	resumed := false
	resume := func() {
		if resumed {
			return
		}
		resumed = true
		for _, handle := range handles {
			windows.ResumeThread(handle)
			windows.CloseHandle(handle)
		}
	}
	t.Cleanup(resume)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for e := windows.Thread32First(snapshot, &entry); e == nil; e = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid || entry.ThreadID != supervisorThread {
			continue
		}
		handle, e := windows.OpenThread(windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_LIMITED_INFORMATION, false, entry.ThreadID)
		if e != nil {
			resume()
			t.Fatal(e)
		}
		owner, _, _ := threadPID.Call(uintptr(handle))
		if uint32(owner) != pid {
			windows.CloseHandle(handle)
			resume()
			t.Fatal("Thread owner changed")
		}
		previous, _, err := suspend.Call(uintptr(handle))
		if uint32(previous) == 0xffffffff {
			windows.CloseHandle(handle)
			resume()
			t.Fatal(err)
		}
		handles = append(handles, handle)
	}
	if len(handles) == 0 {
		resume()
		t.Fatal("No fixture threads suspended")
	}
	return resume
}
