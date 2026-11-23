//go:build windows

// Minimal parent for invoking the pinned guardian in a disposable guest.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

func creation(process windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	err := windows.GetProcessTimes(process, &created, &exited, &kernel, &user)
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), err
}

func run() error {
	const root = `C:\P0Lab`
	cwd, _ := os.Getwd()
	if !strings.EqualFold(cwd, root) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" || len(os.Args) != 5 {
		return fmt.Errorf("disposable Claude guest required")
	}
	folder, address, relayPID, image := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	cleanImage := strings.ToLower(filepath.Clean(image))
	officialLayout := strings.HasPrefix(cleanImage, `c:\program files\windowsapps\claude_`)
	guestAppFiles := cleanImage == `c:\program files\proxyharborp0claude\app\claude.exe`
	domainProbe := cleanImage == `c:\p0lab\domain-probe.exe`
	ip := net.ParseIP(address)
	pid, err := strconv.ParseUint(relayPID, 10, 32)
	if err != nil || pid == 0 || ip.To4() == nil || ip.String() != address ||
		!strings.EqualFold(filepath.Dir(filepath.Clean(folder)), filepath.Join(root, "sessions")) ||
		(!domainProbe && (!strings.EqualFold(filepath.Base(image), "Claude.exe") || (!officialLayout && !guestAppFiles))) {
		return fmt.Errorf("invalid guest session inputs")
	}
	parentCreated, err := creation(windows.CurrentProcess())
	if err != nil {
		return err
	}
	relay, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(relay)
	relayCreated, err := creation(relay)
	if err != nil {
		return err
	}
	request := fmt.Sprintf("PH4\n%s\n%d\n%d\n10808\nclient-user\n1\n%s %d %d\n%s\n", filepath.Base(folder),
		os.Getpid(), parentCreated, address, pid, relayCreated, image)
	if err := os.WriteFile(filepath.Join(folder, "request.txt"), []byte(request), 0600); err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(root, "guardian.exe"), "start", folder)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
