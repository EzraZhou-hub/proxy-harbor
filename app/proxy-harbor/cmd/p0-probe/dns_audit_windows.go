package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type auditDNSRequest struct {
	Version   uint32
	Name      *uint16
	Type      uint16
	Options   uint64
	Servers   uintptr
	Interface uint32
	Callback  uintptr
	Context   uintptr
}

type auditDNSAnswer struct {
	Version  uint32
	Status   uint32
	Options  uint64
	Records  *windows.DNSRecord
	Reserved uintptr
}

type auditDNSEntry struct {
	Status    uint32 `json:"status"`
	Address   string `json:"address,omitempty"`
	Records   bool   `json:"records"`
	Callbacks int32  `json:"callbacks"`
	Connected bool   `json:"connected"`
}

// This fixture never changes machine DNS. A custom server, when requested,
// is always the isolated guest's 127.0.0.1:53 observer.
func runDNSAudit(scenario, host string) {
	working, _ := os.Getwd()
	executable, _ := os.Executable()
	allowedPath := strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-probe.exe`) ||
		strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\control\proxy-harbor-p0-probe.exe`)
	label, suffix := strings.CutSuffix(host, ".p0-dns-audit.invalid")
	validName := suffix && len(label) == 16
	for _, c := range label {
		validName = validName && (c >= '0' && c <= '9' || c >= 'a' && c <= 'f')
	}
	if !allowedPath || !validName || !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		emit(false, "DNS audit requires the isolated guest, exact fixture and bounded .invalid name")
		return
	}
	name, _ := windows.UTF16PtrFromString(host)
	narrow, _ := windows.BytePtrFromString(host)
	request := auditDNSRequest{Version: 1, Name: name, Type: 1}
	method := "DnsQueryEx"
	async, connect, repeats := false, false, 1
	switch scenario {
	case "w", "a", "utf8", "ex-sync", "ex-async", "repeat":
		connect = true
		async = scenario == "ex-async"
		if scenario == "repeat" {
			repeats = 2
		}
	case "w-cache-only", "ex-cache-only":
		request.Options = 0x10
	case "w-return-message", "ex-return-message":
		request.Options = 0x200
	case "w-tcp-only":
		request.Options = 2
	case "a-multicast-only":
		request.Options = 0x400
	case "ex-unknown-option":
		request.Options = 1 << 63
	case "ex-interface":
		request.Interface = 1
	case "ex-version3":
		request.Version = 3
	case "ex-aaaa":
		request.Type = 28
	case "ex-txt":
		request.Type = 16
	case "ex-https":
		request.Type = 65
	case "ex-async-cache-only":
		async = true
		request.Options = 0x10
	case "ex-custom-server":
		request.Options = 0x108
	case "ex-system":
		request.Options = 0x108
	default:
		emit(false, "unknown DNS audit scenario")
		return
	}
	if strings.HasPrefix(scenario, "w") {
		method = "DnsQuery_W"
	}
	if strings.HasPrefix(scenario, "a-") || scenario == "a" {
		method = "DnsQuery_A"
	}
	if scenario == "utf8" {
		method = "DnsQuery_UTF8"
	}
	// Packed DNS_ADDR_ARRAY header (32 bytes) plus one DNS_ADDR (64 bytes).
	var servers [96]byte
	// Match Microsoft's DNSAsyncQuery sample: array Family and socket port
	// remain zero; DNS selects its standard port. Only MaxCount/AddrCount and
	// the socket family/address are populated.
	servers[0], servers[4] = 1, 1
	servers[32], servers[36], servers[39] = 2, 127, 1
	if scenario == "ex-custom-server" {
		request.Servers = uintptr(unsafe.Pointer(&servers[0]))
	}
	module := windows.NewLazySystemDLL("dnsapi.dll")
	var entries []auditDNSEntry
	for range repeats {
		answer := auditDNSAnswer{Version: 1}
		var records *windows.DNSRecord
		var callbacks atomic.Int32
		completed := make(chan struct{}, 2)
		var cancel [32]byte
		if async {
			request.Callback = syscall.NewCallback(func(_ uintptr, _ uintptr) uintptr {
				callbacks.Add(1)
				select {
				case completed <- struct{}{}:
				default:
				}
				return 0
			})
		}
		var status uintptr
		if method == "DnsQueryEx" {
			status, _, _ = module.NewProc(method).Call(uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&answer)), uintptr(unsafe.Pointer(&cancel)))
			if status == 9506 {
				select {
				case <-completed:
					status = uintptr(answer.Status)
				case <-time.After(2 * time.Second):
					emit(false, "DNS audit callback timed out")
					return
				}
			}
			records = answer.Records
		} else {
			namePointer := uintptr(unsafe.Pointer(name))
			if method != "DnsQuery_W" {
				namePointer = uintptr(unsafe.Pointer(narrow))
			}
			status, _, _ = module.NewProc(method).Call(namePointer, uintptr(request.Type), uintptr(request.Options), 0, uintptr(unsafe.Pointer(&records)), 0)
		}
		runtime.KeepAlive(name)
		runtime.KeepAlive(narrow)
		runtime.KeepAlive(servers)
		if async {
			time.Sleep(30 * time.Millisecond)
		}
		entry := auditDNSEntry{Status: uint32(status), Records: records != nil, Callbacks: callbacks.Load()}
		if records != nil {
			if records.Type == 1 {
				entry.Address = net.IP(append([]byte(nil), records.Data[:4]...)).String()
			}
			windows.DnsRecordListFree(records, 1)
		}
		if connect && status == 0 && entry.Address != "" {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(entry.Address, "443"))
			cancel()
			if err == nil {
				conn.SetDeadline(time.Now().Add(time.Second))
				_, err = conn.Write([]byte("P0"))
				var reply [2]byte
				if err == nil {
					_, err = io.ReadFull(conn, reply[:])
				}
				entry.Connected = err == nil && string(reply[:]) == "P0"
				conn.Close()
			}
		}
		entries = append(entries, entry)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"success": true, "scenario": scenario, "name": host, "pid": os.Getpid(), "entries": entries})
}
