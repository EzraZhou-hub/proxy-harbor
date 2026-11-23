package main

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errAsyncDNSBlocked = errors.New("unsupported async DNS blocked")

// Native ADDRINFOEXA/W prefix. Typed pointers keep the returned allocation
// separate from integer handles and avoid retaining an unsafe uintptr.
type fixtureAddrInfo struct {
	Flags     int32
	Family    int32
	Socktype  int32
	Protocol  int32
	Addrlen   uintptr
	Canonname *uint16
	Addr      *windows.RawSockaddrInet4
}

// Only main's exact guest/path/target allowlist can reach this function.
func resolveTransparent(api, endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	name, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return "", err
	}
	if api == "dnsquery-raw-blocked" {
		raw := windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsQueryRaw")
		if err := raw.Find(); err != nil {
			return "", err
		}
		// The strict entry must reject before validating or dispatching data.
		status, _, _ := raw.Call(0, 0)
		if status == 50 {
			return "", errAsyncDNSBlocked
		}
		return "", fmt.Errorf("raw DNS entry was not confined: %d", status)
	}
	var address net.IP
	if strings.HasPrefix(api, "getaddrinfoex-") {
		var data windows.WSAData
		if err := windows.WSAStartup(0x202, &data); err != nil {
			return "", err
		}
		defer windows.WSACleanup()
		wide := api != "getaddrinfoex-a"
		method, free := "GetAddrInfoExW", "FreeAddrInfoExW"
		if !wide {
			method, free = "GetAddrInfoExA", "FreeAddrInfoEx"
		}
		var result *fixtureAddrInfo
		module := windows.NewLazySystemDLL("ws2_32.dll")
		var overlap windows.Overlapped
		var async uintptr
		if api == "getaddrinfoex-async" {
			async = uintptr(unsafe.Pointer(&overlap))
		}
		namePtr := uintptr(unsafe.Pointer(name))
		var narrow *byte
		if !wide {
			narrow, err = windows.BytePtrFromString(host)
			if err != nil {
				return "", err
			}
			namePtr = uintptr(unsafe.Pointer(narrow))
		}
		status, _, _ := module.NewProc(method).Call(namePtr, 0, 12, 0, 0, uintptr(unsafe.Pointer(&result)), 0, async, 0, 0)
		runtime.KeepAlive(name)
		runtime.KeepAlive(narrow)
		if api == "getaddrinfoex-async" {
			if status == 10045 && result == nil {
				return "", errAsyncDNSBlocked
			}
			return "", fmt.Errorf("async resolver was not rejected: %d", status)
		}
		if status != 0 {
			return "", fmt.Errorf("%s status %d", method, status)
		}
		defer module.NewProc(free).Call(uintptr(unsafe.Pointer(result)))
		if result == nil || result.Family != windows.AF_INET {
			return "", errors.New("missing IPv4 resolver result")
		}
		if result.Addr == nil || result.Addrlen < 16 {
			return "", errors.New("incomplete IPv4 resolver result")
		}
		address = net.IP(result.Addr.Addr[:])
	} else {
		module := windows.NewLazySystemDLL("dnsapi.dll")
		var records *windows.DNSRecord
		if api == "dnsqueryex-sync" || api == "dnsqueryex-async" || api == "dnsqueryex-cancel" {
			type request struct {
				Version   uint32
				Name      *uint16
				Type      uint16
				Options   uint64
				Servers   uintptr
				Interface uint32
				Callback  uintptr
				Context   uintptr
			}
			type result struct {
				Version  uint32
				Status   uint32
				Options  uint64
				Records  *windows.DNSRecord
				Reserved uintptr
			}
			query := request{Version: 1, Name: name, Type: 1}
			answer := result{Version: 1}
			async := api == "dnsqueryex-async" || api == "dnsqueryex-cancel"
			completed := make(chan struct{}, 1)
			var callbacks atomic.Int32
			var cancel [32]byte
			if async {
				query.Context = 0x5030
				query.Callback = syscall.NewCallback(func(context uintptr, _ uintptr) uintptr {
					if context != 0x5030 {
						return 0
					}
					callbacks.Add(1)
					completed <- struct{}{}
					return 0
				})
			}
			status, _, _ := module.NewProc("DnsQueryEx").Call(uintptr(unsafe.Pointer(&query)), uintptr(unsafe.Pointer(&answer)), uintptr(unsafe.Pointer(&cancel)))
			if async {
				if status != 9506 {
					return "", fmt.Errorf("async DNS did not return pending: %d", status)
				}
				if api == "dnsqueryex-cancel" {
					module.NewProc("DnsCancelQuery").Call(uintptr(unsafe.Pointer(&cancel)))
				}
				select {
				case <-completed:
				case <-time.After(time.Second):
					return "", errors.New("async DNS callback timed out")
				}
				if callbacks.Load() != 1 {
					return "", errors.New("unexpected DNS callback count")
				}
				status = uintptr(answer.Status)
				if api == "dnsqueryex-cancel" {
					if answer.Records != nil {
						windows.DnsRecordListFree(answer.Records, 1)
					}
					if status == 0 || status == 995 {
						return "", errAsyncDNSBlocked
					}
					return "", fmt.Errorf("unexpected cancellation result: %d", status)
				}
			}

			if status != 0 {
				return "", fmt.Errorf("DnsQueryEx status %d", status)
			}
			records = answer.Records
		} else if api == "dnsquery-w" {
			if err := windows.DnsQuery(host, 1, 8, nil, &records, nil); err != nil {
				return "", err
			}
		} else if api == "dnsquery-a" || api == "dnsquery-utf8" {
			method := "DnsQuery_A"
			if api == "dnsquery-utf8" {
				method = "DnsQuery_UTF8"
			}
			narrow, err := windows.BytePtrFromString(host)
			if err != nil {
				return "", err
			}
			status, _, _ := module.NewProc(method).Call(uintptr(unsafe.Pointer(narrow)), 1, 8, 0, uintptr(unsafe.Pointer(&records)), 0)
			if status != 0 {
				return "", fmt.Errorf("%s status %d", method, status)
			}
		} else {
			return "", errors.New("unsupported fixture resolver API")
		}
		if records == nil {
			return "", errors.New("DNS API returned no records")
		}
		defer windows.DnsRecordListFree(records, 1)
		if records.Type != 1 {
			return "", errors.New("DNS API did not return an A record")
		}
		address = net.IP(append([]byte(nil), records.Data[:4]...))
	}
	return net.JoinHostPort(address.String(), port), nil
}
