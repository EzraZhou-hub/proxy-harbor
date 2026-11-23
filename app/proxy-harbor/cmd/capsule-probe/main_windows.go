//go:build windows

// Generic guest fixture for inherited AppContainer identity, not an app launcher.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func identity(userCapsule bool) (string, bool) {
	// The AppContainer can use the process-token pseudo handle even when a
	// separate OpenProcessToken access check is denied by its process DACL.
	token := windows.GetCurrentProcessToken()
	if userCapsule {
		user, err := token.GetTokenUser()
		if err != nil {
			return "", false
		}
		return user.User.Sid.String(), true
	}
	var data [256]byte
	var size uint32
	var container uint32
	if windows.GetTokenInformation(token, 29, (*byte)(unsafe.Pointer(&container)), 4, &size) != nil || container != 1 {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"identityError": "container_class", "value": container})
		return "", false
	}
	if windows.GetTokenInformation(token, 30, &data[0], uint32(len(data)), &size) != nil || *(*uint32)(unsafe.Pointer(&data[0])) != 0 {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"identityError": "capabilities"})
		return "", false
	}
	if windows.GetTokenInformation(token, 31, &data[0], uint32(len(data)), &size) != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"identityError": "sid"})
		return "", false
	}
	sid := *(**windows.SID)(unsafe.Pointer(&data[0]))
	if sid == nil {
		return "", false
	}
	return sid.String(), true
}
func main() {
	proxy := flag.String("proxy", "127.0.0.1:9", "")
	leaf := flag.Bool("leaf", false, "")
	network := flag.String("network", "tcp4", "")
	address := flag.String("address", "127.0.0.1:9", "")
	hold := flag.Bool("hold", false, "")
	userCapsule := flag.Bool("user-capsule", false, "")
	flag.Parse()
	image, _ := os.Executable()
	if !strings.HasPrefix(strings.ToLower(image), `c:\program files\proxyharborp0capsule\`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		os.Exit(2)
	}
	sid, container := identity(*userCapsule)
	if !container {
		os.Exit(3)
	}
	enc := json.NewEncoder(os.Stdout)
	if *hold {
		enc.Encode(map[string]any{"heldChild": true, "pid": os.Getpid(), "sid": sid})
		time.Sleep(90 * time.Second)
		return
	}
	direct := func(network, address string) map[string]any {
		endpoint, err := netip.ParseAddrPort(address)
		if err != nil || (!endpoint.Addr().IsLoopback() && address != "1.1.1.1:53") {
			os.Exit(2)
		}
		switch network {
		case "tcp4", "tcp6", "udp4", "udp6":
		default:
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err == nil {
			conn.SetDeadline(time.Now().Add(time.Second))
			_, err = conn.Write([]byte("P0"))
			if err == nil {
				var reply [2]byte
				_, err = io.ReadFull(conn, reply[:])
			}
			conn.Close()
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		return map[string]any{"success": err == nil, "accessDenied": errors.Is(err, syscall.Errno(10013)), "detail": detail, "sid": sid, "leaf": true, "pid": os.Getpid()}
	}
	if *leaf {
		enc.Encode(direct(*network, *address))
		return
	}
	enc.Encode(map[string]any{"ready": true, "sid": sid, "pid": os.Getpid()})
	var held net.Conn
	defer func() {
		if held != nil {
			held.Close()
		}
	}()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var r struct{ Action, Network, Address string }
		if json.Unmarshal(scanner.Bytes(), &r) != nil {
			os.Exit(2)
		}
		if r.Action == "exit" {
			return
		}
		if r.Action == "crash" {
			os.Exit(7)
		}
		if r.Action == "child" {
			// This image has no per-path WFP rule. Its first operation is the attempted
			// network send; no parent monitor or post-creation rule installation runs.
			cmd := exec.Command(`C:\Program Files\ProxyHarborP0Capsule\unlisted.exe`, "-leaf", "-network", r.Network, "-address", r.Address)
			if *userCapsule {
				cmd.Args = append(cmd.Args, "-user-capsule")
			}
			output, err := cmd.Output()
			var result map[string]any
			json.Unmarshal(output, &result)
			if err != nil || result == nil {
				result = map[string]any{"fixtureError": true}
			}
			result["action"] = "child"
			enc.Encode(result)
			continue
		}
		if r.Action == "direct" {
			result := direct(r.Network, r.Address)
			result["action"] = "direct"
			enc.Encode(result)
			continue
		}
		var err error
		if r.Action == "proxy" {
			endpoint, e := netip.ParseAddrPort(*proxy)
			if e != nil {
				os.Exit(2)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			transport := engine.Upstream{Profile: domain.ProxyProfile{Name: "capsule fixture", Protocol: "socks5", Host: endpoint.Addr().String(), Port: int(endpoint.Port())}}
			var conn net.Conn
			conn, err = transport.DialContext(ctx, "tcp4", "capsule.proxy-harbor.invalid:443")
			cancel()
			if err == nil {
				if held != nil {
					held.Close()
				}
				held = conn
			}
		}
		if r.Action == "proxy" || r.Action == "held" {
			if held == nil {
				err = io.ErrClosedPipe
			} else if err == nil {
				held.SetDeadline(time.Now().Add(time.Second))
				_, err = held.Write([]byte("P0"))
				if err == nil {
					var p [2]byte
					_, err = io.ReadFull(held, p[:])
					if err == nil && string(p[:]) != "P0" {
						err = io.ErrUnexpectedEOF
					}
				}
			}
		} else {
			os.Exit(2)
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		enc.Encode(map[string]any{"action": r.Action, "success": err == nil, "detail": detail, "sid": sid, "port": strconv.Itoa(0)})
	}
}
