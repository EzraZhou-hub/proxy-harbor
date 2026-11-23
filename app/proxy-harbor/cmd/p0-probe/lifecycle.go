package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"strings"
	"time"
)

// Loopback-only, disposable-guest protocol; no arbitrary external destination.
func runLifecycle() {
	cwd, _ := os.Getwd()
	if !strings.EqualFold(cwd, `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.Encode(map[string]any{"ready": true, "container": verifiedAppContainer()})
	var held net.Conn
	defer func() {
		if held != nil {
			held.Close()
		}
	}()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		var request struct{ Action, Network, Address string }
		if json.Unmarshal(scanner.Bytes(), &request) != nil {
			os.Exit(2)
		}
		if request.Action == "exit" {
			return
		}
		if request.Action == "crash" {
			os.Exit(7)
		}
		if request.Action == "public" {
			if request.Network != "tcp4" {
				os.Exit(2)
			}
			image, _ := os.Executable()
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			output, _ := exec.CommandContext(ctx, image, "-public-wire", "-network", "tcp4", "-address", "1.1.1.1:53").Output()
			cancel()
			record := map[string]any{}
			json.Unmarshal(output, &record)
			record["action"] = "public"
			encoder.Encode(record)
			continue
		}
		var err error
		if request.Action == "echo" {
			if held == nil {
				err = io.ErrClosedPipe
			} else {
				held.SetDeadline(time.Now().Add(time.Second))
				_, err = held.Write([]byte("p0"))
				if err == nil {
					var reply [2]byte
					_, err = io.ReadFull(held, reply[:])
					if err == nil && string(reply[:]) != "p0" {
						err = io.ErrUnexpectedEOF
					}
				}
			}
		} else {
			endpoint, e := netip.ParseAddrPort(request.Address)
			if e != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() < 1024 {
				os.Exit(2)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			var connection net.Conn
			if request.Action == "proxy" {
				transport := engine.Upstream{Profile: domain.ProxyProfile{Name: "lifecycle fixture", Protocol: "socks5", Host: endpoint.Addr().String(), Port: int(endpoint.Port())}}
				connection, err = transport.DialContext(ctx, "tcp4", "lifecycle.p0-dns-audit.invalid:443")
			} else if request.Action == "direct" && (request.Network == "tcp4" || request.Network == "tcp6" || request.Network == "udp4" || request.Network == "udp6") {
				connection, err = (&net.Dialer{}).DialContext(ctx, request.Network, request.Address)
				if err == nil {
					connection.SetDeadline(time.Now().Add(time.Second))
					_, err = connection.Write([]byte("p0"))
					if err == nil {
						var reply [2]byte
						_, err = io.ReadFull(connection, reply[:])
						if err == nil && string(reply[:]) != "p0" {
							err = io.ErrUnexpectedEOF
						}
					}
				}
			} else {
				cancel()
				os.Exit(2)
			}
			cancel()
			if request.Action == "proxy" && err == nil {
				if held != nil {
					held.Close()
				}
				held = connection
			} else if connection != nil {
				connection.Close()
			}
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		encoder.Encode(map[string]any{"action": request.Action, "success": err == nil, "detail": detail})
	}
}
