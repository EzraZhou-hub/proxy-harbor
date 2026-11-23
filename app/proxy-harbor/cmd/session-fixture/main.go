// Disposable guest client. It accepts only loopback echo tests and never
// starts installed applications or reads account data.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"proxyharbor/internal/domain"
	"proxyharbor/internal/engine"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// This stand-in holds two CONNECT streams inside the offline Windows guest.
// Its parent test independently observes when both streams open and close.
func runDesktopClientFixture() {
	cwd, err := os.Getwd()
	if err != nil || !strings.HasPrefix(strings.ToLower(cwd), `c:\users\ph_`) ||
		os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		os.Exit(2)
	}
	proxy := os.Getenv("HTTPS_PROXY")
	address, err := netip.ParseAddrPort(strings.TrimPrefix(proxy, "http://"))
	if err != nil || address.Addr() != netip.MustParseAddr("127.0.0.1") ||
		proxy != "http://"+address.String() || os.Getenv("HTTP_PROXY") != proxy ||
		os.Getenv("ALL_PROXY") != proxy || os.Getenv("NO_PROXY") != "" {
		os.Exit(2)
	}
	var held []net.Conn
	var control *bufio.Reader
	for _, host := range []string{"first.p0.invalid", "unlisted.p0.invalid"} {
		c, err := net.DialTimeout("tcp4", address.String(), 3*time.Second)
		if err != nil {
			os.Exit(3)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
		reader := bufio.NewReader(c)
		status, readErr := reader.ReadString('\n')
		if err != nil || readErr != nil || status != "HTTP/1.1 200 Connection Established\r\n" {
			os.Exit(3)
		}
		if end, err := reader.ReadString('\n'); err != nil || end != "\r\n" {
			os.Exit(3)
		}
		if control == nil {
			control = reader
		}
		c.SetDeadline(time.Time{})
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	line, err := control.ReadString('\n')
	if err != nil {
		return
	}
	target, err := netip.ParseAddrPort(strings.TrimSpace(line))
	if err != nil || target.Addr() != address.Addr() || target.Port() == address.Port() {
		os.Exit(4)
	}
	if c, err := net.DialTimeout("tcp4", target.String(), 2*time.Second); err == nil {
		c.Close()
	}
	time.Sleep(time.Minute) // Only the guardian should end this client.
}

func main() {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "--user-data-dir=") {
		runDesktopClientFixture()
		return
	}
	folder := flag.String("session-fixture", "", "guest test directory")
	port := flag.Int("proxy-port", 10808, "fixture port")
	child := flag.Bool("child", false, "child lifetime fixture")
	ownedProfile := flag.Bool("owned-profile", false, "new guest account profile only")
	firstNetwork := flag.String("first-network", "", "guest first-packet probe")
	firstAddress := flag.String("first-address", "", "guest loopback observer")
	bindOnly := flag.String("bind-only", "", "guest loopback listener probe")
	parentHold := flag.Bool("parent-hold", false, "guest desktop lifetime fixture")
	flag.Parse()
	cwd, _ := os.Getwd()
	if strings.HasPrefix(strings.ToLower(*folder), `c:\p0lab\`) && !*child {
		diagnostic, _ := json.Marshal(map[string]any{"cwd": cwd, "marker": os.Getenv("PROXY_HARBOR_P0_GUEST"), "pid": os.Getpid()})
		os.WriteFile(filepath.Join(*folder, "fixture-startup.json"), diagnostic, 0600)
	}
	valid := strings.EqualFold(cwd, `C:\P0Lab`) && strings.HasPrefix(strings.ToLower(*folder), `c:\p0lab\`)
	if *ownedProfile {
		valid = strings.HasPrefix(strings.ToLower(cwd), `c:\users\ph_`) && strings.EqualFold(cwd, *folder) && filepath.Clean(cwd) == cwd
	}
	if !valid || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		os.Exit(2)
	}
	if *bindOnly != "" {
		endpoint, err := netip.ParseAddrPort(*bindOnly)
		if err != nil || !endpoint.Addr().IsLoopback() {
			os.Exit(2)
		}
		listener, err := net.Listen("tcp4", *bindOnly)
		if listener != nil {
			listener.Close()
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"success": err == nil, "detail": detail, "accessDenied": errors.Is(err, syscall.Errno(10013))})
		return
	}
	if *parentHold {
		for {
			time.Sleep(time.Second)
		}
	}
	if *child {
		if *firstNetwork != "" {
			endpoint, err := netip.ParseAddrPort(*firstAddress)
			if err != nil || !endpoint.Addr().IsLoopback() {
				os.Exit(2)
			}
			conn, err := net.DialTimeout(*firstNetwork, *firstAddress, time.Second)
			if err == nil {
				echo(conn)
				conn.Close()
			}
		}
		for {
			time.Sleep(time.Second)
		}
	}
	var held net.Conn
	defer func() {
		if held != nil {
			held.Close()
		}
	}()
	sequence := 0
	for {
		data, err := os.ReadFile(filepath.Join(*folder, "command.json"))
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var request struct {
			Sequence                 int
			Action, Network, Address string
		}
		if json.Unmarshal(data, &request) != nil || request.Sequence <= sequence {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		sequence = request.Sequence
		result := map[string]any{"sequence": sequence, "pid": os.Getpid(), "success": false}
		err = nil
		if request.Action == "bind-trusted" {
			cmd := exec.Command(`C:\P0Lab\.local\p0\bin\p0-policy-tests.exe`, "-test.run=^TestP0BindPortFixture$")
			cmd.Env = append(os.Environ(), "PH_P0_BIND_PORT="+strconv.Itoa(*port))
			out, e := cmd.CombinedOutput()
			var row map[string]any
			json.Unmarshal([]byte(strings.SplitN(string(out), "\n", 2)[0]), &row)
			if e == nil && row != nil {
				for key, value := range row {
					result[key] = value
				}
				if row["success"] != true {
					err = errors.New("Controlled bind refused")
				}
			} else {
				result["fixtureError"] = true
				result["fixtureOutput"] = string(out)
				err = errors.New("Controlled bind fixture failed")
			}
		} else if request.Action == "finish" {
			return
		} else if request.Action == "drop-held" {
			if held != nil {
				held.Close()
				held = nil
			}
		} else if request.Action == "child" || request.Action == "unknown" {
			image, _ := os.Executable()
			if request.Action == "unknown" {
				image = `C:\P0Lab\.local\p0\control\session-fixture.exe`
			}
			cmd := exec.Command(image, "-session-fixture", *folder, "-child")
			if *ownedProfile {
				cmd.Args = append(cmd.Args, "-owned-profile")
			}
			if request.Network != "" {
				cmd.Args = append(cmd.Args, "-first-network", request.Network, "-first-address", request.Address)
			}
			err = cmd.Start()
			if err == nil {
				result["childPid"] = cmd.Process.Pid
				go cmd.Wait()
			}
		} else if request.Action == "held" {
			if held == nil {
				err = io.ErrClosedPipe
			} else {
				err = echo(held)
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			var connection net.Conn
			if request.Action == "proxy" {
				u := engine.Upstream{Profile: domain.ProxyProfile{Name: "session fixture", Protocol: "http", Host: "127.0.0.1", Port: *port}}
				connection, err = u.DialContext(ctx, "tcp4", "fixture.proxy-harbor.invalid:443")
			} else if request.Action == "direct" {
				address, e := netip.ParseAddrPort(request.Address)
				if e != nil || !address.Addr().IsLoopback() {
					os.Exit(2)
				}
				connection, err = (&net.Dialer{}).DialContext(ctx, request.Network, request.Address)
			} else {
				cancel()
				os.Exit(2)
			}
			cancel()
			if err == nil {
				err = echo(connection)
			}
			if request.Action == "proxy" && err == nil {
				if held != nil {
					held.Close()
				}
				held = connection
			} else if connection != nil {
				connection.Close()
			}
		}
		result["success"] = err == nil
		if err != nil {
			result["detail"] = err.Error()
		}
		result["port"] = strconv.Itoa(*port)
		out, _ := json.Marshal(result)
		temporary := filepath.Join(*folder, "result.tmp")
		os.WriteFile(temporary, out, 0600)
		os.Rename(temporary, filepath.Join(*folder, "result.json"))
	}
}
func echo(conn net.Conn) error {
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("PH")); err != nil {
		return err
	}
	var reply [2]byte
	_, err := io.ReadFull(conn, reply[:])
	if err == nil && string(reply[:]) != "PH" {
		return io.ErrUnexpectedEOF
	}
	return err
}
