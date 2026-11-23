package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Fixed public DNS endpoints provide a real response baseline. No hostnames
// are resolved locally; each query uses a random reserved .invalid name.
func runPublicWire(network, address string) {
	working, _ := os.Getwd()
	executable, _ := os.Executable()
	validImage := strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-probe.exe`) || strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\control\proxy-harbor-p0-probe.exe`)
	validEndpoint := (network == "tcp4" || network == "udp4") && address == "1.1.1.1:53" || (network == "tcp6" || network == "udp6") && address == "[2606:4700:4700::1111]:53"
	if !validImage || !validEndpoint || !strings.EqualFold(filepath.Clean(working), `C:\P0Lab`) || os.Getenv("PROXY_HARBOR_P0_GUEST") != "offline-lab" {
		emit(false, "public wire fixture requires exact guest and fixed endpoints")
		return
	}
	result := map[string]any{"publicWire": true, "success": false, "network": network, "endpoint": address, "accessDenied": false}
	finish := func(err error) {
		if err != nil {
			result["error"] = err.Error()
			result["accessDenied"] = errors.Is(err, syscall.Errno(10013))
		}
		json.NewEncoder(os.Stdout).Encode(result)
		if result["success"] != true {
			os.Exit(1)
		}
	}
	var nonce [10]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		finish(err)
		return
	}
	query := []byte{nonce[0], nonce[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	label := "p0-" + hex.EncodeToString(nonce[2:])
	query = append(query, byte(len(label)))
	query = append(query, label...)
	query = append(query, 7)
	query = append(query, "invalid"...)
	query = append(query, 0, 0, 1, 0, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		finish(err)
		return
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	frame := query
	if strings.HasPrefix(network, "tcp") {
		frame = append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
	}
	if _, err := connection.Write(frame); err != nil {
		finish(err)
		return
	}
	var reply []byte
	if strings.HasPrefix(network, "tcp") {
		var size [2]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			finish(err)
			return
		}
		length := binary.BigEndian.Uint16(size[:])
		if length < 12 || length > 4096 {
			finish(errors.New("public DNS response length invalid"))
			return
		}
		reply = make([]byte, int(length))
		_, err = io.ReadFull(connection, reply)
	} else {
		reply = make([]byte, 4096)
		var count int
		count, err = connection.Read(reply)
		reply = reply[:count]
	}
	if err != nil {
		finish(err)
		return
	}
	if len(reply) < 12 || reply[0] != query[0] || reply[1] != query[1] || reply[2]&0x80 == 0 {
		finish(errors.New("public DNS response invalid"))
		return
	}
	result["success"] = true
	result["responseCode"] = int(reply[3] & 15)
	finish(nil)
}
