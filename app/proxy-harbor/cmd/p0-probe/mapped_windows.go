package main

import "golang.org/x/sys/windows"

// Use a real AF_INET6 socket with IPV6_V6ONLY disabled. A Go tcp6 Dialer
// rejects mapped addresses itself, which cannot measure WFP dual-stack policy.
func mappedIPv4Echo(port int) (bool, error) {
	var startup windows.WSAData
	if err := windows.WSAStartup(0x202, &startup); err != nil {
		return false, err
	}
	defer windows.WSACleanup()
	s, err := windows.Socket(windows.AF_INET6, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return false, err
	}
	defer windows.Closesocket(s)
	for _, option := range []struct{ level, name, value int }{{windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 0}, {windows.SOL_SOCKET, windows.SO_RCVTIMEO, 1000}, {windows.SOL_SOCKET, windows.SO_SNDTIMEO, 1000}} {
		if err := windows.SetsockoptInt(s, option.level, option.name, option.value); err != nil {
			return false, err
		}
	}
	address := &windows.SockaddrInet6{Port: port}
	address.Addr[10] = 255
	address.Addr[11] = 255
	address.Addr[12] = 127
	address.Addr[15] = 1
	if err := windows.Connect(s, address); err != nil {
		return false, err
	}
	payload := []byte("P0")
	buffer := windows.WSABuf{Len: 2, Buf: &payload[0]}
	var sent uint32
	if err := windows.WSASend(s, &buffer, 1, &sent, 0, nil, nil); err != nil {
		return false, err
	}
	var response [2]byte
	var read, flags uint32
	buffer.Buf = &response[0]
	if err := windows.WSARecv(s, &buffer, 1, &read, &flags, nil, nil); err != nil {
		return false, err
	}
	return sent == 2 && read == 2 && string(response[:]) == "P0", nil
}
