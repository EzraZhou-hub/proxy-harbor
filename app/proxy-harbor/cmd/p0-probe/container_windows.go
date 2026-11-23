package main

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func verifiedAppContainer() bool {
	// TOKEN_INFORMATION_CLASS values from Windows SDK winnt.h; the pinned
	// x/sys version stops its named constants before these newer classes.
	const tokenIsAppContainer, tokenCapabilities = 29, 30
	token := windows.GetCurrentProcessToken()
	var isContainer, size uint32
	if windows.GetTokenInformation(token, tokenIsAppContainer, (*byte)(unsafe.Pointer(&isContainer)), 4, &size) != nil || isContainer != 1 {
		return false
	}
	var capabilities [4096]byte
	if windows.GetTokenInformation(token, tokenCapabilities, &capabilities[0], uint32(len(capabilities)), &size) != nil || size < 4 {
		return false
	}
	return *(*uint32)(unsafe.Pointer(&capabilities[0])) == 0
}
