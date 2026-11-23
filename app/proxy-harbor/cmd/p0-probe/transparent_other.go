//go:build !windows

package main

import "errors"

var errAsyncDNSBlocked = errors.New("unsupported async DNS blocked")

func resolveTransparent(string, string) (string, error) {
	return "", errors.New("Windows-only fixture API")
}

func runDNSAudit(string, string) { emit(false, "Windows-only DNS audit fixture") }
func verifiedAppContainer() bool { return false }
func mappedIPv4Echo(int) (bool, error) {
	return false, errors.New("Windows-only mapped socket fixture")
}
