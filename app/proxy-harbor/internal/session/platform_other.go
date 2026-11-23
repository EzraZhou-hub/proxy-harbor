//go:build !windows

package session

import (
	"errors"
	"os"
)

func openHelper(path string) (*os.File, error) { return os.Open(path) }
func startLock(string) (*os.File, error)       { return nil, errors.New("会话守护仅支持 Windows") }

func currentCreation() (uint64, error)     { return 0, errors.New("会话守护仅支持 Windows") }
func processAlive(uint32) bool             { return false }
func processMatches(uint32, uint64) bool   { return false }
func elevate(string, string, string) error { return errors.New("会话守护仅支持 Windows") }
func startTakeoverWorker(string, string) (*os.Process, error) {
	return nil, errors.New("Claude 账户接管仅支持 Windows")
}
func privateDirectory(string) error { return errors.New("会话守护仅支持 Windows") }
