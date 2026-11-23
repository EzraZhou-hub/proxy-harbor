package session

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
)

// Pin the Windows desktop guardian and its approved Claude Desktop scope.
//
//go:embed approved_guardian.json
var admissionRecord []byte

type guardianAdmission struct {
	ClaudeDesktop  bool   `json:"claudeDesktop"`
	ClaudeTakeover bool   `json:"claudeTakeover"`
	Quarantined    bool   `json:"quarantined"`
	SHA            string `json:"guardianSha256"`
}

func admission() (bool, string) {
	return parseAdmission(admissionRecord)
}

func parseAdmission(data []byte) (bool, string) {
	record := readAdmission(data)
	return record.ClaudeDesktop, record.SHA
}

func readAdmission(data []byte) guardianAdmission {
	var record guardianAdmission
	if json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &record) != nil || record.Quarantined || len(record.SHA) != 64 {
		return guardianAdmission{}
	}
	return record
}

func takeoverAdmitted() bool {
	return DesktopAdmitted() && readAdmission(admissionRecord).ClaudeTakeover
}
func DesktopAdmitted() bool {
	accepted, hash := admission()
	return runtime.GOOS == "windows" && runtime.GOARCH == "amd64" && accepted && hash != ""
}
func helperApproved(path string) bool {
	file, err := verifiedHelper(path)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func verifiedHelper(path string) (*os.File, error) {
	_, expected := admission()
	if expected == "" {
		return nil, errors.New("缺少守护程序指纹")
	}
	file, err := openHelper(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(file, 8*1024*1024+1))
	if err != nil || count > 8*1024*1024 || hex.EncodeToString(digest.Sum(nil)) != expected {
		file.Close()
		return nil, errors.New("守护程序指纹不匹配")
	}
	return file, nil
}

func (r *Runtime) invoke(action, folder string) error {
	file, err := verifiedHelper(r.helper)
	if err != nil {
		return err
	}
	defer file.Close()
	return elevate(r.helper, action, folder)
}
