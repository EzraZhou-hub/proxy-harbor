package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"proxyharbor/internal/domain"
	"strconv"
	"strings"
	"time"
)

type ProxyEndpoint struct {
	IPv4    string
	PID     uint32
	Created uint64
	Port    int
}

func validExit(ip string) bool {
	return domain.ValidateExpectedProxyIPv4(ip) == nil
}
func (p ProxyEndpoint) valid() bool {
	return validExit(p.IPv4) && domain.ValidateV2rayNHTTPPort(p.Port) == nil && p.PID != 0 && p.Created != 0
}

func (r *Runtime) V2rayNEndpoint(ip string, port int) (ProxyEndpoint, error) {
	if !validExit(ip) {
		return ProxyEndpoint{}, errors.New("请输入已确认的代理公网 IPv4 出口")
	}
	if err := domain.ValidateV2rayNHTTPPort(port); err != nil {
		return ProxyEndpoint{}, err
	}
	endpoint := ProxyEndpoint{IPv4: ip}
	output, err := r.queryGuardian("proxy-owner", strconv.Itoa(port))
	if err != nil || json.Unmarshal(output, &endpoint) != nil || endpoint.Port != port || !endpoint.valid() {
		return ProxyEndpoint{}, fmt.Errorf("无法核对 127.0.0.1:%d 的监听进程及其 v2rayN 父进程", port)
	}
	return endpoint, nil
}

func (r *Runtime) claudeImage() (string, error) {
	output, err := r.queryGuardian("claude-image")
	path := strings.TrimRight(string(output), "\r\n")
	if err != nil || !filepath.IsAbs(path) || !strings.EqualFold(filepath.Base(path), "Claude.exe") ||
		strings.ContainsAny(path, "\"\r\n\x00") {
		return "", errors.New("未找到当前 Windows 账户安装的官方 Claude Desktop x64。请先安装或更新应用。")
	}
	return path, nil
}

func (r *Runtime) queryGuardian(args ...string) ([]byte, error) {
	binary, err := verifiedHelper(r.helper)
	if err != nil {
		return nil, err
	}
	defer binary.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, r.helper, args...).Output()
}
