package domain

import (
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

var hostLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

var specialIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func ValidateExpectedProxyIPv4(value string) error {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return errors.New("请输入固定代理的公网 IPv4 地址")
	}
	for _, prefix := range specialIPv4 {
		if prefix.Contains(ip) {
			return errors.New("固定代理出口不能使用保留地址")
		}
	}
	return nil
}

func ValidateProfile(p ProxyProfile) error {
	if strings.TrimSpace(p.Name) == "" || len([]rune(p.Name)) > 80 {
		return errors.New("请输入 1–80 个字符的配置名称")
	}
	if p.Protocol != "http" && p.Protocol != "https" && p.Protocol != "socks5" {
		return errors.New("请选择 HTTP、HTTPS 或 SOCKS5")
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("端口必须介于 1 和 65535 之间")
	}
	if ip := net.ParseIP(p.Host); ip != nil {
		if ip.To4() == nil {
			return errors.New("当前仅接受 IPv4 代理入口，IPv6 入口尚未验证")
		}
		return nil
	}
	if len(p.Host) > 253 || p.Host == "" {
		return errors.New("请输入 IPv4 地址或域名，不含协议、端口和账号")
	}
	for _, label := range strings.Split(p.Host, ".") {
		if !hostLabel.MatchString(label) {
			return errors.New("代理地址只能填写 IPv4 或域名，不含协议、端口、账号和密码")
		}
	}
	return nil
}
func ValidateConfig(c Config) error {
	if c.ExpectedProxyIPv4 != "" {
		if err := ValidateExpectedProxyIPv4(c.ExpectedProxyIPv4); err != nil {
			return err
		}
	}
	if c.Version != 1 {
		return errors.New("配置版本不受支持，未覆盖原文件")
	}
	seen := map[string]bool{}
	for _, p := range c.Profiles {
		if p.ID == "" || seen[p.ID] {
			return errors.New("代理配置 ID 缺失或重复")
		}
		if err := ValidateProfile(p); err != nil {
			return err
		}
		seen[p.ID] = true
	}
	if c.SelectedProfileID != "" && !seen[c.SelectedProfileID] {
		return errors.New("所选代理不存在")
	}
	apps := map[string]bool{}
	for _, app := range c.Applications {
		if (app.ID != "claude" && app.ID != "codex" && app.ID != "chrome") || apps[app.ID] {
			return errors.New("应用配置无效")
		}
		apps[app.ID] = true
		if app.Compatibility != "unverified" {
			return errors.New("配置文件不能自行声明应用已经通过保护验证")
		}
	}
	// Version 1 files may still contain the retired Chrome and Codex entries.
	if !apps["claude"] {
		return errors.New("应用配置不完整")
	}
	return nil
}
