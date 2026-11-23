// routing-audit reads a redacted topology summary from stdin. It never opens
// v2rayN files or contacts a proxy. Its result describes only the supplied model.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

type topology struct {
	SelectedTag      string `json:"selectedTag"`
	DefaultTag       string `json:"defaultTag"`
	SelectedProtocol string `json:"selectedProtocol"`
	Chained          bool   `json:"chained"`
	DomainStrategy   string `json:"domainStrategy"`
	Routes           []struct {
		OutboundTag string `json:"outboundTag"`
		BalancerTag string `json:"balancerTag"`
	} `json:"routes"`
	DNS struct {
		DisableFallback bool     `json:"disableFallback"`
		Servers         []string `json:"servers"`
	} `json:"dns"`
}

func audit(t topology) []string {
	var issues []string
	if t.SelectedTag == "" || t.DefaultTag != t.SelectedTag {
		issues = append(issues, "默认出站必须指向选定节点")
	}
	switch t.SelectedProtocol {
	case "vless", "vmess", "trojan", "shadowsocks":
	default:
		issues = append(issues, "选定出站尚无受支持的远程节点协议证明")
	}
	if t.Chained {
		issues = append(issues, "链式出站需要独立核对最终连接路径")
	}
	if t.DomainStrategy != "AsIs" {
		issues = append(issues, "域名匹配前解析可能引入额外 DNS 路径")
	}
	for i, r := range t.Routes {
		if r.BalancerTag != "" || r.OutboundTag != t.SelectedTag {
			issues = append(issues, fmt.Sprintf("第 %d 条路由存在其他出站或负载均衡路径", i+1))
		}
	}
	if !t.DNS.DisableFallback || len(t.DNS.Servers) == 0 {
		issues = append(issues, "DNS 必须明确禁止回退并指定解析器")
	}
	for _, server := range t.DNS.Servers {
		u, err := url.Parse(server)
		if err != nil {
			issues = append(issues, "解析器地址无效")
			continue
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/dns-query" || err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || (u.Port() != "" && u.Port() != "443") {
			issues = append(issues, "DNS 模型要求 HTTPS 字面公网 IPv4 解析器，避免解析器域名的引导查询")
		}
	}
	return issues
}

func main() {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 65537))
	decoder.DisallowUnknownFields()
	var model topology
	if err := decoder.Decode(&model); err != nil {
		fmt.Fprintln(os.Stderr, "仅接受脱敏拓扑摘要，请勿输入节点配置或凭据")
		os.Exit(2)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		fmt.Fprintln(os.Stderr, "摘要必须是单个 JSON 对象")
		os.Exit(2)
	}
	issues := audit(model)
	result := struct {
		ModelPassed     bool     `json:"modelPassed"`
		RuntimeVerified bool     `json:"runtimeVerified"`
		Scope           string   `json:"scope"`
		Issues          []string `json:"issues"`
	}{len(issues) == 0, false, "仅检查输入的静态模型；摘要与实际内核的一致性待核对", issues}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(2)
	}
	if len(issues) > 0 {
		fmt.Fprintln(os.Stderr, strings.Join(issues, "\n"))
		os.Exit(1)
	}
}
