package diagnostics

import (
	"net"
	"os"
	"proxyharbor/internal/domain"
	"runtime"
	"time"
)

// CollectLocal never resolves hostnames or opens outbound connections.
func CollectLocal() domain.Environment {
	result := domain.Environment{OS: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version(), CollectedAt: time.Now().Format(time.RFC3339), Interfaces: []domain.InterfaceInfo{}, Warnings: []string{}}
	var err error
	result.Hostname, err = os.Hostname()
	if err != nil {
		result.Warnings = append(result.Warnings, "无法读取主机名称")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		result.Warnings = append(result.Warnings, "无法读取网卡信息")
		return result
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := item.Addrs()
		if err != nil {
			result.Warnings = append(result.Warnings, "无法读取网卡地址: "+item.Name)
			continue
		}
		info := domain.InterfaceInfo{Name: item.Name, Loopback: item.Flags&net.FlagLoopback != 0, Addresses: []string{}}
		for _, address := range addresses {
			info.Addresses = append(info.Addresses, address.String())
		}
		result.Interfaces = append(result.Interfaces, info)
	}
	return result
}
func PendingChecks() []domain.DiagnosticCheck {
	return []domain.DiagnosticCheck{
		{ID: "exit", Name: "代理出口", Status: "not_run", Detail: "尚未请求外部 IP 回显服务"},
		{ID: "dns", Name: "DNS 路径", Status: "not_run", Detail: "等待远端解析与外部观测接入"},
		{ID: "ipv6", Name: "IPv6 防绕过", Status: "not_run", Detail: "尚未安装应用级阻断规则"},
		{ID: "udp", Name: "UDP 防绕过", Status: "not_run", Detail: "尚未验证目标应用 UDP 阻断"},
	}
}
