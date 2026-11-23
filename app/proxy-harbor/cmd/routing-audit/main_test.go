package main

import "testing"

func TestSplitRoutingAndLocalDNSAreRejected(t *testing.T) {
	var model topology
	model.SelectedTag = "proxy"
	model.DefaultTag = "proxy"
	model.SelectedProtocol = "vless"
	model.DomainStrategy = "AsIs"
	model.DNS.DisableFallback = true
	model.DNS.Servers = []string{"https://1.1.1.1/dns-query"}
	if issues := audit(model); len(issues) != 0 {
		t.Fatal(issues)
	}
	model.Routes = append(model.Routes, struct {
		OutboundTag string `json:"outboundTag"`
		BalancerTag string `json:"balancerTag"`
	}{"direct", ""})
	if len(audit(model)) == 0 {
		t.Fatal("Destination-specific DIRECT survived the model check")
	}
	model.Routes = nil
	for _, server := range []string{"localhost", "https+local://1.1.1.1/dns-query", "https://dns.example/dns-query", "https://127.0.0.1/dns-query"} {
		model.DNS.Servers = []string{server}
		if len(audit(model)) == 0 {
			t.Fatalf("DNS bypass accepted: %s", server)
		}
	}
}
