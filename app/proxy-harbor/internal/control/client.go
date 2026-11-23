// Package control is transport-neutral. The scaffold is in-process; a restricted
// Named Pipe client will replace this implementation after P0.
package control

import "proxyharbor/internal/domain"

type Client interface {
	Snapshot() domain.Snapshot
	ReloadConfiguration() domain.Snapshot
	ResetConfiguration(bool) (domain.Snapshot, error)
	SaveProxy(domain.ProxyProfile) (domain.Snapshot, error)
	SaveExpectedProxyIPv4(string) (domain.Snapshot, error)
	DeleteProxy(string) (domain.Snapshot, error)
	SelectProxy(string) (domain.Snapshot, error)
	ConfigureApplication(string, string) (domain.Snapshot, error)
	RefreshEnvironment() domain.Snapshot
	StartProtection() error
}
