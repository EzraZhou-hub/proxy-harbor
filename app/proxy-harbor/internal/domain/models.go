package domain

type ProxyProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}
type TargetApplication struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Executable    string `json:"executable"`
	Compatibility string `json:"compatibility"`
}
type Config struct {
	Version           int                 `json:"version"`
	Profiles          []ProxyProfile      `json:"profiles"`
	SelectedProfileID string              `json:"selectedProfileId"`
	ExpectedProxyIPv4 string              `json:"expectedProxyIPv4"`
	V2rayNHTTPPort    int                 `json:"v2rayNHTTPPort,omitempty"`
	Applications      []TargetApplication `json:"applications"`
}

func DefaultConfig() Config {
	return Config{Version: 1, V2rayNHTTPPort: DefaultV2rayNHTTPPort, Profiles: []ProxyProfile{}, Applications: []TargetApplication{
		{ID: "claude", Name: "Claude Desktop", Compatibility: "unverified"},
	}}
}

type Capabilities struct {
	ForwardTCP bool `json:"forwardTCP"`
	RemoteDNS  bool `json:"remoteDNS"`
	BlockIPv6  bool `json:"blockIPv6"`
	BlockUDP   bool `json:"blockUDP"`
	FailClosed bool `json:"failClosed"`
}
type EngineStatus struct {
	Name         string       `json:"name"`
	Available    bool         `json:"available"`
	Reason       string       `json:"reason"`
	Capabilities Capabilities `json:"capabilities"`
}
type ProtectionStatus struct {
	State    string   `json:"state"`
	CanStart bool     `json:"canStart"`
	Blockers []string `json:"blockers"`
}
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Loopback  bool     `json:"loopback"`
}
type Environment struct {
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	Architecture string          `json:"architecture"`
	GoVersion    string          `json:"goVersion"`
	Interfaces   []InterfaceInfo `json:"interfaces"`
	Warnings     []string        `json:"warnings"`
	CollectedAt  string          `json:"collectedAt"`
}
type DiagnosticCheck struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}
type StartupStatus struct {
	Error      string `json:"error"`
	CanReset   bool   `json:"canReset"`
	BackupPath string `json:"backupPath"`
}
type Snapshot struct {
	Version     string            `json:"version"`
	Startup     StartupStatus     `json:"startup"`
	Config      Config            `json:"config"`
	ConfigPath  string            `json:"configPath"`
	Engine      EngineStatus      `json:"engine"`
	Protection  ProtectionStatus  `json:"protection"`
	Environment Environment       `json:"environment"`
	Checks      []DiagnosticCheck `json:"checks"`
	Logs        []LogEntry        `json:"logs"`
}

type ManagedSession struct {
	TakeoverAvailable    bool   `json:"takeoverAvailable"`
	Available            bool   `json:"available"`
	State                string `json:"state"`
	Reason               string `json:"reason"`
	Detail               string `json:"detail"`
	Error                uint32 `json:"error"`
	PID                  uint32 `json:"pid"`
	GuardianPID          uint32 `json:"guardianPid"`
	GuardianCreated      uint64 `json:"guardianCreated"`
	FilterCount          int    `json:"filterCount"`
	ComponentCount       int    `json:"componentCount"`
	ProxyExit            string `json:"proxyExit"`
	ExpectedProxyIPv4    string `json:"expectedProxyIPv4"`
	V2rayNHTTPPort       int    `json:"v2rayNHTTPPort"`
	LastObservedExit     string `json:"lastObservedExit"`
	ExitCheckedAt        string `json:"exitCheckedAt"`
	LastExitSuccessAt    string `json:"lastExitSuccessAt"`
	ExitState            string `json:"exitState"`
	ExitFailures         uint32 `json:"exitFailures"`
	ExitStopCause        string `json:"exitStopCause"`
	TunIndex             uint32 `json:"tunIndex"`
	UpdatedAt            string `json:"updatedAt"`
	BlockedAt            string `json:"blockedAt"`
	BlockedFilterID      string `json:"blockedFilterId"`
	BlockDirection       string `json:"blockDirection"`
	BlockedProtocol      uint8  `json:"blockedProtocol"`
	BlockedRemotePort    uint16 `json:"blockedRemotePort"`
	UnexpectedPeerPID    uint32 `json:"unexpectedPeerPid"`
	UnexpectedPeerFamily uint16 `json:"unexpectedPeerFamily"`
	UnexpectedPeerPort   uint16 `json:"unexpectedPeerPort"`
	ApplicationID        string `json:"applicationId"`
	Directory            string `json:"directory"`
	DNS                  string `json:"dns"`
	UDP                  string `json:"udp"`
	IPv6                 string `json:"ipv6"`
}
