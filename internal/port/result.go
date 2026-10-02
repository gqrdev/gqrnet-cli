package port

import "time"

const (
	StateOpen       = "open"
	StateClosed     = "closed"
	StateTimeout    = "timeout"
	StateCancelled  = "cancelled"
	StateError      = "error"
	StateNotChecked = "not_checked"
)

// Result contains TCP connectivity checks for every resolved address and port.
type Result struct {
	Target            string       `json:"target"`
	Protocol          string       `json:"protocol"`
	StartedAt         time.Time    `json:"started_at"`
	DurationMS        int64        `json:"duration_ms"`
	TimeoutMS         int64        `json:"timeout_ms"`
	FullScan          bool         `json:"full_scan"`
	Complete          bool         `json:"complete"`
	RequestedPorts    []int        `json:"requested_ports,omitempty"`
	ResolvedAddresses []Address    `json:"resolved_addresses,omitempty"`
	Results           []PortResult `json:"results,omitempty"`
	Summary           Summary      `json:"summary"`
	Error             string       `json:"error,omitempty"`
}

// Address identifies an IP address returned by DNS resolution.
type Address struct {
	IP     string `json:"ip"`
	Family string `json:"family"`
}

// PortResult describes one TCP connection attempt.
type PortResult struct {
	IP            string `json:"ip"`
	Family        string `json:"family"`
	Port          int    `json:"port"`
	Status        string `json:"status"`
	ConnectTimeMS int64  `json:"connect_time_ms,omitempty"`
	ServiceHint   string `json:"service_hint,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Summary counts the outcome of each IP/port check, including omitted results.
type Summary struct {
	AddressesChecked int `json:"addresses_checked"`
	PortsPerAddress  int `json:"ports_per_address"`
	Open             int `json:"open"`
	Closed           int `json:"closed"`
	Timeout          int `json:"timeout"`
	Cancelled        int `json:"cancelled"`
	Errors           int `json:"errors"`
	NotChecked       int `json:"not_checked"`
}
