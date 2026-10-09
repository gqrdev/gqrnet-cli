package mail

const (
	StatusConfigured    = "configured"
	StatusMissing       = "missing"
	StatusMultiple      = "multiple"
	StatusInvalid       = "invalid"
	StatusDisabled      = "disabled"
	StatusIndeterminate = "indeterminate"
)

// CheckResult describes one DNS-based mail configuration check.
type CheckResult struct {
	Status  string   `json:"status"`
	Records []string `json:"records,omitempty"`
	Policy  string   `json:"policy,omitempty"`
	Detail  string   `json:"detail,omitempty"`
}

// Result summarizes the domain's MX, SPF, and DMARC DNS configuration.
type Result struct {
	Domain     string      `json:"domain"`
	MX         CheckResult `json:"mx"`
	SPF        CheckResult `json:"spf"`
	DMARC      CheckResult `json:"dmarc"`
	DurationMS int64       `json:"duration_ms"`
}
