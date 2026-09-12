package tls

import "time"

// Result contains SSL/TLS metadata and certificate status.
type Result struct {
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysValid   int       `json:"days_valid"`
	Error       string    `json:"error,omitempty"`
}
