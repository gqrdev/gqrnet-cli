package domain

import (
	"time"

	"gqrnet/internal/dns"
	"gqrnet/internal/http"
	"gqrnet/internal/network"
	"gqrnet/internal/tls"
)

// DomainResult represents the outcome of a domain scan.
type DomainResult struct {
	Domain    string         `json:"domain"`
	Timestamp time.Time      `json:"timestamp"`
	Duration  time.Duration  `json:"duration"`
	Network   network.Result `json:"network"`
	DNS       dns.Result     `json:"dns"`
	HTTP      http.Result    `json:"http"`
	TLS       tls.Result     `json:"tls"`
}
