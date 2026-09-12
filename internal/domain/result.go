package domain

import (
	"time"

	"github.com/gqrdev/gqrnet-cli/internal/dns"
	"github.com/gqrdev/gqrnet-cli/internal/http"
	"github.com/gqrdev/gqrnet-cli/internal/network"
	"github.com/gqrdev/gqrnet-cli/internal/tls"
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
