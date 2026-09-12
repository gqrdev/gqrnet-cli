package domain

import (
	"context"
	"sync"
	"time"

	"github.com/gqrdev/gqrnet-cli/internal/dns"
	"github.com/gqrdev/gqrnet-cli/internal/http"
	"github.com/gqrdev/gqrnet-cli/internal/network"
	"github.com/gqrdev/gqrnet-cli/internal/tls"
)

// ScanDomain orchestrates parallel calls to DNS, HTTP, TLS, and Network checks.
func ScanDomain(domain string, timeout time.Duration) DomainResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	result := DomainResult{Domain: domain, Timestamp: start}
	var wg sync.WaitGroup

	// Run concurrently for performance
	wg.Add(4)

	go func() {
		defer wg.Done()
		result.Network = network.ResolveIPs(ctx, domain)
	}()

	go func() {
		defer wg.Done()
		result.DNS = dns.QueryDNS(ctx, domain)
	}()

	go func() {
		defer wg.Done()
		result.HTTP = http.CheckHTTP(ctx, domain)
	}()

	go func() {
		defer wg.Done()
		result.TLS = tls.InspectTLS(ctx, domain)
	}()

	wg.Wait()
	result.Duration = time.Since(start)
	return result
}
