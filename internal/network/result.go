package network

import (
	"context"
	"net"
)

// Result stores IPv4 and IPv6 addresses resolved for a domain.
type Result struct {
	IPv4  []string `json:"ipv4,omitempty"`
	IPv6  []string `json:"ipv6,omitempty"`
	Error string   `json:"error,omitempty"`
}

// ResolveIPs resolves the domain name into both IPv4 and IPv6 addresses.
func ResolveIPs(ctx context.Context, domain string) Result {
	var res Result
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	for _, ip := range ips {
		if ip.IP.To4() != nil {
			res.IPv4 = append(res.IPv4, ip.IP.String())
		} else if ip.IP.To16() != nil {
			res.IPv6 = append(res.IPv6, ip.IP.String())
		}
	}
	return res
}
