package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Result stores DNS records discovered for a domain.
type Result struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	SOA   []string `json:"soa,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	Error string   `json:"error,omitempty"`
}

// QueryDNS queries common record types (A, AAAA, MX, NS, TXT) using miekg/dns.
func QueryDNS(ctx context.Context, domain string) Result {
	var res Result
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		res.Error = "unable to read system DNS configuration"
		return res
	}
	resolver := &dns.Client{}
	dnsServer := net.JoinHostPort(config.Servers[0], config.Port)

	// Helper to send DNS requests safely
	lookup := func(qtype uint16) ([]string, error) {
		m := new(dns.Msg)
		// Ensure fully qualified domain name ending with a dot
		m.SetQuestion(dns.Fqdn(domain), qtype)

		in, _, err := resolver.ExchangeContext(ctx, m, dnsServer)
		if err != nil || in == nil {
			return nil, err
		}

		var records []string
		for _, ans := range in.Answer {
			switch r := ans.(type) {
			case *dns.A:
				records = append(records, r.A.String())
			case *dns.AAAA:
				records = append(records, r.AAAA.String())
			case *dns.MX:
				records = append(records, fmt.Sprintf("%s (%d)", r.Mx, r.Preference))
			case *dns.NS:
				records = append(records, r.Ns)
			case *dns.SOA:
				records = append(records, fmt.Sprintf("%s %s %d %d %d %d %d", r.Ns, r.Mbox, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl))
			case *dns.CNAME:
				records = append(records, r.Target)
			case *dns.TXT:
				records = append(records, strings.Join(r.Txt, " "))
			}
		}
		return records, nil
	}

	queries := []struct {
		qtype  uint16
		target *[]string
	}{
		{dns.TypeA, &res.A},
		{dns.TypeAAAA, &res.AAAA},
		{dns.TypeMX, &res.MX},
		{dns.TypeNS, &res.NS},
		{dns.TypeSOA, &res.SOA},
		{dns.TypeTXT, &res.TXT},
		{dns.TypeCNAME, &res.CNAME},
	}
	for _, query := range queries {
		records, err := lookup(query.qtype)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		*query.target = records
	}

	return res
}
