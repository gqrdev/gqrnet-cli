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

// Options controls how DNS records are queried.
type Options struct {
	Server string
	Types  []uint16
}

var defaultTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeMX,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeTXT,
	dns.TypeCNAME,
}

// QueryDNS queries all supported record types using the system DNS configuration.
func QueryDNS(ctx context.Context, domain string) Result {
	return QueryDNSWithOptions(ctx, domain, Options{})
}

// QueryDNSWithOptions queries selected record types using an optional DNS server.
func QueryDNSWithOptions(ctx context.Context, domain string, options Options) Result {
	var res Result
	dnsServer := options.Server
	if dnsServer == "" {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(config.Servers) == 0 {
			res.Error = "unable to read system DNS configuration"
			return res
		}
		dnsServer = net.JoinHostPort(config.Servers[0], config.Port)
	}
	queryTypes := options.Types
	if len(queryTypes) == 0 {
		queryTypes = defaultTypes
	}

	// Helper to send DNS requests safely
	lookup := func(qtype uint16) ([]string, error) {
		m := new(dns.Msg)
		// Ensure fully qualified domain name ending with a dot
		m.SetQuestion(dns.Fqdn(domain), qtype)

		resolver := &dns.Client{}
		in, _, err := resolver.ExchangeContext(ctx, m, dnsServer)
		if err != nil || in == nil {
			return nil, err
		}
		if in.Truncated {
			resolver.Net = "tcp"
			in, _, err = resolver.ExchangeContext(ctx, m, dnsServer)
			if err != nil || in == nil {
				return nil, err
			}
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

	for _, qtype := range queryTypes {
		records, err := lookup(qtype)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		switch qtype {
		case dns.TypeA:
			res.A = records
		case dns.TypeAAAA:
			res.AAAA = records
		case dns.TypeMX:
			res.MX = records
		case dns.TypeNS:
			res.NS = records
		case dns.TypeSOA:
			res.SOA = records
		case dns.TypeTXT:
			res.TXT = records
		case dns.TypeCNAME:
			res.CNAME = records
		}
	}

	return res
}
