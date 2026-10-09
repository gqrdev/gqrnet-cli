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

// QueryRecords queries one DNS record type and returns the response RCODE separately from transport errors.
func QueryRecords(ctx context.Context, name string, qtype uint16, server string) ([]dns.RR, int, error) {
	address, err := resolveDNSServer(server)
	if err != nil {
		return nil, 0, err
	}
	return queryDNSRecords(ctx, name, qtype, address)
}

// QueryDNSWithOptions queries selected record types using an optional DNS server.
func QueryDNSWithOptions(ctx context.Context, domain string, options Options) Result {
	var res Result
	dnsServer, err := resolveDNSServer(options.Server)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	queryTypes := options.Types
	if len(queryTypes) == 0 {
		queryTypes = defaultTypes
	}
	var queryErrors []string

	// Helper to send DNS requests safely
	lookup := func(qtype uint16) ([]string, error) {
		answers, rcode, err := queryDNSRecords(ctx, domain, qtype, dnsServer)
		if err != nil {
			return nil, err
		}
		if rcode != dns.RcodeSuccess {
			rcodeName, ok := dns.RcodeToString[rcode]
			if !ok {
				rcodeName = fmt.Sprintf("RCODE%d", rcode)
			}
			return nil, fmt.Errorf("DNS server returned %s", rcodeName)
		}

		var records []string
		for _, ans := range answers {
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
			typeName := dns.TypeToString[qtype]
			if typeName == "" {
				typeName = fmt.Sprintf("TYPE%d", qtype)
			}
			queryErrors = append(queryErrors, fmt.Sprintf("%s: %v", typeName, err))
			if ctx.Err() != nil {
				break
			}
			continue
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

	res.Error = strings.Join(queryErrors, "; ")
	return res
}

func resolveDNSServer(server string) (string, error) {
	if server != "" {
		return server, nil
	}
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		return "", fmt.Errorf("unable to read system DNS configuration")
	}
	return net.JoinHostPort(config.Servers[0], config.Port), nil
}

func queryDNSRecords(ctx context.Context, name string, qtype uint16, server string) ([]dns.RR, int, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), qtype)

	resolver := &dns.Client{}
	response, _, err := resolver.ExchangeContext(ctx, request, server)
	if err != nil {
		return nil, 0, err
	}
	if response == nil {
		return nil, 0, fmt.Errorf("DNS server returned an empty response")
	}
	if response.Truncated {
		resolver.Net = "tcp"
		response, _, err = resolver.ExchangeContext(ctx, request, server)
		if err != nil {
			return nil, 0, err
		}
		if response == nil {
			return nil, 0, fmt.Errorf("DNS server returned an empty response")
		}
	}
	return response.Answer, response.Rcode, nil
}
