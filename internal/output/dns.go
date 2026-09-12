package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	dnsquery "gqrnet/internal/dns"
)

// PrintDNSJSON writes a DNS result using the stable dns.Result JSON contract.
func PrintDNSJSON(w io.Writer, result dnsquery.Result) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// PrintDNSText presents a human-readable DNS result.
func PrintDNSText(w io.Writer, domain string, result dnsquery.Result) {
	fmt.Fprintf(w, "=== Target Domain: %s ===\n\n", domain)
	fmt.Fprintln(w, "[ DNS Records ]")
	if result.Error != "" {
		fmt.Fprintf(w, " Error: %s\n", result.Error)
		return
	}
	fmt.Fprintf(w, " A:     %s\n", strings.Join(result.A, ", "))
	fmt.Fprintf(w, " AAAA:  %s\n", strings.Join(result.AAAA, ", "))
	fmt.Fprintf(w, " CNAME: %s\n", strings.Join(result.CNAME, ", "))
	fmt.Fprintf(w, " MX:    %s\n", strings.Join(result.MX, ", "))
	fmt.Fprintf(w, " NS:    %s\n", strings.Join(result.NS, ", "))
	fmt.Fprintf(w, " SOA:   %s\n", strings.Join(result.SOA, ", "))
	fmt.Fprintf(w, " TXT:   %s\n", strings.Join(result.TXT, ", "))
}
