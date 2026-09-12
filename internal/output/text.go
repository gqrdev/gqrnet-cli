package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/gqrdev/gqrnet-cli/internal/domain"
)

// PrintText presents human-readable formatted output to the terminal.
func PrintText(w io.Writer, res domain.DomainResult) {
	fmt.Fprintf(w, "=== Target Domain: %s ===\n\n", res.Domain)

	// Network
	fmt.Fprintln(w, "[ Network Resolution ]")
	if res.Network.Error != "" {
		fmt.Fprintf(w, " Error: %s\n", res.Network.Error)
	} else {
		fmt.Fprintf(w, " IPv4: %s\n", strings.Join(res.Network.IPv4, ", "))
		fmt.Fprintf(w, " IPv6: %s\n", strings.Join(res.Network.IPv6, ", "))
	}
	fmt.Fprintln(w)

	// DNS
	fmt.Fprintln(w, "[ DNS Records ]")
	if res.DNS.Error != "" {
		fmt.Fprintf(w, " Error: %s\n", res.DNS.Error)
	} else {
		fmt.Fprintf(w, " A:     %s\n", strings.Join(res.DNS.A, ", "))
		fmt.Fprintf(w, " AAAA:  %s\n", strings.Join(res.DNS.AAAA, ", "))
		fmt.Fprintf(w, " MX:    %s\n", strings.Join(res.DNS.MX, ", "))
		fmt.Fprintf(w, " NS:    %s\n", strings.Join(res.DNS.NS, ", "))
		fmt.Fprintf(w, " SOA:   %s\n", strings.Join(res.DNS.SOA, ", "))
		fmt.Fprintf(w, " TXT:   %s\n", strings.Join(res.DNS.TXT, ", "))
	}
	fmt.Fprintln(w)

	// HTTP
	fmt.Fprintln(w, "[ HTTP Status ]")
	if res.HTTP.Error != "" {
		fmt.Fprintf(w, " Error: %s\n", res.HTTP.Error)
	} else {
		fmt.Fprintf(w, " Status Code:    %d\n", res.HTTP.StatusCode)
		fmt.Fprintf(w, " Protocol:       %s\n", res.HTTP.Proto)
		fmt.Fprintf(w, " Response Time:  %d ms\n", res.HTTP.ResponseTime)
		if res.HTTP.RedirectURL != "" {
			fmt.Fprintf(w, " Redirects To:   %s\n", res.HTTP.RedirectURL)
		}
	}
	fmt.Fprintln(w)

	// TLS
	fmt.Fprintln(w, "[ TLS Certificate ]")
	if res.TLS.Error != "" {
		fmt.Fprintf(w, " Error: %s\n", res.TLS.Error)
	} else {
		fmt.Fprintf(w, " TLS Version:    %s\n", res.TLS.Version)
		fmt.Fprintf(w, " Cipher Suite:   %s\n", res.TLS.CipherSuite)
		fmt.Fprintf(w, " Issuer:         %s\n", res.TLS.Issuer)
		fmt.Fprintf(w, " Expires In:     %d days\n", res.TLS.DaysValid)
	}
}
