package output

import (
	"fmt"
	"strings"

	"gqrnet/internal/domain"
)

// PrintText presents human-readable formatted output to the terminal.
func PrintText(res domain.DomainResult) {
	fmt.Printf("=== Target Domain: %s ===\n\n", res.Domain)

	// Network
	fmt.Println("[ Network Resolution ]")
	if res.Network.Error != "" {
		fmt.Printf(" Error: %s\n", res.Network.Error)
	} else {
		fmt.Printf(" IPv4: %s\n", strings.Join(res.Network.IPv4, ", "))
		fmt.Printf(" IPv6: %s\n", strings.Join(res.Network.IPv6, ", "))
	}
	fmt.Println()

	// DNS
	fmt.Println("[ DNS Records ]")
	if res.DNS.Error != "" {
		fmt.Printf(" Error: %s\n", res.DNS.Error)
	} else {
		fmt.Printf(" A:     %s\n", strings.Join(res.DNS.A, ", "))
		fmt.Printf(" AAAA:  %s\n", strings.Join(res.DNS.AAAA, ", "))
		fmt.Printf(" MX:    %s\n", strings.Join(res.DNS.MX, ", "))
		fmt.Printf(" NS:    %s\n", strings.Join(res.DNS.NS, ", "))
		fmt.Printf(" SOA:   %s\n", strings.Join(res.DNS.SOA, ", "))
		fmt.Printf(" TXT:   %s\n", strings.Join(res.DNS.TXT, ", "))
	}
	fmt.Println()

	// HTTP
	fmt.Println("[ HTTP Status ]")
	if res.HTTP.Error != "" {
		fmt.Printf(" Error: %s\n", res.HTTP.Error)
	} else {
		fmt.Printf(" Status Code:    %d\n", res.HTTP.StatusCode)
		fmt.Printf(" Protocol:       %s\n", res.HTTP.Proto)
		fmt.Printf(" Response Time:  %d ms\n", res.HTTP.ResponseTime)
		if res.HTTP.RedirectURL != "" {
			fmt.Printf(" Redirects To:   %s\n", res.HTTP.RedirectURL)
		}
	}
	fmt.Println()

	// TLS
	fmt.Println("[ TLS Certificate ]")
	if res.TLS.Error != "" {
		fmt.Printf(" Error: %s\n", res.TLS.Error)
	} else {
		fmt.Printf(" TLS Version:    %s\n", res.TLS.Version)
		fmt.Printf(" Cipher Suite:   %s\n", res.TLS.CipherSuite)
		fmt.Printf(" Issuer:         %s\n", res.TLS.Issuer)
		fmt.Printf(" Expires In:     %d days\n", res.TLS.DaysValid)
	}
}
