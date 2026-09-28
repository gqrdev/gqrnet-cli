package cmd

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	dnsquery "github.com/gqrdev/gqrnet-cli/internal/dns"
	"github.com/gqrdev/gqrnet-cli/internal/output"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	dnsJSONOutput bool
	dnsTimeoutSec = 10
	dnsServer     string
	dnsTypes      []string
	dnsQuery      = dnsquery.QueryDNSWithOptions
)

var dnsTypeCodes = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"CNAME": dns.TypeCNAME,
	"MX":    dns.TypeMX,
	"NS":    dns.TypeNS,
	"SOA":   dns.TypeSOA,
	"TXT":   dns.TypeTXT,
}

var dnsCmd = &cobra.Command{
	Use:   "dns [target-domain]",
	Short: "Query DNS records for a domain.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := normalizeDNSDomain(args[0])
		if err != nil {
			return err
		}
		if dnsTimeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}

		types, err := parseDNSTypes(dnsTypes)
		if err != nil {
			return err
		}
		server, err := normalizeDNSServer(dnsServer)
		if err != nil {
			return err
		}

		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, time.Duration(dnsTimeoutSec)*time.Second)
		defer cancel()
		result := dnsQuery(ctx, target, dnsquery.Options{Server: server, Types: types})

		if dnsJSONOutput {
			return output.PrintDNSJSON(cmd.OutOrStdout(), result)
		}
		output.PrintDNSText(cmd.OutOrStdout(), target, result)
		return nil
	},
}

func init() {
	dnsCmd.Flags().BoolVar(&dnsJSONOutput, "json", false, "Output results in JSON format")
	dnsCmd.Flags().IntVar(&dnsTimeoutSec, "timeout", 10, "Execution timeout in seconds")
	dnsCmd.Flags().StringVar(&dnsServer, "server", "", "DNS server to query (port 53 is used by default)")
	dnsCmd.Flags().StringArrayVar(&dnsTypes, "type", nil, "DNS record type to query (repeatable)")

	RootCmd.AddCommand(dnsCmd)
}

func normalizeDNSDomain(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, ":/\\") {
		return "", errors.New("target must be a hostname without scheme, path, or port")
	}
	trimmed := strings.TrimSuffix(value, ".")
	if trimmed == "" || net.ParseIP(trimmed) != nil {
		return "", errors.New("target must be a hostname")
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("target must be a valid hostname")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("target must be a valid hostname")
			}
		}
	}
	return trimmed, nil
}

func parseDNSTypes(values []string) ([]uint16, error) {
	if len(values) == 0 {
		return nil, nil
	}
	types := make([]uint16, 0, len(values))
	for _, value := range values {
		code, ok := dnsTypeCodes[strings.ToUpper(value)]
		if !ok {
			return nil, errors.New("unsupported DNS record type: " + value)
		}
		types = append(types, code)
	}
	return types, nil
}

func normalizeDNSServer(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "/\\") {
		return "", errors.New("server must be a hostname or IP address")
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value, nil
	}
	if strings.Count(value, ":") > 1 {
		if net.ParseIP(value) == nil {
			return "", errors.New("server must be a valid hostname or IP address")
		}
		return net.JoinHostPort(value, "53"), nil
	}
	if net.ParseIP(value) == nil {
		for _, char := range value {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '.' {
				return "", errors.New("server must be a valid hostname or IP address")
			}
		}
	}
	return net.JoinHostPort(value, "53"), nil
}
