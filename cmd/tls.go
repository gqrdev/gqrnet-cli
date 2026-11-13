package cmd

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/gqrdev/gqrnet-cli/internal/output"
	tlsinspect "github.com/gqrdev/gqrnet-cli/internal/tls"
	"github.com/spf13/cobra"
)

var (
	tlsJSONOutput bool
	tlsTimeoutSec = 10
	tlsPort       = 443
	tlsServerName string
	tlsInspect    = tlsinspect.InspectTLSWithOptions
)

var tlsCmd = &cobra.Command{
	Use:   "tls [host]",
	Short: "Inspect a host's TLS connection and certificate.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host, err := normalizeTLSHost(args[0])
		if err != nil {
			return err
		}
		if tlsPort < 1 || tlsPort > 65535 {
			return errors.New("port must be an integer between 1 and 65535")
		}
		if tlsTimeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}
		serverName, err := normalizeTLSServerName(tlsServerName)
		if err != nil {
			return err
		}

		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		timeout := time.Duration(tlsTimeoutSec) * time.Second
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()

		result := tlsInspect(ctx, host, tlsinspect.Options{
			Port:       tlsPort,
			ServerName: serverName,
		})
		if tlsJSONOutput {
			return output.PrintTLSJSON(cmd.OutOrStdout(), host, tlsPort, serverName, result)
		}
		output.PrintTLSText(cmd.OutOrStdout(), host, tlsPort, serverName, result)
		return nil
	},
}

func init() {
	tlsCmd.Flags().BoolVar(&tlsJSONOutput, "json", false, "Output results in JSON format")
	tlsCmd.Flags().IntVar(&tlsTimeoutSec, "timeout", 10, "Execution timeout in seconds")
	tlsCmd.Flags().IntVar(&tlsPort, "port", 443, "TLS service port (1-65535)")
	tlsCmd.Flags().StringVar(&tlsServerName, "server-name", "", "Server name for SNI and certificate verification")

	RootCmd.AddCommand(tlsCmd)
}

func normalizeTLSHost(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\") {
		return "", errors.New("host must be a hostname or IP address without scheme, path, or port")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if strings.Contains(value, ":") {
		return "", errors.New("host must be a hostname or IP address without scheme, path, or port")
	}
	return normalizeDomainTarget(value)
}

func normalizeTLSServerName(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if net.ParseIP(value) != nil {
		return "", errors.New("server-name must be a valid hostname")
	}
	normalized, err := normalizeDomainTarget(value)
	if err != nil {
		return "", errors.New("server-name must be a valid hostname")
	}
	return normalized, nil
}
