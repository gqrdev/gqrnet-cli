package cmd

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/gqrdev/gqrnet-cli/internal/output"
	portscan "github.com/gqrdev/gqrnet-cli/internal/port"
	"github.com/spf13/cobra"
)

var (
	portJSONOutput        bool
	portOpenOnly          bool
	portTimeoutSec        = 120
	portConnectTimeoutSec = 3
	portValues            []string
	portScan              = portscan.Scan
)

var portCmd = &cobra.Command{
	Use:   "port [target-domain]",
	Short: "Find open TCP ports by default or check selected ports on a domain.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := normalizeDomainTarget(args[0])
		if err != nil {
			return err
		}
		if portTimeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}
		if portConnectTimeoutSec <= 0 {
			return errors.New("connect-timeout must be greater than zero seconds")
		}
		var ports []int
		if len(portValues) > 0 {
			ports, err = parsePortValues(portValues)
			if err != nil {
				return err
			}
		}

		timeout := time.Duration(portTimeoutSec) * time.Second
		connectTimeout := time.Duration(portConnectTimeoutSec) * time.Second
		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		result := portScan(ctx, target, ports, timeout, connectTimeout)

		if portJSONOutput {
			return output.PrintPortJSON(cmd.OutOrStdout(), result, portOpenOnly)
		}
		output.PrintPortText(cmd.OutOrStdout(), result, portOpenOnly)
		return nil
	},
}

func init() {
	portCmd.Flags().BoolVar(&portJSONOutput, "json", false, "Output results in JSON format")
	portCmd.Flags().BoolVar(&portOpenOnly, "open-only", false, "Show only open ports; scan all selected ports as usual")
	portCmd.Flags().IntVar(&portTimeoutSec, "timeout", 120, "Execution timeout in seconds")
	portCmd.Flags().IntVar(&portConnectTimeoutSec, "connect-timeout", 3, "Timeout for each TCP connection attempt in seconds")
	portCmd.Flags().StringArrayVar(&portValues, "port", nil, "TCP port to check (repeatable; 1-65535, max 100 unique ports)")

	RootCmd.AddCommand(portCmd)
}

func parsePortValues(values []string) ([]int, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one --port value is required")
	}
	ports := make([]int, 0, len(values))
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("port must be an integer between 1 and 65535: " + value)
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
		if len(ports) > 100 {
			return nil, errors.New("no more than 100 unique ports may be requested")
		}
	}
	return ports, nil
}
