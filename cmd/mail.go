package cmd

import (
	"context"
	"errors"
	"time"

	mailaudit "github.com/gqrdev/gqrnet-cli/internal/mail"
	"github.com/gqrdev/gqrnet-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	mailJSONOutput bool
	mailTimeoutSec = 10
	mailServer     string
	mailScan       = mailaudit.Scan
)

var mailCmd = &cobra.Command{
	Use:   "mail [target-domain]",
	Short: "Inspect MX, SPF, and DMARC records for a domain.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := normalizeDomainTarget(args[0])
		if err != nil {
			return err
		}
		if mailTimeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}
		server, err := normalizeDNSServer(mailServer)
		if err != nil {
			return err
		}

		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, time.Duration(mailTimeoutSec)*time.Second)
		defer cancel()
		result := mailScan(ctx, target, server)

		if mailJSONOutput {
			return output.PrintMailJSON(cmd.OutOrStdout(), result)
		}
		output.PrintMailText(cmd.OutOrStdout(), result)
		return nil
	},
}

func init() {
	mailCmd.Flags().BoolVar(&mailJSONOutput, "json", false, "Output results in JSON format")
	mailCmd.Flags().IntVar(&mailTimeoutSec, "timeout", 10, "Execution timeout in seconds")
	mailCmd.Flags().StringVar(&mailServer, "server", "", "DNS server to query (port 53 is used by default)")

	RootCmd.AddCommand(mailCmd)
}
