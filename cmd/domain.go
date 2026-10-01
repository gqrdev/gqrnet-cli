package cmd

import (
	"errors"
	"time"

	"github.com/gqrdev/gqrnet-cli/internal/domain"
	"github.com/gqrdev/gqrnet-cli/internal/output"

	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	timeoutSec int
	scanDomain = domain.ScanDomain
)

// domainCmd represents the "gqrnet domain <target>" subcommand.
var domainCmd = &cobra.Command{
	Use:   "domain [target-domain]",
	Short: "Inspect DNS, HTTP, HTTPS, TLS, and network status for a domain.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetDomain, err := normalizeDomainTarget(args[0])
		if err != nil {
			return err
		}
		if timeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}

		timeout := time.Duration(timeoutSec) * time.Second

		// Perform full scan
		result := scanDomain(targetDomain, timeout)

		// Render output based on CLI flags
		if jsonOutput {
			return output.PrintJSON(cmd.OutOrStdout(), result)
		}

		output.PrintText(cmd.OutOrStdout(), result)
		return nil
	},
}

func init() {
	// Register flags
	domainCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	domainCmd.Flags().IntVar(&timeoutSec, "timeout", 10, "Execution timeout in seconds")

	// Add "domain" command to the root command "gqrnet"
	RootCmd.AddCommand(domainCmd)
}
