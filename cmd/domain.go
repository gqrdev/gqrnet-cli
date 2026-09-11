package cmd

import (
	"errors"
	"time"

	"gqrnet/internal/domain"
	"gqrnet/internal/output"

	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	timeoutSec int
)

// domainCmd represents the "gqrnet domain <target>" subcommand.
var domainCmd = &cobra.Command{
	Use:   "domain [target-domain]",
	Short: "Inspect DNS, HTTP, TLS, and Network status for a given domain.",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("please specify a target domain (e.g. gqrnet domain example.com)")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if timeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}

		targetDomain := args[0]
		timeout := time.Duration(timeoutSec) * time.Second

		// Perform full scan
		result := domain.ScanDomain(targetDomain, timeout)

		// Render output based on CLI flags
		if jsonOutput {
			return output.PrintJSON(result)
		}

		output.PrintText(result)
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
