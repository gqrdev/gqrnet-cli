package cmd

import (
	"context"
	"errors"
	"time"

	httpaudit "github.com/gqrdev/gqrnet-cli/internal/http"
	"github.com/gqrdev/gqrnet-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	httpJSONOutput   bool
	httpTimeoutSec   = 10
	httpShowHeaders  bool
	httpShowCookies  bool
	httpShowTLS      bool
	httpShowRedirect bool
	httpAudit        = httpaudit.AuditURL
)

var httpCmd = &cobra.Command{
	Use:   "http [url]",
	Short: "Inspect HTTP security-related information for a URL.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if httpTimeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}

		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, time.Duration(httpTimeoutSec)*time.Second)
		defer cancel()

		result, err := httpAudit(ctx, args[0])
		if err != nil {
			return err
		}
		sections := httpaudit.AuditSections{
			Headers:   httpShowHeaders,
			Cookies:   httpShowCookies,
			TLS:       httpShowTLS,
			Redirects: httpShowRedirect,
		}
		if httpJSONOutput {
			return output.PrintHTTPJSON(cmd.OutOrStdout(), result, sections)
		}
		output.PrintHTTPText(cmd.OutOrStdout(), result, sections)
		return nil
	},
}

func init() {
	httpCmd.Flags().BoolVar(&httpJSONOutput, "json", false, "Output results in JSON format")
	httpCmd.Flags().IntVar(&httpTimeoutSec, "timeout", 10, "Execution timeout in seconds")
	httpCmd.Flags().BoolVar(&httpShowHeaders, "headers", false, "Show security response headers")
	httpCmd.Flags().BoolVar(&httpShowCookies, "cookies", false, "Show cookie security attributes")
	httpCmd.Flags().BoolVar(&httpShowTLS, "tls", false, "Show TLS connection and certificate details")
	httpCmd.Flags().BoolVar(&httpShowRedirect, "redirects", false, "Show the initial redirect destination")

	RootCmd.AddCommand(httpCmd)
}
