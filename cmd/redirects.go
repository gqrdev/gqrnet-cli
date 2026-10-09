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
	redirectsJSONOutput   bool
	redirectsTimeoutSec   = 10
	redirectsMaxRedirects = 10
	redirectsFollow       = httpaudit.FollowRedirects
)

var redirectsCmd = &cobra.Command{
	Use:   "redirects [url]",
	Short: "Follow and report the HTTP redirect chain for a URL.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if redirectsTimeoutSec <= 0 {
			return errors.New("timeout must be greater than zero seconds")
		}
		if redirectsMaxRedirects <= 0 {
			return errors.New("max-redirects must be greater than zero")
		}

		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, time.Duration(redirectsTimeoutSec)*time.Second)
		defer cancel()

		result, err := redirectsFollow(ctx, args[0], redirectsMaxRedirects)
		if err != nil {
			return err
		}
		if redirectsJSONOutput {
			return output.PrintRedirectsJSON(cmd.OutOrStdout(), result)
		}
		output.PrintRedirectsText(cmd.OutOrStdout(), result)
		return nil
	},
}

func init() {
	redirectsCmd.Flags().BoolVar(&redirectsJSONOutput, "json", false, "Output results in JSON format")
	redirectsCmd.Flags().IntVar(&redirectsTimeoutSec, "timeout", 10, "Execution timeout in seconds")
	redirectsCmd.Flags().IntVar(&redirectsMaxRedirects, "max-redirects", 10, "Maximum number of redirects to follow")
	redirectsCmd.Flags().IntVar(&redirectsMaxRedirects, "max-hops", 10, "Maximum number of redirects to follow")
	_ = redirectsCmd.Flags().MarkDeprecated("max-hops", "use --max-redirects instead")

	RootCmd.AddCommand(redirectsCmd)
}
