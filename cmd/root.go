package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd defines the base application command "gqrnet".
var RootCmd = &cobra.Command{
	Use:   "gqrnet",
	Short: "gqrnet is an open-source networking and infrastructure CLI utility.",
	Long:  `A fast and modular CLI designed to query DNS, TLS, HTTP, and network information.`,
}

// Execute triggers the Cobra execution pipeline.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
		os.Exit(1)
	}
}
