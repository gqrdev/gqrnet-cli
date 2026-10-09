package output

import (
	"encoding/json"
	"fmt"
	"io"

	httpaudit "github.com/gqrdev/gqrnet-cli/internal/http"
)

// PrintRedirectsJSON writes a redirect chain as indented JSON.
func PrintRedirectsJSON(w io.Writer, result httpaudit.RedirectResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// PrintRedirectsText presents a human-readable redirect chain.
func PrintRedirectsText(w io.Writer, result httpaudit.RedirectResult) {
	fmt.Fprintf(w, "=== Redirect Chain: %s ===\n\n", result.URL)
	fmt.Fprintln(w, "[ Redirects ]")
	if len(result.Hops) == 0 {
		fmt.Fprintln(w, " None")
	}
	for index, hop := range result.Hops {
		fmt.Fprintf(w, " %d. Status: %d\n", index+1, hop.StatusCode)
		fmt.Fprintf(w, "    From: %s\n", hop.URL)
		fmt.Fprintf(w, "    To:   %s\n", hop.Location)
	}
	fmt.Fprintf(w, "\n Final URL: %s\n", result.FinalURL)
	if result.FinalStatusCode != 0 {
		fmt.Fprintf(w, " Final Status: %d\n", result.FinalStatusCode)
	}
	fmt.Fprintf(w, " Complete: %t\n", result.Complete)
	if result.Error != "" {
		fmt.Fprintf(w, " Error: %s\n", result.Error)
	}
}
