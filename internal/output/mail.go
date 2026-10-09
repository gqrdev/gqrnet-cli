package output

import (
	"encoding/json"
	"fmt"
	"io"

	mailaudit "github.com/gqrdev/gqrnet-cli/internal/mail"
)

// PrintMailJSON writes a mail configuration result as indented JSON.
func PrintMailJSON(w io.Writer, result mailaudit.Result) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// PrintMailText presents MX, SPF, and DMARC checks in a human-readable format.
func PrintMailText(w io.Writer, result mailaudit.Result) {
	fmt.Fprintf(w, "=== Target Domain: %s ===\n", result.Domain)
	printMailCheck(w, "MX", result.MX)
	printMailCheck(w, "SPF", result.SPF)
	printMailCheck(w, "DMARC", result.DMARC)
	fmt.Fprintf(w, "\nDuration: %d ms\n", result.DurationMS)
}

func printMailCheck(w io.Writer, name string, check mailaudit.CheckResult) {
	fmt.Fprintf(w, "\n[ %s ]\n", name)
	fmt.Fprintf(w, " Status: %s\n", check.Status)
	if check.Policy != "" {
		fmt.Fprintf(w, " Policy: %s\n", check.Policy)
	}
	if check.Detail != "" {
		fmt.Fprintf(w, " Detail: %s\n", check.Detail)
	}
	for _, record := range check.Records {
		fmt.Fprintf(w, " Record: %s\n", record)
	}
}
