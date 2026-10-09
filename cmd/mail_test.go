package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	mailaudit "github.com/gqrdev/gqrnet-cli/internal/mail"
)

func TestMailCommandPassesOptionsAndPrintsJSON(t *testing.T) {
	oldJSON, oldTimeout, oldServer, oldScan := mailJSONOutput, mailTimeoutSec, mailServer, mailScan
	t.Cleanup(func() {
		mailJSONOutput, mailTimeoutSec, mailServer, mailScan = oldJSON, oldTimeout, oldServer, oldScan
	})
	mailJSONOutput = true
	mailTimeoutSec = 3
	mailServer = "1.1.1.1"
	mailScan = func(ctx context.Context, domain, server string) mailaudit.Result {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("mail scan context has no deadline")
		}
		if domain != "example.com" || server != "1.1.1.1:53" {
			t.Errorf("Scan(%q, %q), want normalized domain and server", domain, server)
		}
		return mailaudit.Result{Domain: domain, MX: mailaudit.CheckResult{Status: mailaudit.StatusConfigured}}
	}

	var output bytes.Buffer
	mailCmd.SetOut(&output)
	t.Cleanup(func() { mailCmd.SetOut(nil) })
	if err := mailCmd.RunE(mailCmd, []string{"example.com."}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	var result mailaudit.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if result.Domain != "example.com" || result.MX.Status != mailaudit.StatusConfigured {
		t.Fatalf("result = %#v", result)
	}
}

func TestMailCommandRejectsInvalidOptionsBeforeScanning(t *testing.T) {
	oldTimeout, oldServer, oldScan := mailTimeoutSec, mailServer, mailScan
	t.Cleanup(func() { mailTimeoutSec, mailServer, mailScan = oldTimeout, oldServer, oldScan })
	mailScan = func(context.Context, string, string) mailaudit.Result {
		t.Fatal("mail scan called with invalid options")
		return mailaudit.Result{}
	}

	mailTimeoutSec = 0
	if err := mailCmd.RunE(mailCmd, []string{"example.com"}); err == nil {
		t.Fatal("expected timeout validation error")
	}
	mailTimeoutSec = 10
	mailServer = "invalid/server"
	if err := mailCmd.RunE(mailCmd, []string{"example.com"}); err == nil {
		t.Fatal("expected DNS server validation error")
	}
	mailServer = ""
	if err := mailCmd.RunE(mailCmd, []string{"https://example.com"}); err == nil {
		t.Fatal("expected invalid hostname error")
	}
}

func TestMailCommandTextOutputIncludesChecks(t *testing.T) {
	oldJSON, oldTimeout, oldScan := mailJSONOutput, mailTimeoutSec, mailScan
	t.Cleanup(func() { mailJSONOutput, mailTimeoutSec, mailScan = oldJSON, oldTimeout, oldScan })
	mailJSONOutput = false
	mailTimeoutSec = 2
	mailScan = func(_ context.Context, domain, _ string) mailaudit.Result {
		return mailaudit.Result{
			Domain: domain,
			MX:     mailaudit.CheckResult{Status: mailaudit.StatusMissing},
			SPF:    mailaudit.CheckResult{Status: mailaudit.StatusConfigured},
			DMARC:  mailaudit.CheckResult{Status: mailaudit.StatusIndeterminate},
		}
	}
	var output bytes.Buffer
	mailCmd.SetOut(&output)
	t.Cleanup(func() { mailCmd.SetOut(nil) })
	if err := mailCmd.RunE(mailCmd, []string{"example.com"}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	for _, status := range []string{"[ MX ]", "Status: missing", "[ SPF ]", "Status: configured", "[ DMARC ]", "Status: indeterminate"} {
		if !strings.Contains(output.String(), status) {
			t.Errorf("output missing %q: %s", status, output.String())
		}
	}
}
