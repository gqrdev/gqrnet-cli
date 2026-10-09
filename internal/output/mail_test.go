package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	mailaudit "github.com/gqrdev/gqrnet-cli/internal/mail"
)

func TestPrintMailTextShowsStatusesAndEvidence(t *testing.T) {
	var output bytes.Buffer
	PrintMailText(&output, mailaudit.Result{
		Domain: "example.com",
		MX:     mailaudit.CheckResult{Status: mailaudit.StatusDisabled, Records: []string{". (0)"}},
		SPF:    mailaudit.CheckResult{Status: mailaudit.StatusMissing, Detail: "no SPF record found"},
		DMARC:  mailaudit.CheckResult{Status: mailaudit.StatusConfigured, Policy: "reject", Records: []string{"v=DMARC1; p=reject"}},
	})
	for _, expected := range []string{"[ MX ]", "Status: disabled", "Record: . (0)", "Status: missing", "Policy: reject", "v=DMARC1; p=reject"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output missing %q: %s", expected, output.String())
		}
	}
}

func TestPrintMailJSONPreservesCheckStates(t *testing.T) {
	var output bytes.Buffer
	result := mailaudit.Result{
		Domain: "example.com",
		MX:     mailaudit.CheckResult{Status: mailaudit.StatusIndeterminate, Detail: "DNS query failed"},
	}
	if err := PrintMailJSON(&output, result); err != nil {
		t.Fatalf("PrintMailJSON returned error: %v", err)
	}
	var decoded mailaudit.Result
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.MX.Status != mailaudit.StatusIndeterminate || decoded.Domain != result.Domain {
		t.Fatalf("decoded result = %#v", decoded)
	}
}
