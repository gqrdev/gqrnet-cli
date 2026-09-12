package output

import (
	"bytes"
	"strings"
	"testing"

	dnsquery "gqrnet/internal/dns"
)

func TestPrintDNSJSONWritesResult(t *testing.T) {
	var output bytes.Buffer
	result := dnsquery.Result{A: []string{"192.0.2.1"}, MX: []string{"mail.example.com (10)"}}

	if err := PrintDNSJSON(&output, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output.String(), `"a": [`) || !strings.Contains(output.String(), `"mx": [`) {
		t.Fatalf("JSON output is missing records: %s", output.String())
	}
}

func TestPrintDNSTextWritesDNSSectionAndError(t *testing.T) {
	var output bytes.Buffer
	PrintDNSText(&output, "example.com", dnsquery.Result{Error: "lookup failed"})

	for _, expected := range []string{
		"=== Target Domain: example.com ===",
		"[ DNS Records ]",
		"Error: lookup failed",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output does not contain %q: %s", expected, output.String())
		}
	}
}
