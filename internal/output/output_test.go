package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	dnsquery "github.com/gqrdev/gqrnet-cli/internal/dns"
	"github.com/gqrdev/gqrnet-cli/internal/domain"
)

func TestPrintJSONWritesValidResult(t *testing.T) {
	var output bytes.Buffer
	result := domain.DomainResult{Domain: "example.com"}

	if err := PrintJSON(&output, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded domain.DomainResult
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if decoded.Domain != result.Domain {
		t.Fatalf("domain = %q, want %q", decoded.Domain, result.Domain)
	}
}

func TestPrintTextWritesAllSections(t *testing.T) {
	var output bytes.Buffer
	PrintText(&output, domain.DomainResult{
		Domain: "example.com",
		DNS:    dnsquery.Result{CNAME: []string{"www.example.com"}},
	})

	for _, section := range []string{
		"=== Target Domain: example.com ===",
		"[ Network Resolution ]",
		"[ DNS Records ]",
		"CNAME: www.example.com",
		"[ HTTP Status ]",
		"[ TLS Certificate ]",
	} {
		if !strings.Contains(output.String(), section) {
			t.Errorf("output does not contain %q", section)
		}
	}
}
