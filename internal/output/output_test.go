package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	dnsquery "github.com/gqrdev/gqrnet-cli/internal/dns"
	"github.com/gqrdev/gqrnet-cli/internal/domain"
	httpresult "github.com/gqrdev/gqrnet-cli/internal/http"
)

func TestPrintJSONWritesValidResult(t *testing.T) {
	var output bytes.Buffer
	result := domain.DomainResult{
		Domain: "example.com",
		HTTPS:  httpresult.Result{StatusCode: 200},
	}

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
	if decoded.HTTPS.StatusCode != result.HTTPS.StatusCode {
		t.Fatalf("HTTPS status code = %d, want %d", decoded.HTTPS.StatusCode, result.HTTPS.StatusCode)
	}
}

func TestPrintTextWritesAllSections(t *testing.T) {
	var output bytes.Buffer
	PrintText(&output, domain.DomainResult{
		Domain: "example.com",
		DNS: dnsquery.Result{
			CNAME: []string{"www.example.com"},
			Error: "MX: DNS server returned SERVFAIL",
		},
		HTTPS: httpresult.Result{
			StatusCode:  302,
			RedirectURL: "https://www.example.com",
		},
	})

	for _, section := range []string{
		"=== Target Domain: example.com ===",
		"[ Network Resolution ]",
		"[ DNS Records ]",
		"Error: MX: DNS server returned SERVFAIL",
		"CNAME: www.example.com",
		"[ HTTP Status ]",
		"[ HTTPS Status ]",
		"Status Code:    302",
		"Redirects To:   https://www.example.com",
		"[ TLS Certificate ]",
	} {
		if !strings.Contains(output.String(), section) {
			t.Errorf("output does not contain %q", section)
		}
	}
}
