package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	httpaudit "github.com/gqrdev/gqrnet-cli/internal/http"
)

func TestPrintHTTPTextShowsAllSectionsAndDoesNotExposeCookieValue(t *testing.T) {
	var output bytes.Buffer
	PrintHTTPText(&output, httpaudit.AuditResult{
		URL:        "https://example.com/login",
		Status:     "200 OK",
		Protocol:   "HTTP/2.0",
		StatusCode: 200,
		SecurityHeaders: []httpaudit.SecurityHeader{
			{Name: "Content-Security-Policy", Present: false, Applicable: true},
			{Name: "Strict-Transport-Security", Applicable: false},
		},
		Cookies:  []httpaudit.CookieAudit{{Name: "session", Secure: true, HTTPOnly: true, SameSite: "Lax"}},
		Redirect: &httpaudit.RedirectAudit{},
		TLS:      &httpaudit.TLSAudit{Applicable: true, Verified: true, Version: "TLS 1.3", DaysValid: 30},
	}, httpaudit.AuditSections{})

	for _, expected := range []string{"[ HTTP Response ]", "[ Security Headers ]", "Content-Security-Policy: missing", "[ Cookies ]", "session: Secure=true", "[ Redirect ]", "[ TLS ]", "Version:        TLS 1.3"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output missing %q: %s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "cookie-value") {
		t.Fatal("output exposed a cookie value")
	}
}

func TestPrintHTTPJSONFiltersSections(t *testing.T) {
	var output bytes.Buffer
	err := PrintHTTPJSON(&output, httpaudit.AuditResult{
		URL:             "https://example.com",
		SecurityHeaders: []httpaudit.SecurityHeader{{Name: "Content-Security-Policy", Present: true}},
		Cookies:         []httpaudit.CookieAudit{{Name: "session"}},
		Redirect:        &httpaudit.RedirectAudit{},
		TLS:             &httpaudit.TLSAudit{Applicable: true},
	}, httpaudit.AuditSections{Headers: true})
	if err != nil {
		t.Fatalf("PrintHTTPJSON returned error: %v", err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if _, ok := result["security_headers"]; !ok {
		t.Fatal("selected security_headers section missing")
	}
	for _, omitted := range []string{"cookies", "redirect", "tls"} {
		if _, ok := result[omitted]; ok {
			t.Errorf("unselected section %q included in JSON", omitted)
		}
	}
}
