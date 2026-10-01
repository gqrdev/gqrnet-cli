package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	httpaudit "github.com/gqrdev/gqrnet-cli/internal/http"
)

func TestHTTPCommandPrintsAllSectionsByDefault(t *testing.T) {
	oldJSON, oldTimeout := httpJSONOutput, httpTimeoutSec
	oldHeaders, oldCookies, oldTLS, oldRedirect := httpShowHeaders, httpShowCookies, httpShowTLS, httpShowRedirect
	oldAudit := httpAudit
	t.Cleanup(func() {
		httpJSONOutput, httpTimeoutSec = oldJSON, oldTimeout
		httpShowHeaders, httpShowCookies, httpShowTLS, httpShowRedirect = oldHeaders, oldCookies, oldTLS, oldRedirect
		httpAudit = oldAudit
	})

	httpJSONOutput = false
	httpTimeoutSec = 4
	httpShowHeaders, httpShowCookies, httpShowTLS, httpShowRedirect = false, false, false, false
	var gotTarget string
	httpAudit = func(_ context.Context, target string) (httpaudit.AuditResult, error) {
		gotTarget = target
		return httpaudit.AuditResult{
			URL:        target,
			StatusCode: 200,
			Status:     "200 OK",
			Protocol:   "HTTP/1.1",
			SecurityHeaders: []httpaudit.SecurityHeader{
				{Name: "Content-Security-Policy", Present: true, Applicable: true, Value: "default-src 'self'"},
			},
			Cookies:  []httpaudit.CookieAudit{{Name: "session", HTTPOnly: true, SameSite: "Lax"}},
			Redirect: &httpaudit.RedirectAudit{},
			TLS:      &httpaudit.TLSAudit{Applicable: false},
		}, nil
	}

	var output bytes.Buffer
	httpCmd.SetOut(&output)
	t.Cleanup(func() { httpCmd.SetOut(nil) })
	if err := httpCmd.RunE(httpCmd, []string{"https://example.com/login"}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	if gotTarget != "https://example.com/login" {
		t.Errorf("target = %q, want full URL", gotTarget)
	}
	for _, section := range []string{"[ Security Headers ]", "[ Cookies ]", "[ TLS ]", "[ Redirect ]"} {
		if !strings.Contains(output.String(), section) {
			t.Errorf("default output missing %q: %s", section, output.String())
		}
	}
}

func TestHTTPCommandJSONIncludesOnlySelectedSections(t *testing.T) {
	oldJSON, oldTimeout := httpJSONOutput, httpTimeoutSec
	oldHeaders, oldCookies, oldTLS, oldRedirect := httpShowHeaders, httpShowCookies, httpShowTLS, httpShowRedirect
	oldAudit := httpAudit
	t.Cleanup(func() {
		httpJSONOutput, httpTimeoutSec = oldJSON, oldTimeout
		httpShowHeaders, httpShowCookies, httpShowTLS, httpShowRedirect = oldHeaders, oldCookies, oldTLS, oldRedirect
		httpAudit = oldAudit
	})

	httpJSONOutput = true
	httpTimeoutSec = 3
	httpShowHeaders, httpShowCookies, httpShowTLS, httpShowRedirect = true, false, false, false
	httpAudit = func(_ context.Context, target string) (httpaudit.AuditResult, error) {
		return httpaudit.AuditResult{URL: target, StatusCode: 200, SecurityHeaders: []httpaudit.SecurityHeader{{Name: "Content-Security-Policy", Present: true}}}, nil
	}

	var output bytes.Buffer
	httpCmd.SetOut(&output)
	t.Cleanup(func() { httpCmd.SetOut(nil) })
	if err := httpCmd.RunE(httpCmd, []string{"https://example.com"}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	if !strings.Contains(output.String(), `"security_headers"`) || strings.Contains(output.String(), `"cookies"`) {
		t.Errorf("JSON does not respect section selection: %s", output.String())
	}
}

func TestHTTPCommandRejectsNonPositiveTimeout(t *testing.T) {
	oldTimeout := httpTimeoutSec
	oldAudit := httpAudit
	t.Cleanup(func() {
		httpTimeoutSec = oldTimeout
		httpAudit = oldAudit
	})
	httpTimeoutSec = 0
	httpAudit = func(context.Context, string) (httpaudit.AuditResult, error) {
		t.Fatal("audit called despite invalid timeout")
		return httpaudit.AuditResult{}, nil
	}
	if err := httpCmd.RunE(httpCmd, []string{"https://example.com"}); err == nil {
		t.Fatal("expected timeout validation error")
	}
}
