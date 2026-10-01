package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditURLCollectsPassiveSecurityDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret-value", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := auditURL(context.Background(), server.URL+"/account?token=secret", nil)
	if err != nil {
		t.Fatalf("auditURL returned error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected request error: %s", result.Error)
	}
	if result.URL != server.URL+"/account?%5Bquery-redacted%5D" {
		t.Errorf("result URL = %q, want query redacted", result.URL)
	}
	if result.StatusCode != http.StatusOK || result.Protocol == "" {
		t.Errorf("incomplete HTTP result: %#v", result)
	}
	if !strings.Contains(strings.Join(headerNames(result.SecurityHeaders), ","), "Content-Security-Policy") {
		t.Fatal("security header checks do not include Content-Security-Policy")
	}
	if len(result.Cookies) != 1 || result.Cookies[0].Name != "session" || !result.Cookies[0].HTTPOnly || result.Cookies[0].SameSite != "Lax" {
		t.Errorf("cookie audit = %#v, want only security attributes", result.Cookies)
	}
	if result.TLS == nil || result.TLS.Applicable {
		t.Errorf("TLS result = %#v, want not applicable", result.TLS)
	}
}

func TestAuditURLDoesNotFollowRedirectAndRedactsQuery(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/" {
			http.Redirect(w, r, "https://other.example/private?access_token=secret", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := auditURL(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("auditURL returned error: %v", err)
	}
	if result.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", result.StatusCode, http.StatusFound)
	}
	if result.Redirect == nil || result.Redirect.Location != "https://other.example/private?%5Bquery-redacted%5D" {
		t.Errorf("redirect = %#v, want redacted location", result.Redirect)
	}
	if requestCount != 1 {
		t.Errorf("request count = %d, want one request", requestCount)
	}
}

func TestAuditURLIncludesVerifiedTLSDetails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := auditURL(context.Background(), server.URL+"/secure", server.Client().Transport)
	if err != nil {
		t.Fatalf("auditURL returned error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected request error: %s", result.Error)
	}
	if result.TLS == nil || !result.TLS.Applicable || !result.TLS.Verified || result.TLS.Version == "" {
		t.Errorf("TLS result = %#v, want verified TLS details", result.TLS)
	}
	if len(result.SecurityHeaders) == 0 || !result.SecurityHeaders[0].Present {
		t.Errorf("HSTS result = %#v, want present", result.SecurityHeaders)
	}
}

func TestAuditURLRedactsQueryFromRequestErrors(t *testing.T) {
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("request failed for %s", request.URL)
	})
	result, err := auditURL(context.Background(), "https://example.com/login?token=secret", transport)
	if err != nil {
		t.Fatalf("auditURL returned error: %v", err)
	}
	if strings.Contains(result.Error, "secret") {
		t.Fatalf("request error exposed query value: %s", result.Error)
	}
}

func TestParseAuditURLValidation(t *testing.T) {
	for _, target := range []string{
		"example.com",
		"ftp://example.com",
		"https://user:pass@example.com",
		"https://example.com:99999",
		"https:///path",
	} {
		t.Run(target, func(t *testing.T) {
			if _, err := parseAuditURL(target); err == nil {
				t.Fatalf("parseAuditURL(%q) succeeded, want error", target)
			}
		})
	}
	if _, err := parseAuditURL("https://example.com:8443/account"); err != nil {
		t.Fatalf("valid URL with custom port rejected: %v", err)
	}
}

func headerNames(headers []SecurityHeader) []string {
	names := make([]string, 0, len(headers))
	for _, header := range headers {
		names = append(names, header.Name)
	}
	return names
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
