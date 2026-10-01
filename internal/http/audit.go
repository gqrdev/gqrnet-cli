package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AuditResult contains passive security observations for a single HTTP URL.
type AuditResult struct {
	URL             string           `json:"url"`
	StatusCode      int              `json:"status_code"`
	Status          string           `json:"status"`
	Protocol        string           `json:"protocol"`
	ResponseTimeMS  int64            `json:"response_time_ms"`
	Error           string           `json:"error,omitempty"`
	SecurityHeaders []SecurityHeader `json:"security_headers,omitempty"`
	Cookies         []CookieAudit    `json:"cookies,omitempty"`
	Redirect        *RedirectAudit   `json:"redirect,omitempty"`
	TLS             *TLSAudit        `json:"tls,omitempty"`
}

// SecurityHeader records whether a security-related response header was sent.
type SecurityHeader struct {
	Name       string `json:"name"`
	Present    bool   `json:"present"`
	Applicable bool   `json:"applicable"`
	Value      string `json:"value,omitempty"`
}

// CookieAudit reports cookie security attributes without retaining its value.
type CookieAudit struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

// RedirectAudit reports the first redirect without following it.
type RedirectAudit struct {
	Location string `json:"location,omitempty"`
}

// TLSAudit contains metadata from the connection used for the HTTP request.
type TLSAudit struct {
	Applicable  bool      `json:"applicable"`
	Verified    bool      `json:"verified,omitempty"`
	Version     string    `json:"version,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	DaysValid   int       `json:"days_valid,omitempty"`
}

// AuditSections selects which detailed sections are included in output.
// When no section is selected, all sections are included.
type AuditSections struct {
	Headers   bool
	Cookies   bool
	TLS       bool
	Redirects bool
}

// IncludesAll reports whether no section filter was supplied.
func (s AuditSections) IncludesAll() bool {
	return !s.Headers && !s.Cookies && !s.TLS && !s.Redirects
}

// AuditURL performs one passive GET request and reports security-related metadata.
func AuditURL(ctx context.Context, target string) (AuditResult, error) {
	return auditURL(ctx, target, nil)
}

func auditURL(ctx context.Context, target string, transport http.RoundTripper) (AuditResult, error) {
	targetURL, err := parseAuditURL(target)
	if err != nil {
		return AuditResult{}, err
	}

	result := AuditResult{URL: sanitizeAuditURL(targetURL)}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return AuditResult{}, err
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		result.Error = sanitizeRequestError(err, targetURL)
		return result, nil
	}
	defer response.Body.Close()

	result.ResponseTimeMS = time.Since(started).Milliseconds()
	result.StatusCode = response.StatusCode
	result.Status = response.Status
	result.Protocol = response.Proto
	result.SecurityHeaders = auditSecurityHeaders(response.Header, targetURL.Scheme == "https")
	result.Cookies = auditCookies(response.Cookies())
	result.Redirect = auditRedirect(targetURL, response.Header.Get("Location"))
	result.TLS = auditTLS(response.TLS, targetURL.Scheme == "https")
	return result, nil
}

func parseAuditURL(target string) (*url.URL, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, errors.New("target must be a valid absolute HTTP or HTTPS URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" || parsed.User != nil {
		return nil, errors.New("target must be an absolute HTTP or HTTPS URL without credentials")
	}
	if strings.Contains(parsed.Host, ":") && parsed.Port() == "" && !strings.HasSuffix(parsed.Host, "]") {
		return nil, errors.New("target must contain a valid port")
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, errors.New("target must contain a valid port")
		}
	}
	return parsed, nil
}

func sanitizeAuditURL(target *url.URL) string {
	sanitized := *target
	sanitized.User = nil
	sanitized.Fragment = ""
	if sanitized.RawQuery != "" || sanitized.ForceQuery {
		sanitized.RawQuery = "%5Bquery-redacted%5D"
		sanitized.ForceQuery = false
	}
	return sanitized.String()
}

func sanitizeRequestError(err error, target *url.URL) string {
	requestURL := *target
	requestURL.Fragment = ""
	return strings.ReplaceAll(err.Error(), requestURL.String(), sanitizeAuditURL(&requestURL))
}

func auditSecurityHeaders(headers http.Header, https bool) []SecurityHeader {
	checks := []struct {
		name       string
		applicable bool
	}{
		{name: "Strict-Transport-Security", applicable: https},
		{name: "Content-Security-Policy", applicable: true},
		{name: "X-Content-Type-Options", applicable: true},
		{name: "X-Frame-Options", applicable: true},
		{name: "Referrer-Policy", applicable: true},
		{name: "Permissions-Policy", applicable: true},
		{name: "Cross-Origin-Opener-Policy", applicable: true},
		{name: "Cross-Origin-Resource-Policy", applicable: true},
		{name: "Cross-Origin-Embedder-Policy", applicable: true},
	}

	results := make([]SecurityHeader, 0, len(checks))
	for _, check := range checks {
		values, present := headers[http.CanonicalHeaderKey(check.name)]
		results = append(results, SecurityHeader{
			Name:       check.name,
			Present:    present && len(values) > 0,
			Applicable: check.applicable,
			Value:      strings.Join(values, ", "),
		})
	}
	return results
}

func auditCookies(cookies []*http.Cookie) []CookieAudit {
	results := make([]CookieAudit, 0, len(cookies))
	for _, cookie := range cookies {
		results = append(results, CookieAudit{
			Name:     cookie.Name,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
			SameSite: sameSiteName(cookie.SameSite),
		})
	}
	return results
}

func sameSiteName(mode http.SameSite) string {
	switch mode {
	case http.SameSiteDefaultMode:
		return "unspecified"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "unknown"
	}
}

func auditRedirect(base *url.URL, location string) *RedirectAudit {
	redirect := &RedirectAudit{}
	if location == "" {
		return redirect
	}
	parsed, err := base.Parse(location)
	if err != nil {
		redirect.Location = "[invalid redirect URL]"
		return redirect
	}
	redirect.Location = sanitizeAuditURL(parsed)
	return redirect
}

func auditTLS(state *tls.ConnectionState, https bool) *TLSAudit {
	result := &TLSAudit{Applicable: https}
	if !https || state == nil || len(state.PeerCertificates) == 0 {
		return result
	}

	certificate := state.PeerCertificates[0]
	result.Verified = len(state.VerifiedChains) > 0
	result.Version = tlsVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.Subject = certificate.Subject.CommonName
	result.Issuer = certificate.Issuer.CommonName
	result.NotBefore = certificate.NotBefore
	result.NotAfter = certificate.NotAfter
	result.DaysValid = int(time.Until(certificate.NotAfter).Hours() / 24)
	return result
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%x)", version)
	}
}
