package output

import (
	"encoding/json"
	"fmt"
	"io"

	httpaudit "github.com/gqrdev/gqrnet-cli/internal/http"
)

type httpJSONResult struct {
	URL             string                      `json:"url"`
	StatusCode      int                         `json:"status_code"`
	Status          string                      `json:"status"`
	Protocol        string                      `json:"protocol"`
	ResponseTimeMS  int64                       `json:"response_time_ms"`
	Error           string                      `json:"error,omitempty"`
	SecurityHeaders *[]httpaudit.SecurityHeader `json:"security_headers,omitempty"`
	Cookies         *[]httpaudit.CookieAudit    `json:"cookies,omitempty"`
	Redirect        *httpaudit.RedirectAudit    `json:"redirect,omitempty"`
	TLS             *httpaudit.TLSAudit         `json:"tls,omitempty"`
}

// PrintHTTPJSON writes an HTTP audit result, including only selected sections.
func PrintHTTPJSON(w io.Writer, result httpaudit.AuditResult, sections httpaudit.AuditSections) error {
	formatted := httpJSONResult{
		URL:            result.URL,
		StatusCode:     result.StatusCode,
		Status:         result.Status,
		Protocol:       result.Protocol,
		ResponseTimeMS: result.ResponseTimeMS,
		Error:          result.Error,
	}
	if sections.IncludesAll() || sections.Headers {
		formatted.SecurityHeaders = &result.SecurityHeaders
	}
	if sections.IncludesAll() || sections.Cookies {
		formatted.Cookies = &result.Cookies
	}
	if sections.IncludesAll() || sections.Redirects {
		formatted.Redirect = result.Redirect
	}
	if sections.IncludesAll() || sections.TLS {
		formatted.TLS = result.TLS
	}
	data, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// PrintHTTPText presents a human-readable HTTP security audit.
func PrintHTTPText(w io.Writer, result httpaudit.AuditResult, sections httpaudit.AuditSections) {
	fmt.Fprintf(w, "=== Target URL: %s ===\n\n", result.URL)
	fmt.Fprintln(w, "[ HTTP Response ]")
	if result.Error != "" {
		fmt.Fprintf(w, " Error: %s\n", result.Error)
	} else {
		fmt.Fprintf(w, " Status:         %s\n", result.Status)
		fmt.Fprintf(w, " Protocol:       %s\n", result.Protocol)
		fmt.Fprintf(w, " Response Time:  %d ms\n", result.ResponseTimeMS)
	}

	if sections.IncludesAll() || sections.Headers {
		fmt.Fprintln(w, "\n[ Security Headers ]")
		if result.Error != "" {
			fmt.Fprintln(w, " Not available")
		} else {
			for _, header := range result.SecurityHeaders {
				switch {
				case !header.Applicable:
					fmt.Fprintf(w, " %s: not applicable\n", header.Name)
				case !header.Present:
					fmt.Fprintf(w, " %s: missing\n", header.Name)
				default:
					fmt.Fprintf(w, " %s: %s\n", header.Name, header.Value)
				}
			}
		}
	}

	if sections.IncludesAll() || sections.Cookies {
		fmt.Fprintln(w, "\n[ Cookies ]")
		if result.Error != "" {
			fmt.Fprintln(w, " Not available")
		} else if len(result.Cookies) == 0 {
			fmt.Fprintln(w, " No cookies set")
		} else {
			for _, cookie := range result.Cookies {
				fmt.Fprintf(w, " %s: Secure=%t, HttpOnly=%t, SameSite=%s\n", cookie.Name, cookie.Secure, cookie.HTTPOnly, cookie.SameSite)
			}
		}
	}

	if sections.IncludesAll() || sections.Redirects {
		fmt.Fprintln(w, "\n[ Redirect ]")
		if result.Error != "" {
			fmt.Fprintln(w, " Not available")
		} else if result.Redirect == nil || result.Redirect.Location == "" {
			fmt.Fprintln(w, " None")
		} else {
			fmt.Fprintf(w, " Location: %s\n", result.Redirect.Location)
		}
	}

	if sections.IncludesAll() || sections.TLS {
		fmt.Fprintln(w, "\n[ TLS ]")
		switch {
		case result.Error != "":
			fmt.Fprintln(w, " Not available")
		case result.TLS == nil || !result.TLS.Applicable:
			fmt.Fprintln(w, " Not applicable")
		case result.TLS.Version == "":
			fmt.Fprintln(w, " No certificate details available")
		default:
			fmt.Fprintf(w, " Verified:       %t\n", result.TLS.Verified)
			fmt.Fprintf(w, " Version:        %s\n", result.TLS.Version)
			fmt.Fprintf(w, " Cipher Suite:   %s\n", result.TLS.CipherSuite)
			fmt.Fprintf(w, " Subject:        %s\n", result.TLS.Subject)
			fmt.Fprintf(w, " Issuer:         %s\n", result.TLS.Issuer)
			fmt.Fprintf(w, " Valid From:     %s\n", result.TLS.NotBefore.Format("2006-01-02"))
			fmt.Fprintf(w, " Expires:        %s (%d days)\n", result.TLS.NotAfter.Format("2006-01-02"), result.TLS.DaysValid)
		}
	}
}
