package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	tlsinspect "github.com/gqrdev/gqrnet-cli/internal/tls"
)

func TestPrintTLSTextIncludesCertificateAndVerificationDetails(t *testing.T) {
	result := tlsinspect.Result{
		Version:     "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Subject:     "example.com",
		Issuer:      "Test CA",
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DaysValid:   40,
		Verified:    true,
	}
	var output bytes.Buffer
	PrintTLSText(&output, "127.0.0.1", 8443, "example.com", result)

	for _, expected := range []string{
		"127.0.0.1:8443",
		"Verified:       true",
		"Server Name:    example.com",
		"Protocol:       TLS 1.3",
		"Cipher Suite:   TLS_AES_128_GCM_SHA256",
		"Subject:        example.com",
		"Issuer:         Test CA",
		"Valid From:     2026-01-01",
		"Expires:        2027-01-01",
		"Days Valid:     40",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output does not contain %q: %s", expected, output.String())
		}
	}
}

func TestPrintTLSJSONIncludesVerificationStatus(t *testing.T) {
	var output bytes.Buffer
	err := PrintTLSJSON(&output, "example.com", 443, "", tlsinspect.Result{
		Version:  "TLS 1.3",
		Verified: true,
	})
	if err != nil {
		t.Fatalf("PrintTLSJSON returned error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON output: %v", err)
	}
	for key, expected := range map[string]any{
		"host":     "example.com",
		"port":     float64(443),
		"version":  "TLS 1.3",
		"verified": true,
	} {
		if result[key] != expected {
			t.Errorf("JSON field %q = %#v, want %#v", key, result[key], expected)
		}
	}
}

func TestPrintTLSTextMarksFailedVerification(t *testing.T) {
	var output bytes.Buffer
	PrintTLSText(&output, "example.com", 443, "", tlsinspect.Result{
		Error: "certificate verification failed",
	})
	if !strings.Contains(output.String(), "Verified:       false") ||
		!strings.Contains(output.String(), "Error:          certificate verification failed") {
		t.Errorf("TLS failure output does not report failed verification: %s", output.String())
	}
}
