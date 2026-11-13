package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	tlsinspect "github.com/gqrdev/gqrnet-cli/internal/tls"
)

func TestTLSCommandRequiresExactlyOneHost(t *testing.T) {
	if err := tlsCmd.Args(tlsCmd, nil); err == nil {
		t.Fatal("expected an error when the host is missing")
	}
	if err := tlsCmd.Args(tlsCmd, []string{"example.com", "extra"}); err == nil {
		t.Fatal("expected an error when more than one host is provided")
	}
	if err := tlsCmd.Args(tlsCmd, []string{"example.com"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTLSCommandUsesInspectorOptionsAndJSONOutput(t *testing.T) {
	oldTimeout, oldPort, oldServerName := tlsTimeoutSec, tlsPort, tlsServerName
	oldJSON, oldInspect := tlsJSONOutput, tlsInspect
	t.Cleanup(func() {
		tlsTimeoutSec, tlsPort, tlsServerName = oldTimeout, oldPort, oldServerName
		tlsJSONOutput, tlsInspect = oldJSON, oldInspect
	})

	tlsTimeoutSec = 4
	tlsPort = 8443
	tlsServerName = "example.com."
	tlsJSONOutput = true
	var gotHost string
	var gotOptions tlsinspect.Options
	var gotTimeout time.Duration
	tlsInspect = func(ctx context.Context, host string, options tlsinspect.Options) tlsinspect.Result {
		gotHost = host
		gotOptions = options
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("inspection context has no timeout")
		}
		gotTimeout = time.Until(deadline).Round(time.Second)
		return tlsinspect.Result{Version: "TLS 1.3", Verified: true}
	}

	var output bytes.Buffer
	tlsCmd.SetOut(&output)
	t.Cleanup(func() { tlsCmd.SetOut(nil) })

	if err := tlsCmd.RunE(tlsCmd, []string{"::1"}); err != nil {
		t.Fatalf("unexpected command error: %v", err)
	}
	if gotHost != "::1" {
		t.Errorf("host = %q, want %q", gotHost, "::1")
	}
	if gotOptions != (tlsinspect.Options{Port: 8443, ServerName: "example.com"}) {
		t.Errorf("inspector options = %#v", gotOptions)
	}
	if gotTimeout != 4*time.Second {
		t.Errorf("timeout = %v, want %v", gotTimeout, 4*time.Second)
	}
	if !strings.Contains(output.String(), `"verified": true`) {
		t.Errorf("JSON output missing verification status: %s", output.String())
	}
}

func TestTLSCommandRejectsInvalidInputsBeforeInspecting(t *testing.T) {
	oldTimeout, oldPort, oldServerName := tlsTimeoutSec, tlsPort, tlsServerName
	oldInspect := tlsInspect
	t.Cleanup(func() {
		tlsTimeoutSec, tlsPort, tlsServerName = oldTimeout, oldPort, oldServerName
		tlsInspect = oldInspect
	})

	tlsTimeoutSec = 10
	tlsPort = 443
	tlsServerName = ""
	tlsInspect = func(context.Context, string, tlsinspect.Options) tlsinspect.Result {
		t.Fatal("inspector should not be called for invalid input")
		return tlsinspect.Result{}
	}

	for _, target := range []string{"", "https://example.com", "example.com:443", "example..com", "[::1]", "2001:db8::bad:address"} {
		if err := tlsCmd.RunE(tlsCmd, []string{target}); err == nil {
			t.Errorf("RunE(%q) succeeded, want validation error", target)
		}
	}

	tlsPort = 0
	if err := tlsCmd.RunE(tlsCmd, []string{"example.com"}); err == nil {
		t.Error("port 0 was accepted")
	}
	tlsPort = 65536
	if err := tlsCmd.RunE(tlsCmd, []string{"example.com"}); err == nil {
		t.Error("port 65536 was accepted")
	}
	tlsPort = 443
	tlsTimeoutSec = 0
	if err := tlsCmd.RunE(tlsCmd, []string{"example.com"}); err == nil {
		t.Error("timeout 0 was accepted")
	}
	tlsTimeoutSec = 10
	tlsServerName = "127.0.0.1"
	if err := tlsCmd.RunE(tlsCmd, []string{"example.com"}); err == nil {
		t.Error("IP address was accepted as an SNI server name")
	}
}

func TestNormalizeTLSHostAcceptsHostnameAndIP(t *testing.T) {
	for input, expected := range map[string]string{
		"example.com.": "example.com",
		"127.0.0.1":    "127.0.0.1",
		"2001:db8::1":  "2001:db8::1",
	} {
		got, err := normalizeTLSHost(input)
		if err != nil {
			t.Errorf("normalizeTLSHost(%q) error = %v", input, err)
		} else if got != expected {
			t.Errorf("normalizeTLSHost(%q) = %q, want %q", input, got, expected)
		}
	}
}
