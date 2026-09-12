package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	dnsquery "gqrnet/internal/dns"
)

func TestNormalizeDNSDomain(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "example.com", want: "example.com"},
		{input: "example.com.", want: "example.com"},
	} {
		got, err := normalizeDNSDomain(test.input)
		if err != nil {
			t.Fatalf("normalizeDNSDomain(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Errorf("normalizeDNSDomain(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	for _, input := range []string{"https://example.com", "example.com:443", "example..com", "127.0.0.1"} {
		if _, err := normalizeDNSDomain(input); err == nil {
			t.Errorf("normalizeDNSDomain(%q) succeeded, want error", input)
		}
	}
}

func TestParseDNSTypesIsCaseInsensitiveAndRepeatable(t *testing.T) {
	types, err := parseDNSTypes([]string{"a", "Mx"})
	if err != nil {
		t.Fatalf("parseDNSTypes returned error: %v", err)
	}
	if len(types) != 2 {
		t.Fatalf("got %d types, want 2", len(types))
	}
	if _, err := parseDNSTypes([]string{"PTR"}); err == nil {
		t.Fatal("expected unsupported type error")
	}
}

func TestNormalizeDNSServerAddsDefaultPort(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "1.1.1.1", want: "1.1.1.1:53"},
		{input: "dns.google", want: "dns.google:53"},
		{input: "1.1.1.1:5353", want: "1.1.1.1:5353"},
	} {
		got, err := normalizeDNSServer(test.input)
		if err != nil {
			t.Fatalf("normalizeDNSServer(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Errorf("normalizeDNSServer(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestDNSCommandPassesOptionsAndPrintsJSON(t *testing.T) {
	oldJSON, oldTimeout, oldServer, oldTypes, oldQuery := dnsJSONOutput, dnsTimeoutSec, dnsServer, dnsTypes, dnsQuery
	t.Cleanup(func() {
		dnsJSONOutput, dnsTimeoutSec, dnsServer, dnsTypes, dnsQuery = oldJSON, oldTimeout, oldServer, oldTypes, oldQuery
	})

	dnsJSONOutput = true
	dnsTimeoutSec = 3
	dnsServer = "1.1.1.1"
	dnsTypes = []string{"a", "MX"}
	var gotTarget string
	var gotOptions dnsquery.Options
	dnsQuery = func(_ context.Context, target string, options dnsquery.Options) dnsquery.Result {
		gotTarget = target
		gotOptions = options
		return dnsquery.Result{A: []string{"192.0.2.1"}}
	}

	var output bytes.Buffer
	dnsCmd.SetOut(&output)
	t.Cleanup(func() { dnsCmd.SetOut(nil) })

	if err := dnsCmd.RunE(dnsCmd, []string{"example.com."}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotTarget != "example.com" {
		t.Fatalf("target = %q, want example.com", gotTarget)
	}
	if gotOptions.Server != "1.1.1.1:53" || len(gotOptions.Types) != 2 {
		t.Fatalf("options = %#v, want normalized server and two types", gotOptions)
	}
	if !strings.Contains(output.String(), `"a": [`) {
		t.Fatalf("JSON output does not contain A records: %s", output.String())
	}
}
