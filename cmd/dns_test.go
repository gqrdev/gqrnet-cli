package cmd

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	dnsquery "github.com/gqrdev/gqrnet-cli/internal/dns"
	"github.com/miekg/dns"
)

func TestNormalizeDomainTarget(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "example.com", want: "example.com"},
		{input: "example.com.", want: "example.com"},
	} {
		got, err := normalizeDomainTarget(test.input)
		if err != nil {
			t.Fatalf("normalizeDomainTarget(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Errorf("normalizeDomainTarget(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	for _, input := range []string{"https://example.com", "example.com:443", "example..com", "127.0.0.1"} {
		if _, err := normalizeDomainTarget(input); err == nil {
			t.Errorf("normalizeDomainTarget(%q) succeeded, want error", input)
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
	types, err = parseDNSTypes([]string{"CAA", "SRV", "SVCB", "HTTPS"})
	if err != nil || len(types) != 4 {
		t.Fatalf("parseDNSTypes for extended types = %v, %v; want four types", types, err)
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

func TestDNSReverseCommandQueriesPTRForIPv4AndIPv6(t *testing.T) {
	oldJSON, oldTimeout, oldServer, oldQuery := dnsJSONOutput, dnsTimeoutSec, dnsServer, dnsQuery
	t.Cleanup(func() {
		dnsJSONOutput, dnsTimeoutSec, dnsServer, dnsQuery = oldJSON, oldTimeout, oldServer, oldQuery
	})
	dnsJSONOutput = false
	dnsTimeoutSec = 3
	dnsServer = "1.1.1.1"
	var gotTarget string
	var gotOptions dnsquery.Options
	dnsQuery = func(_ context.Context, target string, options dnsquery.Options) dnsquery.Result {
		gotTarget = target
		gotOptions = options
		return dnsquery.Result{PTR: []string{"host.example.com."}}
	}

	var output bytes.Buffer
	dnsReverseCmd.SetOut(&output)
	t.Cleanup(func() { dnsReverseCmd.SetOut(nil) })
	for _, input := range []string{"192.0.2.1", "2001:db8::1"} {
		ip := net.ParseIP(input)
		wantTarget, err := dns.ReverseAddr(ip.String())
		if err != nil {
			t.Fatalf("ReverseAddr(%q): %v", input, err)
		}
		if err := dnsReverseCmd.RunE(dnsReverseCmd, []string{input}); err != nil {
			t.Fatalf("reverse lookup for %q: %v", input, err)
		}
		if gotTarget != wantTarget {
			t.Errorf("query target = %q, want %q", gotTarget, wantTarget)
		}
		if gotOptions.Server != "1.1.1.1:53" || len(gotOptions.Types) != 1 || gotOptions.Types[0] != dns.TypePTR {
			t.Errorf("query options = %#v, want normalized server and PTR only", gotOptions)
		}
		if !strings.Contains(output.String(), "PTR:   host.example.com.") {
			t.Errorf("reverse output is missing PTR record: %s", output.String())
		}
		output.Reset()
	}
}

func TestDNSReverseCommandRejectsHostnames(t *testing.T) {
	if err := dnsReverseCmd.RunE(dnsReverseCmd, []string{"example.com"}); err == nil {
		t.Fatal("expected hostname to be rejected")
	}
}

func TestDNSReverseCommandPrintsJSON(t *testing.T) {
	oldJSON, oldTimeout, oldServer, oldQuery := dnsJSONOutput, dnsTimeoutSec, dnsServer, dnsQuery
	t.Cleanup(func() {
		dnsJSONOutput, dnsTimeoutSec, dnsServer, dnsQuery = oldJSON, oldTimeout, oldServer, oldQuery
	})
	dnsJSONOutput = true
	dnsTimeoutSec = 3
	dnsServer = ""
	dnsQuery = func(_ context.Context, _ string, _ dnsquery.Options) dnsquery.Result {
		return dnsquery.Result{PTR: []string{"host.example.com."}}
	}

	var output bytes.Buffer
	dnsReverseCmd.SetOut(&output)
	t.Cleanup(func() { dnsReverseCmd.SetOut(nil) })
	if err := dnsReverseCmd.RunE(dnsReverseCmd, []string{"192.0.2.1"}); err != nil {
		t.Fatalf("reverse lookup returned error: %v", err)
	}
	if !strings.Contains(output.String(), `"ptr": [`) {
		t.Fatalf("JSON output does not contain PTR records: %s", output.String())
	}
}
