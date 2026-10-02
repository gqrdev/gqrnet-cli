package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	portscan "github.com/gqrdev/gqrnet-cli/internal/port"
)

func TestPrintPortJSONIncludesDetailedResult(t *testing.T) {
	want := portscan.Result{
		Target:            "example.com",
		Protocol:          "tcp",
		StartedAt:         time.Date(2026, 10, 2, 14, 32, 10, 0, time.UTC),
		DurationMS:        42,
		TimeoutMS:         2000,
		RequestedPorts:    []int{22, 443},
		ResolvedAddresses: []portscan.Address{{IP: "192.0.2.10", Family: "ipv4"}},
		Results: []portscan.PortResult{{
			IP: "192.0.2.10", Family: "ipv4", Port: 443, Status: portscan.StateOpen,
			ConnectTimeMS: 12, ServiceHint: "https",
		}},
		Summary: portscan.Summary{AddressesChecked: 1, PortsPerAddress: 2, Open: 1, NotChecked: 1},
	}
	var output bytes.Buffer
	if err := PrintPortJSON(&output, want); err != nil {
		t.Fatalf("PrintPortJSON returned error: %v", err)
	}
	var got portscan.Result
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got.Target != want.Target || got.DurationMS != want.DurationMS || got.TimeoutMS != want.TimeoutMS {
		t.Errorf("metadata = %#v, want %#v", got, want)
	}
	if len(got.Results) != 1 || got.Results[0].ServiceHint != "https" || got.Summary.NotChecked != 1 {
		t.Errorf("detailed result = %#v, want result and summary preserved", got)
	}
}

func TestPrintPortTextIncludesChecksAndSummary(t *testing.T) {
	var output bytes.Buffer
	PrintPortText(&output, portscan.Result{
		Target:     "example.com",
		Protocol:   "tcp",
		StartedAt:  time.Date(2026, 10, 2, 14, 32, 10, 0, time.UTC),
		DurationMS: 42,
		TimeoutMS:  2000,
		ResolvedAddresses: []portscan.Address{
			{IP: "2001:db8::10", Family: "ipv6"},
		},
		Results: []portscan.PortResult{{
			IP: "2001:db8::10", Port: 443, Status: portscan.StateOpen,
			ConnectTimeMS: 12, ServiceHint: "https",
		}},
		Summary: portscan.Summary{AddressesChecked: 1, PortsPerAddress: 1, Open: 1},
	})
	for _, expected := range []string{"example.com", "2001:db8::10", "[2001:db8::10]:443", "open", "service hint: https", "Open: 1"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output missing %q: %s", expected, output.String())
		}
	}
}

func TestFullScanOutputShowsOnlyOpenPortsButKeepsSummary(t *testing.T) {
	result := portscan.Result{
		Target:   "example.com",
		Protocol: "tcp",
		FullScan: true,
		Complete: true,
		Results: []portscan.PortResult{
			{IP: "192.0.2.1", Port: 22, Status: portscan.StateClosed},
			{IP: "192.0.2.1", Port: 443, Status: portscan.StateOpen},
		},
		Summary: portscan.Summary{Open: 1, Closed: 1, PortsPerAddress: 65535},
	}

	var text bytes.Buffer
	PrintPortText(&text, result)
	if !strings.Contains(text.String(), "[ Open TCP Ports ]") || !strings.Contains(text.String(), "192.0.2.1:443: open") {
		t.Fatalf("full scan output missing open port: %s", text.String())
	}
	if strings.Contains(text.String(), "192.0.2.1:22: closed") || !strings.Contains(text.String(), "Closed: 1") {
		t.Fatalf("full scan should omit closed details but keep their count: %s", text.String())
	}

	var jsonOutput bytes.Buffer
	if err := PrintPortJSON(&jsonOutput, result); err != nil {
		t.Fatalf("PrintPortJSON returned error: %v", err)
	}
	var got portscan.Result
	if err := json.Unmarshal(jsonOutput.Bytes(), &got); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if len(got.Results) != 1 || got.Results[0].Status != portscan.StateOpen || got.Summary.Closed != 1 {
		t.Errorf("JSON results=%#v summary=%#v, want only open details and full counts", got.Results, got.Summary)
	}
}
