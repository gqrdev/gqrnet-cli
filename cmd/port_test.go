package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	portscan "github.com/gqrdev/gqrnet-cli/internal/port"
)

func TestParsePortValuesValidatesAndDeduplicates(t *testing.T) {
	ports, err := parsePortValues([]string{"22", "443", "22"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 443 {
		t.Fatalf("ports = %v, want [22 443]", ports)
	}

	for _, values := range [][]string{nil, {"0"}, {"65536"}, {"abc"}} {
		if _, err := parsePortValues(values); err == nil {
			t.Errorf("parsePortValues(%v) succeeded, want error", values)
		}
	}
}

func TestParsePortValuesLimitsUniquePorts(t *testing.T) {
	values := make([]string, 0, 101)
	for port := 1; port <= 101; port++ {
		values = append(values, strconv.Itoa(port))
	}
	if _, err := parsePortValues(values); err == nil {
		t.Fatal("expected more than 100 unique ports to be rejected")
	}
}

func TestPortCommandPassesOptionsAndPrintsJSON(t *testing.T) {
	oldJSON, oldOpenOnly, oldTimeout, oldConnectTimeout, oldPorts, oldScan := portJSONOutput, portOpenOnly, portTimeoutSec, portConnectTimeoutSec, portValues, portScan
	t.Cleanup(func() {
		portJSONOutput, portOpenOnly, portTimeoutSec, portConnectTimeoutSec, portValues, portScan = oldJSON, oldOpenOnly, oldTimeout, oldConnectTimeout, oldPorts, oldScan
	})
	portJSONOutput = true
	portOpenOnly = false
	portTimeoutSec = 3
	portConnectTimeoutSec = 2
	portValues = []string{"22", "443", "22"}
	var gotTarget string
	var gotPorts []int
	var gotTimeout, gotConnectTimeout time.Duration
	portScan = func(ctx context.Context, target string, ports []int, timeout, connectTimeout time.Duration) portscan.Result {
		gotTarget = target
		gotPorts = ports
		gotTimeout = timeout
		gotConnectTimeout = connectTimeout
		if _, ok := ctx.Deadline(); !ok {
			t.Error("scan context has no deadline")
		}
		return portscan.Result{Target: target, Protocol: "tcp", RequestedPorts: ports}
	}

	var output bytes.Buffer
	portCmd.SetOut(&output)
	t.Cleanup(func() { portCmd.SetOut(nil) })
	if err := portCmd.RunE(portCmd, []string{"example.com."}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	if gotTarget != "example.com" {
		t.Errorf("target = %q, want example.com", gotTarget)
	}
	if len(gotPorts) != 2 || gotPorts[0] != 22 || gotPorts[1] != 443 {
		t.Errorf("ports = %v, want [22 443]", gotPorts)
	}
	if gotTimeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", gotTimeout)
	}
	if gotConnectTimeout != 2*time.Second {
		t.Errorf("connect timeout = %v, want 2s", gotConnectTimeout)
	}
	var result portscan.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if result.Target != "example.com" || result.Protocol != "tcp" {
		t.Errorf("JSON result = %#v, want normalized TCP target", result)
	}
}

func TestPortCommandPassesOpenOnlyToJSONOutput(t *testing.T) {
	oldJSON, oldOpenOnly, oldTimeout, oldPorts, oldScan := portJSONOutput, portOpenOnly, portTimeoutSec, portValues, portScan
	t.Cleanup(func() {
		portJSONOutput, portOpenOnly, portTimeoutSec, portValues, portScan = oldJSON, oldOpenOnly, oldTimeout, oldPorts, oldScan
	})
	portJSONOutput = true
	portOpenOnly = true
	portTimeoutSec = 5
	portValues = []string{"22", "443"}
	portScan = func(_ context.Context, target string, ports []int, _, _ time.Duration) portscan.Result {
		return portscan.Result{
			Target:         target,
			RequestedPorts: ports,
			Results: []portscan.PortResult{
				{IP: "192.0.2.1", Port: 22, Status: portscan.StateClosed},
				{IP: "192.0.2.1", Port: 443, Status: portscan.StateOpen},
			},
			Summary: portscan.Summary{Open: 1, Closed: 1, PortsPerAddress: 2},
		}
	}

	var output bytes.Buffer
	portCmd.SetOut(&output)
	t.Cleanup(func() { portCmd.SetOut(nil) })
	if err := portCmd.RunE(portCmd, []string{"example.com"}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	var result portscan.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(result.Results) != 1 || result.Results[0].Status != portscan.StateOpen {
		t.Errorf("results = %#v, want only the open port", result.Results)
	}
	if result.Summary.Open != 1 || result.Summary.Closed != 1 {
		t.Errorf("summary = %#v, want original counts", result.Summary)
	}
}

func TestPortCommandDefaultsToFullScan(t *testing.T) {
	oldJSON, oldTimeout, oldPorts, oldScan := portJSONOutput, portTimeoutSec, portValues, portScan
	t.Cleanup(func() {
		portJSONOutput, portTimeoutSec, portValues, portScan = oldJSON, oldTimeout, oldPorts, oldScan
	})
	portJSONOutput = false
	portTimeoutSec = 120
	portValues = nil
	portScan = func(_ context.Context, target string, ports []int, timeout, _ time.Duration) portscan.Result {
		if target != "example.com" {
			t.Errorf("target = %q, want example.com", target)
		}
		if len(ports) != 0 {
			t.Errorf("ports = %v, want no explicit ports for full scan", ports)
		}
		if timeout != 120*time.Second {
			t.Errorf("timeout = %v, want 120s", timeout)
		}
		return portscan.Result{
			Target:   target,
			Protocol: "tcp",
			FullScan: true,
			Complete: true,
			Results:  []portscan.PortResult{{IP: "192.0.2.1", Port: 443, Status: portscan.StateOpen}},
			Summary:  portscan.Summary{Open: 1, Closed: 65534, PortsPerAddress: 65535},
		}
	}

	var output bytes.Buffer
	portCmd.SetOut(&output)
	t.Cleanup(func() { portCmd.SetOut(nil) })
	if err := portCmd.RunE(portCmd, []string{"example.com"}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	if !strings.Contains(output.String(), "[ Open TCP Ports ]") || !strings.Contains(output.String(), "443") {
		t.Errorf("full scan output does not show the open result: %s", output.String())
	}
}

func TestPortCommandRejectsInvalidTimeoutBeforeScan(t *testing.T) {
	oldTimeout, oldPorts, oldScan := portTimeoutSec, portValues, portScan
	t.Cleanup(func() { portTimeoutSec, portValues, portScan = oldTimeout, oldPorts, oldScan })
	portTimeoutSec = 0
	portValues = []string{"443"}
	portScan = func(context.Context, string, []int, time.Duration, time.Duration) portscan.Result {
		t.Fatal("scanner called with invalid timeout")
		return portscan.Result{}
	}
	if err := portCmd.RunE(portCmd, []string{"example.com"}); err == nil {
		t.Fatal("expected timeout validation error")
	}
}

func TestPortCommandRejectsInvalidConnectTimeoutBeforeScan(t *testing.T) {
	oldConnectTimeout, oldPorts, oldScan := portConnectTimeoutSec, portValues, portScan
	t.Cleanup(func() { portConnectTimeoutSec, portValues, portScan = oldConnectTimeout, oldPorts, oldScan })
	portConnectTimeoutSec = 0
	portValues = []string{"443"}
	portScan = func(context.Context, string, []int, time.Duration, time.Duration) portscan.Result {
		t.Fatal("scanner called with invalid connect timeout")
		return portscan.Result{}
	}
	if err := portCmd.RunE(portCmd, []string{"example.com"}); err == nil {
		t.Fatal("expected connect timeout validation error")
	}
}

func TestPortCommandRejectsInvalidPortsBeforeScan(t *testing.T) {
	oldPorts, oldScan := portValues, portScan
	t.Cleanup(func() { portValues, portScan = oldPorts, oldScan })
	portValues = []string{"70000"}
	portScan = func(context.Context, string, []int, time.Duration, time.Duration) portscan.Result {
		t.Fatal("scanner called with invalid port")
		return portscan.Result{}
	}
	if err := portCmd.RunE(portCmd, []string{"example.com"}); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestPortCommandTextOutputByDefault(t *testing.T) {
	oldJSON, oldPorts, oldScan := portJSONOutput, portValues, portScan
	t.Cleanup(func() { portJSONOutput, portValues, portScan = oldJSON, oldPorts, oldScan })
	portJSONOutput = false
	portValues = []string{"443"}
	portScan = func(context.Context, string, []int, time.Duration, time.Duration) portscan.Result {
		return portscan.Result{
			Target:         "example.com",
			Protocol:       "tcp",
			RequestedPorts: []int{443},
			ResolvedAddresses: []portscan.Address{
				{IP: "192.0.2.1", Family: "ipv4"},
			},
			Results: []portscan.PortResult{{IP: "192.0.2.1", Port: 443, Status: portscan.StateOpen}},
			Summary: portscan.Summary{AddressesChecked: 1, PortsPerAddress: 1, Open: 1},
		}
	}

	var output bytes.Buffer
	portCmd.SetOut(&output)
	t.Cleanup(func() { portCmd.SetOut(nil) })
	if err := portCmd.RunE(portCmd, []string{"example.com"}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	for _, expected := range []string{"[ Resolved Addresses ]", "192.0.2.1", "[ Port Checks ]", "443", "open", "[ Summary ]"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output missing %q: %s", expected, output.String())
		}
	}
}
