package output

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	portscan "github.com/gqrdev/gqrnet-cli/internal/port"
)

// PrintPortJSON writes a port scan result as indented JSON.
func PrintPortJSON(w io.Writer, result portscan.Result, openOnly bool) error {
	if result.FullScan || openOnly {
		result.Results = openResults(result.Results)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// PrintPortText presents each TCP check and a summary in human-readable form.
func PrintPortText(w io.Writer, result portscan.Result, openOnly bool) {
	fmt.Fprintf(w, "=== TCP Port Scan: %s ===\n\n", result.Target)
	fmt.Fprintf(w, "Protocol: %s\n", result.Protocol)
	fmt.Fprintf(w, "Started:  %s\n", result.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"))
	fmt.Fprintf(w, "Duration: %d ms\n", result.DurationMS)
	fmt.Fprintf(w, "Timeout:  %d ms\n", result.TimeoutMS)
	if result.FullScan {
		fmt.Fprintln(w, "Mode:     Full TCP range (1-65535)")
	} else {
		fmt.Fprintln(w, "Mode:     Explicit ports")
	}
	fmt.Fprintf(w, "Complete: %t\n\n", result.Complete)

	if result.Error != "" {
		fmt.Fprintf(w, "Error: %s\n\n", result.Error)
	}
	fmt.Fprintln(w, "[ Resolved Addresses ]")
	if len(result.ResolvedAddresses) == 0 {
		fmt.Fprintln(w, " No addresses resolved")
	}
	for _, address := range result.ResolvedAddresses {
		fmt.Fprintf(w, " %s (%s)\n", address.IP, address.Family)
	}

	if result.FullScan || openOnly {
		fmt.Fprintln(w, "\n[ Open TCP Ports ]")
	} else {
		fmt.Fprintln(w, "\n[ Port Checks ]")
	}
	checks := result.Results
	if result.FullScan || openOnly {
		checks = openResults(checks)
		if len(checks) == 0 {
			if result.FullScan && result.Complete {
				fmt.Fprintln(w, " No open TCP ports found")
			} else if !result.Complete {
				fmt.Fprintln(w, " No open TCP ports confirmed before the scan ended")
			} else {
				fmt.Fprintln(w, " No open ports found among requested ports")
			}
		}
	}
	for _, check := range checks {
		endpoint := net.JoinHostPort(check.IP, strconv.Itoa(check.Port))
		fmt.Fprintf(w, " %s: %s (%d ms)", endpoint, check.Status, check.ConnectTimeMS)
		if check.ServiceHint != "" {
			fmt.Fprintf(w, "; service hint: %s", check.ServiceHint)
		}
		if check.Error != "" {
			fmt.Fprintf(w, "; error: %s", check.Error)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "\n[ Summary ]")
	fmt.Fprintf(w, " Addresses checked: %d\n", result.Summary.AddressesChecked)
	fmt.Fprintf(w, " Ports per address: %d\n", result.Summary.PortsPerAddress)
	fmt.Fprintf(w, " Open: %d\n", result.Summary.Open)
	fmt.Fprintf(w, " Closed: %d\n", result.Summary.Closed)
	fmt.Fprintf(w, " Timeout: %d\n", result.Summary.Timeout)
	fmt.Fprintf(w, " Cancelled: %d\n", result.Summary.Cancelled)
	fmt.Fprintf(w, " Other errors: %d\n", result.Summary.Errors)
	fmt.Fprintf(w, " Not checked: %d\n", result.Summary.NotChecked)
	if len(result.RequestedPorts) > 0 {
		ports := make([]string, len(result.RequestedPorts))
		for index, port := range result.RequestedPorts {
			ports[index] = strconv.Itoa(port)
		}
		fmt.Fprintf(w, " Requested ports: %s\n", strings.Join(ports, ", "))
	}
}

func openResults(results []portscan.PortResult) []portscan.PortResult {
	open := make([]portscan.PortResult, 0, len(results))
	for _, result := range results {
		if result.Status == portscan.StateOpen {
			open = append(open, result)
		}
	}
	return open
}
