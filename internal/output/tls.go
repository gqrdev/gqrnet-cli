package output

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"

	tlsinspect "github.com/gqrdev/gqrnet-cli/internal/tls"
)

type tlsJSONResult struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name,omitempty"`
	tlsinspect.Result
}

// PrintTLSJSON writes a standalone TLS inspection result as JSON.
func PrintTLSJSON(w io.Writer, host string, port int, serverName string, result tlsinspect.Result) error {
	formatted := tlsJSONResult{
		Host:       host,
		Port:       port,
		ServerName: serverName,
		Result:     result,
	}
	data, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// PrintTLSText presents a human-readable standalone TLS inspection.
func PrintTLSText(w io.Writer, host string, port int, serverName string, result tlsinspect.Result) {
	fmt.Fprintf(w, "=== TLS Target: %s ===\n\n", net.JoinHostPort(host, strconv.Itoa(port)))
	fmt.Fprintln(w, "[ TLS Certificate ]")
	fmt.Fprintf(w, " Verified:       %t\n", result.Verified)
	if serverName != "" {
		fmt.Fprintf(w, " Server Name:    %s\n", serverName)
	}
	if result.Error != "" {
		fmt.Fprintf(w, " Error:          %s\n", result.Error)
		return
	}
	fmt.Fprintf(w, " Protocol:       %s\n", result.Version)
	fmt.Fprintf(w, " Cipher Suite:   %s\n", result.CipherSuite)
	fmt.Fprintf(w, " Subject:        %s\n", result.Subject)
	fmt.Fprintf(w, " Issuer:         %s\n", result.Issuer)
	fmt.Fprintf(w, " Valid From:     %s\n", result.NotBefore.Format("2006-01-02"))
	fmt.Fprintf(w, " Expires:        %s\n", result.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(w, " Days Valid:     %d\n", result.DaysValid)
}
