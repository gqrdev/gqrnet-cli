package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Options configures a standalone TLS inspection.
type Options struct {
	Port       int
	ServerName string
}

// InspectTLS connects via HTTPS port 443 to retrieve TLS certificate details.
func InspectTLS(ctx context.Context, domain string) Result {
	return InspectTLSWithOptions(ctx, domain, Options{})
}

// InspectTLSWithOptions connects to host and inspects its verified TLS connection.
func InspectTLSWithOptions(ctx context.Context, host string, options Options) Result {
	return inspectTLS(ctx, host, options, nil)
}

func inspectTLS(ctx context.Context, host string, options Options, rootCAs *x509.CertPool) Result {
	var res Result
	port := options.Port
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		res.Error = "port must be an integer between 1 and 65535"
		return res
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName: options.ServerName,
			RootCAs:    rootCAs,
		},
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		res.Error = "unexpected TLS connection type"
		return res
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		res.Error = "no TLS certificates found"
		return res
	}

	cert := state.PeerCertificates[0]
	res.Version = getTLSVersionName(state.Version)
	res.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	res.Issuer = cert.Issuer.CommonName
	if res.Issuer == "" {
		res.Issuer = cert.Issuer.String()
	}
	res.Subject = cert.Subject.CommonName
	if res.Subject == "" {
		res.Subject = cert.Subject.String()
	}
	if res.Subject == "" && len(cert.DNSNames) > 0 {
		res.Subject = cert.DNSNames[0]
	}
	if res.Subject == "" && len(cert.IPAddresses) > 0 {
		res.Subject = cert.IPAddresses[0].String()
	}
	res.NotBefore = cert.NotBefore
	res.NotAfter = cert.NotAfter
	res.DaysValid = int(time.Until(cert.NotAfter).Hours() / 24)
	res.Verified = true

	return res
}

func getTLSVersionName(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%x)", ver)
	}
}
