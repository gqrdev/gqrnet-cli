package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// InspectTLS connects via HTTPS port 443 to retrieve TLS certificate details.
func InspectTLS(ctx context.Context, domain string) Result {
	var res Result
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    &tls.Config{InsecureSkipVerify: false},
	}

	conn, err := dialer.DialContext(ctx, "tcp", domain+":443")
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
	res.Subject = cert.Subject.CommonName
	res.NotBefore = cert.NotBefore
	res.NotAfter = cert.NotAfter
	res.DaysValid = int(time.Until(cert.NotAfter).Hours() / 24)

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
