package tls

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestInspectTLSWithOptionsUsesServerNameAndPort(t *testing.T) {
	serverNames := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &stdtls.Config{
		GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			serverNames <- hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	host, portText, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	result := inspectTLS(context.Background(), host, Options{
		Port:       port,
		ServerName: "example.com",
	}, roots)

	if result.Error != "" {
		t.Fatalf("inspection error = %q", result.Error)
	}
	if !result.Verified {
		t.Error("connection was not reported as verified")
	}
	if result.Version == "" || result.CipherSuite == "" || result.Subject == "" || result.Issuer == "" {
		t.Errorf("incomplete TLS certificate result: %#v", result)
	}
	if result.NotBefore.IsZero() || result.NotAfter.IsZero() {
		t.Errorf("certificate validity dates missing: %#v", result)
	}
	select {
	case got := <-serverNames:
		if got != "example.com" {
			t.Errorf("SNI server name = %q, want %q", got, "example.com")
		}
	default:
		t.Fatal("server did not receive a TLS ClientHello")
	}
}

func TestInspectTLSWithOptionsDoesNotSkipCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	host, portText, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}

	result := InspectTLSWithOptions(context.Background(), host, Options{
		Port:       port,
		ServerName: "example.com",
	})
	if result.Error == "" {
		t.Fatal("untrusted test certificate was accepted")
	}
	if result.Verified {
		t.Fatal("untrusted certificate was reported as verified")
	}
}

func TestInspectTLSWithOptionsRejectsInvalidPort(t *testing.T) {
	result := InspectTLSWithOptions(context.Background(), "example.com", Options{Port: 65536})
	if result.Error == "" {
		t.Fatal("expected invalid port error")
	}
	if result.Verified {
		t.Fatal("invalid port result was reported as verified")
	}
}
