package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCheckHTTPReturnsResponseDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-server")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := checkServer(t, "http", server, nil)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if result.Proto != "HTTP/1.1" {
		t.Errorf("protocol = %q, want HTTP/1.1", result.Proto)
	}
	if result.Headers["Server"] != "test-server" {
		t.Errorf("server header = %q, want test-server", result.Headers["Server"])
	}
}

func TestCheckHTTPSReturnsResponseAndDoesNotFollowRedirect(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/destination", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := checkServer(t, "https", server, server.Client().Transport)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.StatusCode != http.StatusFound {
		t.Errorf("status code = %d, want %d", result.StatusCode, http.StatusFound)
	}
	if result.RedirectURL != "/destination" {
		t.Errorf("redirect URL = %q, want /destination", result.RedirectURL)
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1", got)
	}
}

func checkServer(t *testing.T, scheme string, server *httptest.Server, transport http.RoundTripper) Result {
	t.Helper()
	return check(context.Background(), scheme, server.Listener.Addr().String(), transport)
}
