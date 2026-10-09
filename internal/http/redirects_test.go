package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFollowRedirectsFollowsRelativeLocationsAndRedactsQueries(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/next?token=secret", http.StatusFound)
		case "/next":
			gotQuery = r.URL.Query().Get("token")
			http.Redirect(w, r, "/done", http.StatusTemporaryRedirect)
		case "/done":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := FollowRedirects(context.Background(), server.URL+"/start?token=secret", 5)
	if err != nil {
		t.Fatalf("FollowRedirects returned error: %v", err)
	}
	if !result.Complete || result.Error != "" {
		t.Fatalf("result did not complete: %#v", result)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("hop count = %d, want 2", len(result.Hops))
	}
	if result.Hops[0].StatusCode != http.StatusFound || result.Hops[1].StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("hop status codes = %d, %d", result.Hops[0].StatusCode, result.Hops[1].StatusCode)
	}
	if result.FinalURL != server.URL+"/done" || result.FinalStatusCode != http.StatusOK {
		t.Errorf("final response = %q (%d), want /done (200)", result.FinalURL, result.FinalStatusCode)
	}
	if gotQuery != "secret" {
		t.Errorf("follow-up request query token = %q, want secret", gotQuery)
	}
	if strings.Contains(strings.Join([]string{result.URL, result.FinalURL, result.Hops[0].Location}, " "), "secret") {
		t.Fatal("redirect result exposed a query value")
	}
}

func TestFollowRedirectsStopsOnCycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.Redirect(w, r, "/second", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/first", http.StatusFound)
	}))
	defer server.Close()

	result, err := FollowRedirects(context.Background(), server.URL+"/first", 10)
	if err != nil {
		t.Fatalf("FollowRedirects returned error: %v", err)
	}
	if result.Complete || result.Error != "redirect cycle detected" || len(result.Hops) != 2 {
		t.Fatalf("cycle result = %#v", result)
	}
}

func TestFollowRedirectsStopsAtMaximumHops(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/last", http.StatusFound)
	}))
	defer server.Close()

	result, err := FollowRedirects(context.Background(), server.URL+"/start", 1)
	if err != nil {
		t.Fatalf("FollowRedirects returned error: %v", err)
	}
	if result.Complete || result.Error != "maximum redirect hops reached" || len(result.Hops) != 2 {
		t.Fatalf("limited result = %#v", result)
	}
	if requestCount != 2 {
		t.Errorf("request count = %d, want 2", requestCount)
	}
}

func TestFollowRedirectsAllowsFinalResponseAtMaximumHops(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/done", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := FollowRedirects(context.Background(), server.URL+"/start", 1)
	if err != nil {
		t.Fatalf("FollowRedirects returned error: %v", err)
	}
	if !result.Complete || result.FinalStatusCode != http.StatusOK || len(result.Hops) != 1 {
		t.Fatalf("result at hop limit = %#v", result)
	}
}

func TestFollowRedirectsRejectsCredentialedDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://user:password@example.com/private", http.StatusFound)
	}))
	defer server.Close()

	result, err := FollowRedirects(context.Background(), server.URL, 5)
	if err != nil {
		t.Fatalf("FollowRedirects returned error: %v", err)
	}
	if result.Complete || !strings.Contains(result.Error, "without credentials") {
		t.Fatalf("credentialed destination result = %#v", result)
	}
	if strings.Contains(result.Error, "password") || strings.Contains(result.FinalURL, "password") {
		t.Fatal("result exposed redirect credentials")
	}
}

func TestFollowRedirectsValidatesTargetAndMaximumHops(t *testing.T) {
	if _, err := FollowRedirects(context.Background(), "ftp://example.com", 5); err == nil {
		t.Fatal("expected unsupported scheme to be rejected")
	}
	if _, err := FollowRedirects(context.Background(), "https://example.com", 0); err == nil {
		t.Fatal("expected non-positive max hops to be rejected")
	}
}

func TestFollowRedirectsReportsCancellationWithoutLeakingQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})

	result, err := followRedirects(ctx, "https://example.com/path?token=secret", 5, transport)
	if err != nil {
		t.Fatalf("followRedirects returned error: %v", err)
	}
	if result.Complete || !strings.Contains(result.Error, "context canceled") {
		t.Fatalf("canceled result = %#v", result)
	}
	if strings.Contains(result.Error, "secret") {
		t.Fatalf("request error exposed query value: %s", result.Error)
	}
}
