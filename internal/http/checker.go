package http

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// CheckHTTP performs an HTTP GET request to collect response parameters.
func CheckHTTP(ctx context.Context, domain string) Result {
	return check(ctx, "http", domain, nil)
}

// CheckHTTPS performs an HTTPS GET request to collect response parameters.
func CheckHTTPS(ctx context.Context, domain string) Result {
	return check(ctx, "https", domain, nil)
}

func check(ctx context.Context, scheme, domain string, transport http.RoundTripper) Result {
	var res Result
	endpointURL := url.URL{Scheme: scheme, Host: domain}
	endpoint := endpointURL.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		// Do not follow redirects automatically so we can capture redirect URLs
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.ResponseTime = time.Since(start).Milliseconds()
	res.StatusCode = resp.StatusCode
	res.Proto = resp.Proto

	// Capture relevant headers
	res.Headers = make(map[string]string)
	if server := resp.Header.Get("Server"); server != "" {
		res.Headers["Server"] = server
	}

	if location := resp.Header.Get("Location"); location != "" {
		res.RedirectURL = location
	}

	return res
}
