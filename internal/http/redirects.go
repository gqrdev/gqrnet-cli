package http

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// RedirectResult contains the observed redirect chain for a URL.
type RedirectResult struct {
	URL             string        `json:"url"`
	Hops            []RedirectHop `json:"hops"`
	FinalURL        string        `json:"final_url"`
	FinalStatusCode int           `json:"final_status_code,omitempty"`
	Complete        bool          `json:"complete"`
	Error           string        `json:"error,omitempty"`
}

// RedirectHop records one HTTP redirect response.
type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location"`
}

// FollowRedirects follows HTTP redirects up to maxHops requests to redirect destinations.
func FollowRedirects(ctx context.Context, target string, maxHops int) (RedirectResult, error) {
	return followRedirects(ctx, target, maxHops, nil)
}

func followRedirects(ctx context.Context, target string, maxHops int, transport http.RoundTripper) (RedirectResult, error) {
	if maxHops <= 0 {
		return RedirectResult{}, errors.New("max-redirects must be greater than zero")
	}
	current, err := parseAuditURL(target)
	if err != nil {
		return RedirectResult{}, err
	}
	current.Fragment = ""
	current.RawFragment = ""

	result := RedirectResult{
		URL:      sanitizeAuditURL(current),
		Hops:     []RedirectHop{},
		FinalURL: sanitizeAuditURL(current),
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	visited := make(map[string]struct{})
	followedHops := 0

	for {
		key := redirectVisitKey(current)
		if _, exists := visited[key]; exists {
			result.Error = "redirect cycle detected"
			return result, nil
		}
		visited[key] = struct{}{}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			result.Error = "unable to create request"
			return result, nil
		}
		response, err := client.Do(request)
		if err != nil {
			result.Error = sanitizeRequestError(err, current)
			return result, nil
		}
		_ = response.Body.Close()
		result.FinalURL = sanitizeAuditURL(current)
		result.FinalStatusCode = response.StatusCode
		if !isRedirectStatus(response.StatusCode) || response.Header.Get("Location") == "" {
			result.Complete = true
			return result, nil
		}

		destination, err := current.Parse(response.Header.Get("Location"))
		if err != nil {
			result.Error = "invalid redirect URL"
			return result, nil
		}
		destination, err = parseAuditURL(destination.String())
		if err != nil {
			result.Error = "redirect destination must be a valid HTTP or HTTPS URL without credentials"
			return result, nil
		}
		destination.Fragment = ""
		destination.RawFragment = ""
		result.Hops = append(result.Hops, RedirectHop{
			URL:        sanitizeAuditURL(current),
			StatusCode: response.StatusCode,
			Location:   sanitizeAuditURL(destination),
		})
		result.FinalURL = sanitizeAuditURL(destination)
		result.FinalStatusCode = 0
		if followedHops >= maxHops {
			result.Error = "maximum redirect hops reached"
			return result, nil
		}
		followedHops++
		current = destination
	}
}

func redirectVisitKey(target *url.URL) string {
	key := *target
	key.Scheme = strings.ToLower(key.Scheme)
	key.Host = strings.ToLower(key.Host)
	key.Fragment = ""
	key.RawFragment = ""
	return key.String()
}

func isRedirectStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}
