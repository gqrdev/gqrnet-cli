package http

// Result stores the basic HTTP query information and metrics.
type Result struct {
	StatusCode   int               `json:"status_code"`
	Proto        string            `json:"protocol"`
	ResponseTime int64             `json:"response_time_ms"`
	Headers      map[string]string `json:"headers,omitempty"`
	RedirectURL  string            `json:"redirect_url,omitempty"`
	Error        string            `json:"error,omitempty"`
}
