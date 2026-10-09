package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	httpaudit "github.com/gqrdev/gqrnet-cli/internal/http"
)

func TestPrintRedirectsTextIncludesChainAndPartialState(t *testing.T) {
	var output bytes.Buffer
	PrintRedirectsText(&output, httpaudit.RedirectResult{
		URL:      "https://example.com/start?%5Bquery-redacted%5D",
		Hops:     []httpaudit.RedirectHop{{URL: "https://example.com/start", StatusCode: 302, Location: "https://example.com/done"}},
		FinalURL: "https://example.com/done",
		Complete: false,
		Error:    "maximum redirect hops reached",
	})

	for _, expected := range []string{"[ Redirects ]", "1. Status: 302", "https://example.com/done", "Complete: false", "maximum redirect hops reached"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output missing %q: %s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "secret") {
		t.Fatal("output exposed a query value")
	}
}

func TestPrintRedirectsJSONWritesValidResult(t *testing.T) {
	var output bytes.Buffer
	want := httpaudit.RedirectResult{
		URL:             "https://example.com/start",
		Hops:            []httpaudit.RedirectHop{{URL: "https://example.com/start", StatusCode: 301, Location: "https://example.com/done"}},
		FinalURL:        "https://example.com/done",
		FinalStatusCode: 200,
		Complete:        true,
	}
	if err := PrintRedirectsJSON(&output, want); err != nil {
		t.Fatalf("PrintRedirectsJSON returned error: %v", err)
	}
	var got httpaudit.RedirectResult
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if got.FinalURL != want.FinalURL || got.FinalStatusCode != want.FinalStatusCode || len(got.Hops) != 1 {
		t.Errorf("decoded result = %#v, want %#v", got, want)
	}
}
