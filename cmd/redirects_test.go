package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	httpaudit "github.com/gqrdev/gqrnet-cli/internal/http"
)

func TestRedirectsCommandPassesOptionsAndPrintsJSON(t *testing.T) {
	oldJSON, oldTimeout, oldMaxRedirects, oldFollow := redirectsJSONOutput, redirectsTimeoutSec, redirectsMaxRedirects, redirectsFollow
	t.Cleanup(func() {
		redirectsJSONOutput, redirectsTimeoutSec, redirectsMaxRedirects, redirectsFollow = oldJSON, oldTimeout, oldMaxRedirects, oldFollow
	})
	redirectsJSONOutput = true
	redirectsTimeoutSec = 4
	redirectsMaxRedirects = 3
	redirectsFollow = func(ctx context.Context, target string, maxHops int) (httpaudit.RedirectResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("redirect context has no deadline")
		}
		if target != "https://example.com/start" || maxHops != 3 {
			t.Errorf("FollowRedirects(%q, %d), want target and max hops passed through", target, maxHops)
		}
		return httpaudit.RedirectResult{
			URL:      target,
			FinalURL: "https://example.com/done",
			Complete: true,
		}, nil
	}

	var output bytes.Buffer
	redirectsCmd.SetOut(&output)
	t.Cleanup(func() { redirectsCmd.SetOut(nil) })
	if err := redirectsCmd.RunE(redirectsCmd, []string{"https://example.com/start"}); err != nil {
		t.Fatalf("RunE returned error: %v", err)
	}
	var result httpaudit.RedirectResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if result.FinalURL != "https://example.com/done" {
		t.Errorf("final URL = %q, want done URL", result.FinalURL)
	}
}

func TestRedirectsCommandRejectsNonPositiveOptionsBeforeFollowing(t *testing.T) {
	oldTimeout, oldMaxRedirects, oldFollow := redirectsTimeoutSec, redirectsMaxRedirects, redirectsFollow
	t.Cleanup(func() {
		redirectsTimeoutSec, redirectsMaxRedirects, redirectsFollow = oldTimeout, oldMaxRedirects, oldFollow
	})
	redirectsFollow = func(context.Context, string, int) (httpaudit.RedirectResult, error) {
		t.Fatal("redirects called with invalid options")
		return httpaudit.RedirectResult{}, nil
	}

	redirectsTimeoutSec = 0
	if err := redirectsCmd.RunE(redirectsCmd, []string{"https://example.com"}); err == nil {
		t.Fatal("expected timeout validation error")
	}
	redirectsTimeoutSec = 5
	redirectsMaxRedirects = 0
	if err := redirectsCmd.RunE(redirectsCmd, []string{"https://example.com"}); err == nil {
		t.Fatal("expected max-redirects validation error")
	}
	redirectsTimeoutSec = oldTimeout
	redirectsMaxRedirects = oldMaxRedirects
}

func TestRedirectsCommandSupportsMaxRedirectsAndLegacyAlias(t *testing.T) {
	oldMaxRedirects := redirectsMaxRedirects
	t.Cleanup(func() { redirectsMaxRedirects = oldMaxRedirects })

	legacyFlag := redirectsCmd.Flags().Lookup("max-hops")
	if legacyFlag == nil || legacyFlag.Deprecated == "" {
		t.Fatal("max-hops should remain available as a deprecated alias")
	}
	for _, flagName := range []string{"max-redirects", "max-hops"} {
		if err := redirectsCmd.Flags().Set(flagName, "4"); err != nil {
			t.Fatalf("setting --%s failed: %v", flagName, err)
		}
		if redirectsMaxRedirects != 4 {
			t.Errorf("--%s set max redirects to %d, want 4", flagName, redirectsMaxRedirects)
		}
	}
}
