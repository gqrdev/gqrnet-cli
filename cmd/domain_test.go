package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"gqrnet/internal/domain"
)

func TestDomainCommandRequiresExactlyOneTarget(t *testing.T) {
	if err := domainCmd.Args(domainCmd, nil); err == nil {
		t.Fatal("expected an error when the target is missing")
	}
	if err := domainCmd.Args(domainCmd, []string{"example.com", "extra"}); err == nil {
		t.Fatal("expected an error when more than one target is provided")
	}
	if err := domainCmd.Args(domainCmd, []string{"example.com"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomainCommandRejectsNonPositiveTimeout(t *testing.T) {
	oldTimeout := timeoutSec
	oldScanner := scanDomain
	t.Cleanup(func() {
		timeoutSec = oldTimeout
		scanDomain = oldScanner
	})

	timeoutSec = 0
	scanDomain = func(string, time.Duration) domain.DomainResult {
		t.Fatal("scanner should not be called")
		return domain.DomainResult{}
	}

	if err := domainCmd.RunE(domainCmd, []string{"example.com"}); err == nil {
		t.Fatal("expected an error for a non-positive timeout")
	}
}

func TestDomainCommandUsesScannerAndJSONOutput(t *testing.T) {
	oldTimeout := timeoutSec
	oldJSON := jsonOutput
	oldScanner := scanDomain
	t.Cleanup(func() {
		timeoutSec = oldTimeout
		jsonOutput = oldJSON
		scanDomain = oldScanner
	})

	timeoutSec = 3
	jsonOutput = true
	var gotTarget string
	var gotTimeout time.Duration
	scanDomain = func(target string, timeout time.Duration) domain.DomainResult {
		gotTarget = target
		gotTimeout = timeout
		return domain.DomainResult{Domain: target}
	}

	var output bytes.Buffer
	domainCmd.SetOut(&output)
	t.Cleanup(func() { domainCmd.SetOut(nil) })

	if err := domainCmd.RunE(domainCmd, []string{"example.com"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotTarget != "example.com" {
		t.Fatalf("target = %q, want %q", gotTarget, "example.com")
	}
	if gotTimeout != 3*time.Second {
		t.Fatalf("timeout = %v, want %v", gotTimeout, 3*time.Second)
	}
	if !strings.Contains(output.String(), `"domain": "example.com"`) {
		t.Fatalf("JSON output does not contain the target: %s", output.String())
	}
}

func TestDomainCommandUsesTextOutputByDefault(t *testing.T) {
	oldTimeout := timeoutSec
	oldJSON := jsonOutput
	oldScanner := scanDomain
	t.Cleanup(func() {
		timeoutSec = oldTimeout
		jsonOutput = oldJSON
		scanDomain = oldScanner
	})

	timeoutSec = 1
	jsonOutput = false
	scanDomain = func(target string, _ time.Duration) domain.DomainResult {
		return domain.DomainResult{Domain: target}
	}

	var output bytes.Buffer
	domainCmd.SetOut(&output)
	t.Cleanup(func() { domainCmd.SetOut(nil) })

	if err := domainCmd.RunE(domainCmd, []string{"example.com"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output.String(), "=== Target Domain: example.com ===") {
		t.Fatalf("text output does not contain the target: %s", output.String())
	}
}
