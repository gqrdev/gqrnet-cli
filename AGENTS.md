# gqrnet

gqrnet is a Go CLI for inspecting domain DNS records, HTTP responses, TLS certificates, and resolved IP addresses.

## Project Structure

```text
cmd/
	gqrnet/main.go       CLI entry point
	root.go              Root Cobra command and execution
	domain.go            Full-scan command and flags
	dns.go               DNS-only command, flags, and input normalization
	http.go              Passive HTTP security audit command
	port.go              TCP port connectivity command
	*_test.go            CLI tests
internal/
	domain/               Full-scan coordinator and result
	dns/                  DNS queries and DNS result types
	http/                 HTTP request inspection and passive URL audit
	port/                 TCP port connectivity checks, full-range scan by default
	tls/                  TLS handshake and certificate inspection
	network/              IPv4/IPv6 resolution
	output/               Text and JSON formatting for command results
```

## Architecture

- `cmd/root.go` defines and executes the root command. Each subcommand registers itself and its flags.
- `cmd/` owns CLI concerns such as flags, argument parsing, and command-specific input normalization. Keep network inspection and scan coordination in `internal/`.
- `internal/domain/scanner.go` coordinates network, DNS, HTTP, and TLS checks concurrently using a shared context.
- `internal/dns/`, `internal/http/`, `internal/port/`, `internal/tls/`, and `internal/network/` implement the corresponding checks. The standalone `http` command performs one passive GET for an absolute URL and reports selected security-related response metadata; it does not follow redirects, read the response body, or run active vulnerability tests. The standalone `port` command checks TCP ports 1-65535 by default and displays open ports per resolved IP; repeat `--port` to check a selected list (up to 100 unique ports) and report every requested state. It uses at most 100 concurrent connections, defaults to a 120-second timeout, and marks timed-out/incomplete scans; it does not detect services or run vulnerability tests. `internal/output/` formats results and does not perform inspections.
- DNS uses `github.com/miekg/dns`; HTTP, TLS, and IP resolution use Go standard-library packages.

## Command Behavior

- `gqrnet domain <target-domain>` runs the full inspection. It accepts exactly one argument and requires a positive `--timeout` (default: 10 seconds). The command currently passes the target to the scanner without applying the DNS command's hostname normalization.
- `gqrnet dns <target-domain>` runs DNS queries only. It accepts a hostname, strips one trailing dot, rejects IP literals and common hostname syntax errors, and requires a positive `--timeout` (default: 10 seconds). This is command-level syntax validation, not complete RFC or IDNA validation.
- DNS queries all supported types by default: A, AAAA, CNAME, MX, NS, SOA, and TXT. Repeat `--type` to select types; values are case-insensitive. Only these types are supported by the CLI.
- `dns --server` selects an explicit DNS server. Port 53 is added if omitted. Without this flag, the DNS package reads `/etc/resolv.conf`; do not assume this implies identical resolver behavior on every platform.
- DNS retries a truncated response over TCP. Its JSON output serializes `internal/dns.Result`; preserve that result's existing string-based fields unless a requested change explicitly updates the output contract and its tests.
- `gqrnet http <url>` accepts one absolute HTTP or HTTPS URL. It reports security headers, cookie attributes without values, the initial redirect with query values redacted, and TLS details from the request connection. With no section flags it prints all sections; `--headers`, `--cookies`, `--redirects`, and `--tls` filter the detailed sections. `--json` and `--timeout` are supported.
- `gqrnet port <target-domain>` accepts one hostname. Without `--port`, it scans TCP ports 1-65535; repeat `--port` to select up to 100 unique ports and show each requested state, including closed. It checks at most 100 connections concurrently and supports `--json` and a positive `--timeout` (default: 120 seconds). The full scan lists open ports and summarizes other outcomes; an incomplete scan is marked as such. A timeout is not classified as a closed port. Use it only on systems you are authorized to inspect.

## Change Guidelines

- Follow existing Go conventions and run `gofmt` on changed Go files.
- Keep changes focused. Reuse nearby patterns and helpers, preserve public APIs and output formats unless the task requires a change, and avoid unrelated refactors.
- Pass contexts through I/O and network operations. The full scan shares a timeout context across checks; operations must honor the context, so do not describe it as a hard wall-clock guarantee. The HTTP checker also has its own 5-second client timeout.
- Handle returned errors according to the function's contract. Inspection failures are generally stored in each result's `Error` field and do not necessarily make the CLI command fail. JSON output functions return serialization/write errors; current text output functions do not return write errors.
- Add or update focused tests for changed behavior, especially CLI input/flags, DNS result formatting, and output contracts. Do not assume a behavior is covered without checking nearby tests.

## Verification

Run the focused tests for the changed package first, then the repository-wide checks as appropriate:

```bash
go test ./...
go test -race ./...
go vet ./...
```

These are recommended project checks; do not assume they are configured as CI gates without verifying the repository workflows.
