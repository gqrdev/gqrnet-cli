# gqrnet

gqrnet is a Go CLI for inspecting domain DNS records, HTTP responses, TLS certificates, and resolved IP addresses.

## Project Structure

```text
cmd/
	gqrnet/main.go       CLI entry point
	root.go              Root Cobra command and execution
	domain.go            Full-scan command and flags
	dns.go               DNS-only command, flags, and input normalization
	*_test.go            CLI tests
internal/
	domain/               Full-scan coordinator and result
	dns/                  DNS queries and DNS result types
	http/                 HTTP request inspection
	tls/                  TLS handshake and certificate inspection
	network/              IPv4/IPv6 resolution
	output/               Text and JSON formatting
```

## Architecture

- `cmd/root.go` defines and executes the root command. Each subcommand registers itself and its flags.
- `cmd/` owns CLI concerns such as flags, argument parsing, and command-specific input normalization. Keep network inspection and scan coordination in `internal/`.
- `internal/domain/scanner.go` coordinates network, DNS, HTTP, and TLS checks concurrently using a shared context.
- `internal/dns/`, `internal/http/`, `internal/tls/`, and `internal/network/` implement the corresponding checks. `internal/output/` formats results and does not perform inspections.
- DNS uses `github.com/miekg/dns`; HTTP, TLS, and IP resolution use Go standard-library packages.

## Command Behavior

- `gqrnet domain <target-domain>` runs the full inspection. It accepts exactly one argument and requires a positive `--timeout` (default: 10 seconds). The command currently passes the target to the scanner without applying the DNS command's hostname normalization.
- `gqrnet dns <target-domain>` runs DNS queries only. It accepts a hostname, strips one trailing dot, rejects IP literals and common hostname syntax errors, and requires a positive `--timeout` (default: 10 seconds). This is command-level syntax validation, not complete RFC or IDNA validation.
- DNS queries all supported types by default: A, AAAA, CNAME, MX, NS, SOA, and TXT. Repeat `--type` to select types; values are case-insensitive. Only these types are supported by the CLI.
- `dns --server` selects an explicit DNS server. Port 53 is added if omitted. Without this flag, the DNS package reads `/etc/resolv.conf`; do not assume this implies identical resolver behavior on every platform.
- DNS retries a truncated response over TCP. Its JSON output serializes `internal/dns.Result`; preserve that result's existing string-based fields unless a requested change explicitly updates the output contract and its tests.

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
