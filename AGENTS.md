AGENTS.md

# Overview
gqrnet is an open-source command-line interface (CLI) written in Go designed for infrastructure and networking inspection. The primary CLI command is gqrnet.  

# Project Structure
```plaintext
gqrnet/
├── cmd/
│   ├── root.go       # Root command ("gqrnet"), global flags, subcommands registration
│   ├── domain.go     # "gqrnet domain <domain>" complete scan orchestration
│   ├── dns.go        # "gqrnet dns <domain>" DNS-only command and input validation
│   ├── domain_test.go
│   └── dns_test.go
├── internal/
│   ├── domain/       # Domain scanning coordinator and unified result structures
│   ├── dns/          # DNS queries, selected record types, server configuration, UDP/TCP fallback
│   ├── http/         # HTTP/HTTPS requests, status, headers, redirects via net/http
│   ├── tls/          # TLS handshake inspection (versions, cipher suites, certs) via crypto/tls
│   ├── network/      # IPv4 and IPv6 resolution using net library
│   └── output/       # Terminal text rendering and JSON output formatters, including DNS-only output
├── main.go           # Application entry point
├── go.mod            # Go module definitions
└── go.sum            # Dependency checksums
```
## Core Tech Stack
- Language: Go
- DNS Resolution: [github.com/miekg/dns](https://github.com/miekg/dns)
- HTTP Client: Standard library net/http
- TLS Inspector: Standard library crypto/tls
- Network Resolution: Standard library net

## Developer Conventions & Guidelines
### Architecture Principles
- Separation of Concerns: Keep core scanning logic in internal/ packages (dns, http, tls, network) and presentation logic inside internal/output/.
- Concurrency & Timeouts: Coordinate concurrent tasks and execution timeouts for the full scan within internal/domain/scanner.go. The DNS-only command owns its global timeout in cmd/dns.go and passes it through context.Context.
- CLI Layer: CLI flags and input handling belong in cmd/. Direct business logic must not be placed inside cmd/ files.

### Code Style
- Follow standard Go idioms and gofmt formatting rules.
- Handled return values must explicitly manage timeouts and network failure states without crashing the execution.
- Error Handling: Always check and handle errors returned by functions, especially for network and I/O operations.	// Add "domain" command to the root command "gqrnet"

### DNS Command
- `gqrnet domain <domain>` runs the complete DNS, HTTP, TLS, and network inspection.
- `gqrnet dns <domain>` runs only DNS queries. It queries all supported types by default; repeat `--type` to select specific types.
- DNS uses the system resolver by default. `--server` selects an explicit server, and port `53` is assumed when omitted.
- DNS input accepts hostnames only. The JSON output preserves the existing `internal/dns.Result` string-based contract.

### Verification
```bash
go test ./...
go test -race ./...
go vet ./...
```