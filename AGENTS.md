AGENTS.md

# Overview
gqrnet is an open-source command-line interface (CLI) written in Go designed for infrastructure and networking inspection. The primary CLI command is gqrnet.  

# Project Structure
```plaintext
gqrnet/
├── cmd/
│   ├── root.go       # Root command ("gqrnet"), global flags, subcommands registration
│   └── domain.go     # "gqrnet domain <domain>" command orchestration
├── internal/
│   ├── domain/       # Domain scanning coordinator and unified result structures
│   ├── dns/          # DNS queries (A, AAAA, CNAME, MX, NS, TXT, SOA) via github.com/miekg/dns
│   ├── http/         # HTTP/HTTPS requests, status, headers, redirects via net/http
│   ├── tls/          # TLS handshake inspection (versions, cipher suites, certs) via crypto/tls
│   ├── network/      # IPv4 and IPv6 resolution using net library
│   └── output/       # Terminal text rendering and JSON output formatters
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
- Concurrency & Timeouts: Coordinate concurrent tasks and execution timeouts exclusively within internal/domain/scanner.go.
- CLI Layer: CLI flags and input handling belong in cmd/. Direct business logic must not be placed inside cmd/ files.

### Code Style
- Follow standard Go idioms and gofmt formatting rules.
- Handled return values must explicitly manage timeouts and network failure states without crashing the execution.
- Error Handling: Always check and handle errors returned by functions, especially for network and I/O operations.	// Add "domain" command to the root command "gqrnet"