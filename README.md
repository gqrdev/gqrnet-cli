# gqrnet CLI

gqrnet inspects DNS, HTTP and HTTPS responses, TLS certificates, and network information from the terminal.

## Installation

```bash
go install github.com/gqrdev/gqrnet-cli/cmd/gqrnet@latest
```

## Usage

Complete domain scan:

```bash
gqrnet domain google.com --timeout 10
gqrnet domain google.com --json --timeout 10
```

Standalone DNS query:

```bash
gqrnet dns example.com
gqrnet dns example.com --type A --type MX
gqrnet dns example.com --server 1.1.1.1 --json
```

Standalone passive web security inspection:

```bash
gqrnet http https://example.com/login
gqrnet http https://example.com/login --headers --tls
gqrnet http https://example.com/login --json
```

The `http` command accepts one absolute HTTP or HTTPS URL, including a path and optional port. Without section flags it reports the response, security-related headers, cookie security attributes, the initial redirect, and TLS details when applicable. Use `--headers`, `--cookies`, `--redirects`, or `--tls` to select sections, and `--timeout` to set the execution timeout. The command makes one GET request, does not follow redirects or inspect the response body, and does not perform active vulnerability tests. Cookie values and URL query values are not included in its output.

When `--type` is not provided, `dns` queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, and `TXT` records. The flag can be repeated, and values are case-insensitive. The system DNS resolver is used by default; `--server` allows you to specify a server and defaults to port `53` when no port is provided.

The target must be a hostname without a scheme, path, or port. `--timeout` applies to the entire execution and defaults to 10 seconds. DNS failures are printed in the result without changing the command's exit code.

## Verification

```bash
go test ./...
go test -race ./...
go vet ./...
```