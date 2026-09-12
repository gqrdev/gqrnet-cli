# gqrnet CLI

gqrnet inspects DNS, HTTP, TLS, and network information from the terminal.

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

When `--type` is not provided, `dns` queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, and `TXT` records. The flag can be repeated, and values are case-insensitive. The system DNS resolver is used by default; `--server` allows you to specify a server and defaults to port `53` when no port is provided.

The target must be a hostname without a scheme, path, or port. `--timeout` applies to the entire execution and defaults to 10 seconds. DNS failures are printed in the result without changing the command's exit code.

## Verification

```bash
go test ./...
go test -race ./...
go vet ./...
```