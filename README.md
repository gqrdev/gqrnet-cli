# gqrnet CLI

gqrnet is a command-line tool for inspecting domain DNS records, HTTP responses, TLS certificates, and network information.

## Installation

```bash
go install github.com/gqrdev/gqrnet-cli/cmd/gqrnet@latest
```

## Quick start

| Command | Use it to | Example |
| --- | --- | --- |
| `domain` | Run a complete inspection of a hostname | `gqrnet domain example.com` |
| `dns` | Query DNS records only | `gqrnet dns example.com --type A --type MX` |
| `http` | Passively inspect an HTTP or HTTPS URL | `gqrnet http https://example.com/login --headers --tls` |
| `port` | Find open TCP ports or check selected ports | `gqrnet port example.com` |

Add `--json` to any command for JSON output. Each command accepts `--timeout`; the default is 10 seconds, except `port`, which defaults to 120 seconds.

See the [command usage guide](docs/commands.md) for flags, defaults, input requirements, and behavior details.

Without `--port`, the `port` command checks TCP ports 1-65535 and displays open ports per resolved IP. Repeat `--port` to check selected ports and display each requested status, including closed ports; add `--open-only` to filter the displayed results to open ports. The flag does not change the scan or its summary. Scans are limited to 100 concurrent connections and may be partial if the timeout expires. The command does not identify services or run vulnerability tests; use it only against systems you are authorized to inspect.

## Verification

```bash
./test.sh
```