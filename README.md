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

Add `--json` to any command for JSON output. Each command also accepts `--timeout` to set its timeout in seconds (default: 10).

See the [command usage guide](docs/commands.md) for flags, defaults, input requirements, and behavior details.

## Verification

```bash
./test.sh
```