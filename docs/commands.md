# Command Usage

Use `gqrnet --help` to list commands and `gqrnet <command> --help` to see a command's flags.

All commands accept exactly one target. `domain` and `dns` expect a hostname, not a URL, IP address, path, or port. They remove one trailing dot from a hostname. All commands accept `--json` for JSON output and `--timeout` for a positive timeout in seconds (default: 10).

## `domain`

Run the complete domain inspection, including DNS, HTTP/HTTPS, TLS, and network information.

```text
gqrnet domain <target-domain> [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | `false` | Print the result as JSON instead of text. |
| `--timeout` | `10` | Set the execution timeout in seconds; must be greater than zero. |

```bash
gqrnet domain example.com
gqrnet domain example.com --json --timeout 15
```

The target must be a hostname without a scheme, path, or port. IP addresses are not accepted. Inspection errors are reported in the result.

## `dns`

Query DNS records without running the other domain checks.

```text
gqrnet dns <target-domain> [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | `false` | Print the result as JSON instead of text. |
| `--timeout` | `10` | Set the query timeout in seconds; must be greater than zero. |
| `--type` | All supported types | Select a record type. Repeat the flag to query multiple types. Values are case-insensitive. |
| `--server` | System DNS configuration | Select a DNS server. A port defaults to `53` when omitted. |

Supported record types are `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, and `TXT`. When `--type` is omitted, all are queried. Without `--server`, gqrnet reads the system DNS configuration from `/etc/resolv.conf`.

```bash
gqrnet dns example.com
gqrnet dns example.com --type A --type MX
gqrnet dns example.com --server 1.1.1.1 --json
```

The target must be a hostname without a scheme, path, or port; IP addresses are not accepted. DNS query failures are included in the result and do not by themselves make the command fail.

## `http`

Make one passive HTTP request and report response metadata and selected security-related information. This command does not run active vulnerability tests.

```text
gqrnet http <url> [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | `false` | Print the result as JSON instead of text. |
| `--timeout` | `10` | Set the request timeout in seconds; must be greater than zero. |
| `--headers` | `false` | Include security response headers. |
| `--cookies` | `false` | Include cookie security attributes. |
| `--redirects` | `false` | Include the initial redirect destination. |
| `--tls` | `false` | Include TLS connection and certificate details. |

The target must be an absolute HTTP or HTTPS URL. Paths and valid ports are allowed; URLs containing credentials are rejected. With no section flags, all detailed sections are included. If one or more section flags are set, only those sections are included, in text and JSON output.

```bash
gqrnet http https://example.com/login
gqrnet http https://example.com/login --headers --tls
gqrnet http https://example.com/login?next=%2Faccount --json
```

The command sends a single GET request, does not follow redirects, and does not inspect the response body. It reports the initial redirect destination when present. Cookie values are not included, and query values are redacted in the reported URL and redirect destination.