# Changelog

## v1.4.0 - 2026-11-13

- Add reverse DNS PTR lookups and support for CAA, HTTPS, SRV, and SVCB records.
- Update Go dependencies and the Docker base image.

## v1.3.0 - 2026-10-09

- Add a mail DNS audit command for MX, SPF, and DMARC configuration.

## v1.2.0 - 2026-10-09

- Add HTTP redirect-chain inspection with a configurable maximum number of redirects.

## v1.1.1 - 2026-10-02

- Add a configurable per-connection timeout to TCP port checks.

## v1.1.0 - 2026-10-02

- Add TCP port connectivity scanning, including full-range scans by default and an option to show only open ports.
- Add a passive HTTP security audit command and HTTPS inspection to domain scans.
- Improve DNS queries to preserve partial results when an individual record query fails.
- Validate and normalize domain targets, and document command usage.

## v1.0.1 - 2026-09-12

- Introduce the `gqrnet` CLI with DNS-only queries and domain inspection for DNS, HTTP, TLS, and resolved network addresses.
