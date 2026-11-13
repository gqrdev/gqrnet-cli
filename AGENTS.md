# gqrnet

gqrnet is a Go CLI for inspecting DNS and mail records, HTTP response metadata,
TLS certificates, redirect chains, IP addresses, and TCP connectivity.

## Project structure

- Cobra commands and CLI orchestration live in `cmd/`.
- Reusable inspection logic lives in `internal/`.
- Follow the established architecture and directory conventions in those packages.
- Keep tests alongside the code they cover.
- Update `README.md` and `docs/commands.md` when command behavior, flags, or defaults change.

## Behavior and safety

- Run network checks only against systems you are authorized to inspect.
- Keep HTTP checks passive: `http` makes one request and does not follow redirects
  or inspect the response body. `redirects` follows only the requested URL's chain;
  it does not crawl a site.
- Port checks test TCP connectivity only. Do not add service detection or
  vulnerability testing.
- Preserve existing redaction of URL query values and cookie values in HTTP output.

## Compatibility

- Preserve existing command arguments, flags, defaults, validation, and text/JSON output
  unless a behavior change is explicitly requested.
- Add or update focused tests for behavior changes, including output where applicable.

## Verification

- For Go changes, run `./test.sh`. It runs tests, the race detector, and `go vet`.
- Use focused `go test` package tests when appropriate.
