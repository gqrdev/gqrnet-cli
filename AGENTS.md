# gqrnet

gqrnet is a Go CLI for querying DNS and mail records, inspecting HTTP response metadata, following URL redirect chains, inspecting TLS certificates, resolving IPv4/IPv6 addresses, and checking TCP connectivity on ports 1-65535 by default.

## Repository guidance

- Follow the architecture and directory conventions in [.github/copilot-instructions.md](.github/copilot-instructions.md).
- Keep HTTP checks passive; `redirects` follows only the requested URL's redirect chain. Port checks test TCP connectivity and do not identify services or test for vulnerabilities.
- Run network checks only against systems you are authorized to inspect.
- Preserve existing CLI behavior and output formats; follow established code and test patterns, and update related documentation when behavior changes.
- For Go code changes, run `./test.sh`; use focused package tests when appropriate.


