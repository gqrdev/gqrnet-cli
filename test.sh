#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

run_check() {
    local description="$1"
    shift

    printf '\n==> %s\n' "$description"
    "$@"
}

run_check "Executing tests" go test ./...
run_check "Executing tests with the race detector" go test -race ./...
run_check "Executing go vet" go vet ./...

printf '\nAll tests and checks have completed successfully.\n'
