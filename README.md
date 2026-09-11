# gqrnet CLI

## Tests

Run the automated tests without requiring network access:

```bash
go test ./...
go test -race ./...
go vet ./...
```

To manually verify the complete scan against a public domain:

```bash
go run . domain google.com --timeout 10
go run . domain google.com --json --timeout 10
```