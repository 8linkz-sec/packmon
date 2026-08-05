# E2E Tests

The E2E target builds the CLI binary and runs black-box smoke tests against it:

```bash
make test-e2e
```

On Windows hosts without `make`, build the CLI and run the tagged test directly:

```powershell
go build -o .build\packmon.exe .\cmd\packmon
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags e2e .\tests\e2e
```

The suite verifies that the built binary starts and can parse a real
`package-lock.json` through `packmon scan --list-packages`.

It also includes a narrow headless-browser check for the feed auto-refresh
behavior. The browser test auto-detects Chrome, Chromium, or Edge; set
`PACKMON_BROWSER_BIN` to an executable path when auto-detection is not enough.
