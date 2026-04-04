# E2E Tests

Packmon uses the integration suite in `tests/integration` as the default end-to-end smoke path.

Run:

```bash
make test-e2e
```

That target:

1. builds `packmon`
2. builds `packmon-server`
3. runs the integration suite with the `integration` build tag
