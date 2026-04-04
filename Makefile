VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOEXE   ?= $(shell go env GOEXE)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build build-server test test-integration test-e2e lint fmt security clean helm-template

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon$(GOEXE) ./cmd/packmon

build-server:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon-server$(GOEXE) ./cmd/packmon-server

test:
	go test -race -coverprofile=coverage.out ./...

test-integration: build build-server
	PACKMON_TEST_BIN_DIR=$(CURDIR) go test -tags integration ./tests/integration

test-e2e: test-integration

helm-template:
	helm template packmon ./deploy/helm/packmon

lint:
	golangci-lint run ./...
	@test -z "$$(gofumpt -l .)" || (echo "gofumpt needed on:"; gofumpt -l .; exit 1)

fmt:
	gofumpt -w .

security:
	govulncheck ./...
	gosec ./...

clean:
	rm -f packmon packmon-server packmon.exe packmon-server.exe coverage.out
