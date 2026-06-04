VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOEXE   ?= $(shell go env GOEXE)
GOTMPDIR ?= $(CURDIR)/.gotmp
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build build-server test test-ci test-integration test-e2e lint fmt security clean helm-template

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon$(GOEXE) ./cmd/packmon

build-server:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon-server$(GOEXE) ./cmd/packmon-server

test:
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" go test -race -coverprofile=coverage.out ./...

test-ci:
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" go test ./tests/ci

test-integration: build build-server
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -tags integration ./tests/integration

test-e2e: build
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -tags e2e ./tests/e2e

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
