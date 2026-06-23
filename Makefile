VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOEXE   ?= $(shell go env GOEXE)
GOTMPDIR ?= $(CURDIR)/.gotmp
COVERAGE_MIN ?= 79.5
GO_PACKAGES ?= $(shell go list ./...)
GOSEC_DIRS ?= $(shell go list -f '{{.Dir}}' ./...)
GOFMT_FILES ?= $(shell git ls-files '*.go')
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build build-server test test-ci test-integration test-e2e vet lint fmt security clean

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon$(GOEXE) ./cmd/packmon

build-server:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon-server$(GOEXE) ./cmd/packmon-server

test:
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" go test -count=1 -race -coverprofile=coverage.out $(GO_PACKAGES)
	go run ./tools/checkcoverage -profile=coverage.out -min=$(COVERAGE_MIN)

test-ci:
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" go test -count=1 ./tests/ci

test-integration: build build-server
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -count=1 -tags integration ./tests/integration ./internal/db/postgres ./internal/db/postgres/migrations

test-e2e: build
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -count=1 -tags e2e ./tests/e2e

vet:
	mkdir -p "$(GOTMPDIR)"
	GOTMPDIR="$(GOTMPDIR)" go vet $(GO_PACKAGES)

lint:
	golangci-lint run ./...
	@test -z "$$(gofumpt -extra -l $(GOFMT_FILES))" || (echo "gofumpt needed on:"; gofumpt -extra -l $(GOFMT_FILES); exit 1)

fmt:
	gofumpt -extra -w $(GOFMT_FILES)

security:
	govulncheck $(GO_PACKAGES)
	gosec -nosec-require-rules -nosec-require-justification $(GOSEC_DIRS)

clean:
	rm -f packmon packmon-server packmon.exe packmon-server.exe coverage.out
