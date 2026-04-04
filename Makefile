VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build build-server test lint fmt security clean

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon ./cmd/packmon

build-server:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o packmon-server ./cmd/packmon-server

test:
	go test -race -coverprofile=coverage.out ./...

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
