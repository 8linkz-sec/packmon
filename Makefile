VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOEXE   ?= $(shell go env GOEXE)
GOTMPDIR ?= $(CURDIR)/.gotmp
COVERAGE_MIN ?= 79.5
override GOFLAGS := -mod=readonly
export GOFLAGS
GO_PACKAGES ?= $(shell go list ./... | grep -v /node_modules/)
GOSEC_DIRS ?= $(shell go list -f '{{.Dir}}' ./...)
GOFMT_FILES ?= $(shell git ls-files '*.go')
GOLANGCI_LINT_VERSION ?= v2.11.0
GOFUMPT_VERSION ?= v0.9.2
GOLANGCI_LINT_VERSION_NUMBER := $(patsubst v%,%,$(GOLANGCI_LINT_VERSION))
SHELLCHECK_IMAGE ?= koalaman/shellcheck-alpine:v0.10.0
HADOLINT_IMAGE ?= hadolint/hadolint:v2.12.0-alpine
ACTIONLINT_VERSION ?= v1.7.7
PSSCRIPTANALYZER_VERSION ?= 1.24.0
TRIVY ?= trivy
SERVER_IMAGE ?= packmon-server:local
CLI_IMAGE ?= packmon-cli:local
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build build-server test test-ci test-integration test-e2e vet lint fmt security security-images verify clean check-go-lint-tools check-gofumpt-tool check-golangci-lint-tool lint-nongo lint-web lint-openapi lint-shell lint-docker lint-actions lint-powershell

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

lint: check-go-lint-tools lint-nongo lint-web lint-openapi lint-shell lint-docker lint-actions lint-powershell
	golangci-lint run ./...
	@test -z "$$(gofumpt -extra -l $(GOFMT_FILES))" || (echo "gofumpt needed on:"; gofumpt -extra -l $(GOFMT_FILES); exit 1)

fmt: check-gofumpt-tool
	gofumpt -extra -w $(GOFMT_FILES)

check-go-lint-tools: check-gofumpt-tool check-golangci-lint-tool

check-gofumpt-tool:
	@actual="$$(gofumpt -version 2>/dev/null || true)"; case "$$actual" in *"$(GOFUMPT_VERSION)"*) ;; *) echo "gofumpt $$actual does not match $(GOFUMPT_VERSION)"; exit 1;; esac

check-golangci-lint-tool:
	@actual="$$(golangci-lint version 2>/dev/null || true)"; case "$$actual" in *"$(GOLANGCI_LINT_VERSION_NUMBER)"*) ;; *) echo "golangci-lint $$actual does not match $(GOLANGCI_LINT_VERSION)"; exit 1;; esac

lint-nongo:
	bash scripts/check-non-go-format.sh

lint-web:
	npm ci --ignore-scripts
	npm run lint:web

lint-openapi:
	npm ci --ignore-scripts
	npm run lint:openapi

lint-shell:
	docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(SHELLCHECK_IMAGE) scripts/*.sh scripts/lib/*.sh deploy/n8n/*.sh

lint-docker:
	docker run --rm -i $(HADOLINT_IMAGE) < Dockerfile

lint-actions:
	go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	actionlint

lint-powershell:
	pwsh -NoLogo -NoProfile -Command 'Install-Module -Name PSScriptAnalyzer -RequiredVersion $(PSSCRIPTANALYZER_VERSION) -Scope CurrentUser -Force; Invoke-ScriptAnalyzer -Path scripts -Recurse -Severity Error'

security:
	npm ci --ignore-scripts
	npm audit --audit-level=high
	govulncheck $(GO_PACKAGES)
	gosec -nosec-require-rules -nosec-require-justification $(GOSEC_DIRS)
	$(TRIVY) fs --scanners vuln --vuln-type library --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .

# security-images scans the runtime images themselves. `trivy fs` above only
# covers library dependencies in the working tree and says nothing about the
# Alpine packages baked into the image -- which is where OS-level CVEs live.
# Kept separate from `security` because it has to build both images first.
security-images:
	docker build --target server -t $(SERVER_IMAGE) .
	docker build --target cli -t $(CLI_IMAGE) .
	$(TRIVY) image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(SERVER_IMAGE)
	$(TRIVY) image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(CLI_IMAGE)

# verify is the full release gate. Every check that guards a release runs here,
# including the tag-gated suites: those had silently drifted for months because
# nothing executed them, and a suite nothing runs is not a safety net.
verify: lint vet test test-ci test-integration test-e2e security security-images

clean:
	rm -f packmon packmon-server packmon.exe packmon-server.exe coverage.out
