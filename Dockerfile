# syntax=docker/dockerfile:1
ARG PACKMON_GO_BUILDER_IMAGE=golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648
ARG PACKMON_ALPINE_RUNTIME_IMAGE=alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM ${PACKMON_GO_BUILDER_IMAGE} AS build

WORKDIR /src
COPY go.mod go.sum* ./
ENV GOFLAGS=-mod=readonly
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# Persist the Go build cache across image builds so an incremental
# `docker compose up --build` recompiles only changed packages instead of the
# whole dependency tree (modernc.org/sqlite alone is a heavy compile).
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /packmon ./cmd/packmon
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /packmon-server ./cmd/packmon-server
RUN --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/google/go-licenses@v1.6.0 && \
    go-licenses save ./cmd/packmon ./cmd/packmon-server --save_path /go-license-notices --force \
      --ignore github.com/8linkz-sec/packmon \
      --ignore modernc.org/mathutil

FROM ${PACKMON_ALPINE_RUNTIME_IMAGE} AS server

RUN apk add --no-cache \
      ca-certificates=20260611-r0 \
      git=2.54.0-r0 \
      tzdata=2026b-r0 && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /data/feeds /usr/share/doc/packmon/LICENSES && chown packmon:packmon /data/feeds
COPY --from=build /packmon-server /usr/local/bin/packmon-server
COPY LICENSE /usr/share/doc/packmon/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/packmon/THIRD_PARTY_NOTICES.md
COPY SECURITY.md /usr/share/doc/packmon/SECURITY.md
COPY --from=build /go-license-notices /usr/share/doc/packmon/go-license-notices

USER packmon
ENV PACKMON_SERVER_PORT=8080
ENV PACKMON_METRICS_PORT=9090
EXPOSE ${PACKMON_SERVER_PORT} ${PACKMON_METRICS_PORT}

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD scheme=http; \
      wget_opts="-qO-"; \
      if [ -n "$PACKMON_TLS_CERT_FILE" ] && [ -n "$PACKMON_TLS_KEY_FILE" ]; then \
        scheme=https; \
        wget_opts="$wget_opts --no-check-certificate"; \
      fi; \
      wget $wget_opts "${scheme}://localhost:${PACKMON_SERVER_PORT:-8080}/readyz" || exit 1

ENTRYPOINT ["packmon-server"]

FROM ${PACKMON_ALPINE_RUNTIME_IMAGE} AS cli

RUN apk add --no-cache \
      ca-certificates=20260611-r0 \
      tzdata=2026b-r0 && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /usr/share/doc/packmon/LICENSES
COPY --from=build /packmon /usr/local/bin/packmon
COPY LICENSE /usr/share/doc/packmon/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/packmon/THIRD_PARTY_NOTICES.md
COPY SECURITY.md /usr/share/doc/packmon/SECURITY.md
COPY --from=build /go-license-notices /usr/share/doc/packmon/go-license-notices

USER packmon
ENTRYPOINT ["packmon"]
