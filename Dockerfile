# syntax=docker/dockerfile:1
ARG PACKMON_GO_BUILDER_IMAGE=golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb
ARG PACKMON_ALPINE_RUNTIME_IMAGE=alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

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
FROM ${PACKMON_ALPINE_RUNTIME_IMAGE} AS server

RUN apk add --no-cache \
      ca-certificates=20261020-r0 \
      git=2.54.0-r0 \
      tzdata=2026e-r0 && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /data/feeds /usr/share/doc/packmon && chown packmon:packmon /data/feeds
COPY --from=build /packmon-server /usr/local/bin/packmon-server
COPY SECURITY.md /usr/share/doc/packmon/SECURITY.md
COPY LICENSE /usr/share/doc/packmon/LICENSE

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
      ca-certificates=20261020-r0 \
      tzdata=2026e-r0 && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /usr/share/doc/packmon
COPY --from=build /packmon /usr/local/bin/packmon
COPY SECURITY.md /usr/share/doc/packmon/SECURITY.md
COPY LICENSE /usr/share/doc/packmon/LICENSE

USER packmon
ENTRYPOINT ["packmon"]
