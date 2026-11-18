# syntax=docker/dockerfile:1
ARG PACKMON_GO_BUILDER_IMAGE=golang:1.27-alpine
ARG PACKMON_ALPINE_RUNTIME_IMAGE=alpine:3.24

# Both base images follow their line tags without a digest, so every fresh or
# --pull build takes the line's current image and its security fixes; a new
# Go or Alpine line is a deliberate edit here (tests/ci checks the policy).
# DL3006: hadolint does not resolve ARG defaults; both ARGs above are tagged.
# hadolint ignore=DL3006
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
    -o /packmon ./cmd/packmon && \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /packmon-server ./cmd/packmon-server

# hadolint ignore=DL3006
FROM ${PACKMON_ALPINE_RUNTIME_IMAGE} AS server

# Runtime packages are deliberately unpinned: every build first upgrades the
# base image's packages and then installs the current Alpine release of each
# package, so the image always carries the distribution's security updates
# and never fails when Alpine retires an exact package version.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
      ca-certificates \
      git \
      tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /data/feeds /usr/share/doc/packmon && chown packmon:packmon /data/feeds
COPY --from=build /packmon-server /usr/local/bin/packmon-server
COPY SECURITY.md /usr/share/doc/packmon/SECURITY.md
COPY LICENSE /usr/share/doc/packmon/LICENSE

# DL3066: packmon is the system user created above; the image needs no host
# uid mapping.
# hadolint ignore=DL3066
USER packmon
ENV PACKMON_SERVER_PORT=8080
ENV PACKMON_METRICS_PORT=9090
EXPOSE ${PACKMON_SERVER_PORT} ${PACKMON_METRICS_PORT}

# DL3025: the probe needs a shell to choose http or https from the TLS env.
# hadolint ignore=DL3025
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD scheme=http; \
      wget_opts="-qO-"; \
      if [ -n "$PACKMON_TLS_CERT_FILE" ] && [ -n "$PACKMON_TLS_KEY_FILE" ]; then \
        scheme=https; \
        wget_opts="$wget_opts --no-check-certificate"; \
      fi; \
      wget $wget_opts "${scheme}://localhost:${PACKMON_SERVER_PORT:-8080}/readyz" || exit 1

ENTRYPOINT ["packmon-server"]

# hadolint ignore=DL3006
FROM ${PACKMON_ALPINE_RUNTIME_IMAGE} AS cli

# Unpinned on purpose; see the server stage.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
      ca-certificates \
      tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /usr/share/doc/packmon
COPY --from=build /packmon /usr/local/bin/packmon
COPY SECURITY.md /usr/share/doc/packmon/SECURITY.md
COPY LICENSE /usr/share/doc/packmon/LICENSE

# DL3066: packmon is the system user created above; the image needs no host
# uid mapping.
# hadolint ignore=DL3066
USER packmon
ENTRYPOINT ["packmon"]
