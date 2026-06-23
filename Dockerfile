FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /packmon ./cmd/packmon
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /packmon-server ./cmd/packmon-server

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS server

RUN apk add --no-cache ca-certificates git tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /data/feeds /usr/share/doc/packmon/LICENSES && chown packmon:packmon /data/feeds
COPY --from=build /packmon-server /usr/local/bin/packmon-server
COPY LICENSE /usr/share/doc/packmon/LICENSE
COPY LICENSES/LicenseRef-Private.txt /usr/share/doc/packmon/LICENSES/LicenseRef-Private.txt
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/packmon/THIRD_PARTY_NOTICES.md

USER packmon
EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD scheme=http; \
      wget_opts="-qO-"; \
      if [ -n "$PACKMON_TLS_CERT_FILE" ] && [ -n "$PACKMON_TLS_KEY_FILE" ]; then \
        scheme=https; \
        wget_opts="$wget_opts --no-check-certificate"; \
      fi; \
      wget $wget_opts "${scheme}://localhost:${PACKMON_PORT:-8080}/readyz" || exit 1

ENTRYPOINT ["packmon-server"]

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS cli

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /usr/share/doc/packmon/LICENSES
COPY --from=build /packmon /usr/local/bin/packmon
COPY LICENSE /usr/share/doc/packmon/LICENSE
COPY LICENSES/LicenseRef-Private.txt /usr/share/doc/packmon/LICENSES/LicenseRef-Private.txt
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/packmon/THIRD_PARTY_NOTICES.md

USER packmon
ENTRYPOINT ["packmon"]
