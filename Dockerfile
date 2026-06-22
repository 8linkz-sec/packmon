FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS build

RUN apk upgrade --no-cache

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /packmon ./cmd/packmon
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /packmon-server ./cmd/packmon-server

FROM alpine:3.23 AS server

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates git tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon && \
    mkdir -p /data/feeds && chown packmon:packmon /data/feeds
COPY --from=build /packmon-server /usr/local/bin/packmon-server

USER packmon
EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["packmon-server"]

FROM alpine:3.23 AS cli

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon
COPY --from=build /packmon /usr/local/bin/packmon

USER packmon
ENTRYPOINT ["packmon"]
