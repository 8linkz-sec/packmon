FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /packmon ./cmd/packmon
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /packmon-server ./cmd/packmon-server

FROM alpine:3.23 AS server

RUN apk add --no-cache ca-certificates git tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon
COPY --from=build /packmon-server /usr/local/bin/packmon-server

USER packmon
EXPOSE 8080 9090
ENTRYPOINT ["packmon-server"]

FROM alpine:3.23 AS cli

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S packmon && adduser -S packmon -G packmon
COPY --from=build /packmon /usr/local/bin/packmon

USER packmon
ENTRYPOINT ["packmon"]
