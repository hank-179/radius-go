# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.25.10

FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src

ENV CGO_ENABLED=1

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/radius-go ./cmd/radius-go

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 radius \
    && useradd --system --uid 10001 --gid radius --home-dir /app --shell /usr/sbin/nologin radius \
    && install -d -o radius -g radius /app/data /app/logs

WORKDIR /app

COPY --from=builder /out/radius-go /usr/local/bin/radius-go
COPY config.example.yaml /app/config.example.yaml

USER radius:radius

EXPOSE 8080/tcp
EXPOSE 1812/udp

VOLUME ["/app/data", "/app/logs"]

ENTRYPOINT ["/usr/local/bin/radius-go"]
CMD ["-config", "/app/config.yaml"]
