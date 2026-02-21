# --- Build stage ---
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /glitch ./cmd/glitch && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /glitch-proxy ./cmd/glitch-proxy && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /glitch-crawler ./cmd/glitch-crawler

# --- Runtime stage ---
FROM alpine:3.20

LABEL maintainer="glitch-server maintainers"
LABEL description="Intentionally unreliable, adaptive HTTP server for testing"
LABEL org.opencontainers.image.source="https://github.com/njtl/glitchWebServer"

RUN apk add --no-cache ca-certificates

COPY --from=build /glitch /glitch
COPY --from=build /glitch-proxy /glitch-proxy
COPY --from=build /glitch-crawler /glitch-crawler

EXPOSE 8765 8766

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8765/health || exit 1

ENTRYPOINT ["/glitch"]
