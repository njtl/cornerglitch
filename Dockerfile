# --- Build stage ---
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /glitch ./cmd/glitch

# --- Runtime stage ---
FROM alpine:3.20

LABEL maintainer="glitch-server maintainers"
LABEL description="Intentionally unreliable, adaptive HTTP server for testing"
LABEL org.opencontainers.image.source="https://github.com/njtl/cornerglitch"

RUN apk add --no-cache ca-certificates curl

RUN adduser -D -u 1000 glitch
USER glitch

COPY --from=builder /glitch /glitch

ENV GLITCH_CONFIG=""
ENV GLITCH_HEALTH_SECRET="docker-healthcheck-secret"

EXPOSE 8765 8766 8767

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8765/_internal/${GLITCH_HEALTH_SECRET}/healthz || exit 1

ENTRYPOINT ["/glitch"]
CMD []
