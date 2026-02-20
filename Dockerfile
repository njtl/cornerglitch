FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /glitch ./cmd/glitch

FROM alpine:3.20
COPY --from=build /glitch /glitch
EXPOSE 8765 8766
ENTRYPOINT ["/glitch"]
