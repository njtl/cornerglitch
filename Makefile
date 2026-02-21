.PHONY: build test vet clean docker-build docker-run run run-proxy cross

# Build all binaries
build:
	go build -o glitch ./cmd/glitch
	go build -o glitch-proxy ./cmd/glitch-proxy
	go build -o glitch-crawler ./cmd/glitch-crawler

# Run tests
test:
	go test ./...

# Static analysis
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -f glitch glitch-proxy glitch-crawler
	rm -f glitch-linux-amd64 glitch-linux-arm64 glitch-darwin-amd64 glitch-darwin-arm64

# Docker
docker-build:
	docker build -t glitch-server .

docker-run:
	docker run -p 8765:8765 -p 8766:8766 glitch-server

# Run directly
run: build
	./glitch

# Run proxy mode (usage: make run-proxy TARGET=http://localhost:80)
run-proxy: build
	./glitch-proxy -target $(TARGET)

# Build for multiple platforms
cross:
	GOOS=linux GOARCH=amd64 go build -o glitch-linux-amd64 ./cmd/glitch
	GOOS=linux GOARCH=arm64 go build -o glitch-linux-arm64 ./cmd/glitch
	GOOS=darwin GOARCH=amd64 go build -o glitch-darwin-amd64 ./cmd/glitch
	GOOS=darwin GOARCH=arm64 go build -o glitch-darwin-arm64 ./cmd/glitch
