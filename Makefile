.PHONY: build test vet clean docker-build docker-push k8s-deploy run cross

BINARY     := glitch
IMAGE      := ghcr.io/njtl/glitch-server
TAG        := latest
NAMESPACE  := glitch-server

# Default target
all: build

# Build the server binary
build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) ./cmd/glitch

# Run tests
test:
	go test ./... -count=1

# Static analysis
vet:
	go vet ./...

# Remove build artifacts
clean:
	rm -f glitch glitch-proxy glitch-crawler
	rm -f glitch-linux-amd64 glitch-linux-arm64 glitch-darwin-amd64 glitch-darwin-arm64

# Build Docker image
docker-build:
	docker build -t $(IMAGE):$(TAG) .

# Push Docker image to GHCR
docker-push: docker-build
	docker push $(IMAGE):$(TAG)

# Deploy to Kubernetes
k8s-deploy:
	kubectl apply -f deploy/k8s/configmap.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/deployment.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/service.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/ingress.yaml -n $(NAMESPACE)

# Run locally
run: build
	./$(BINARY)

# Build for multiple platforms
cross:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o glitch-linux-amd64 ./cmd/glitch
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o glitch-linux-arm64 ./cmd/glitch
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o glitch-darwin-amd64 ./cmd/glitch
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o glitch-darwin-arm64 ./cmd/glitch
