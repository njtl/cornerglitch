.PHONY: build test vet clean docker-build docker-push k8s-deploy run start stop restart logs status cross db-up db-down db-reset db-psql

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
	kubectl apply -f deploy/k8s/namespace.yaml
	kubectl apply -f deploy/k8s/configmap.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/postgres-secret.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/postgres-statefulset.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/postgres-service.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/deployment.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/service.yaml -n $(NAMESPACE)
	kubectl apply -f deploy/k8s/ingress.yaml -n $(NAMESPACE)

# Run locally (auto-loads .env)
run: build
	./$(BINARY)

# Run in background with logging
start: build
	@echo "Starting Glitch server..."
	@nohup ./$(BINARY) > /tmp/glitch.log 2>&1 & echo "$$!" > .glitch.pid
	@sleep 1 && head -10 /tmp/glitch.log
	@echo "PID: $$(cat .glitch.pid) — logs: /tmp/glitch.log"

# Stop background server
stop:
	@if [ -f .glitch.pid ]; then \
		kill $$(cat .glitch.pid) 2>/dev/null && echo "Stopped PID $$(cat .glitch.pid)" || echo "Process not running"; \
		rm -f .glitch.pid; \
	else \
		echo "No .glitch.pid file found"; \
	fi

# Restart background server
restart: stop
	@sleep 2
	@$(MAKE) start

# Show server logs
logs:
	@tail -f /tmp/glitch.log

# Show server status
status:
	@if [ -f .glitch.pid ] && kill -0 $$(cat .glitch.pid) 2>/dev/null; then \
		echo "Glitch is running (PID $$(cat .glitch.pid))"; \
	else \
		echo "Glitch is not running"; \
		rm -f .glitch.pid 2>/dev/null; \
	fi

# Build for multiple platforms
cross:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o glitch-linux-amd64 ./cmd/glitch
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o glitch-linux-arm64 ./cmd/glitch
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o glitch-darwin-amd64 ./cmd/glitch
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o glitch-darwin-arm64 ./cmd/glitch

# Database targets
DB_CONTAINER := glitch-postgres
DB_USER      := glitch
DB_NAME      := glitch
DB_PORT      := 5432

# Start PostgreSQL container
db-up:
	@docker run -d --name $(DB_CONTAINER) \
		-e POSTGRES_USER=$(DB_USER) \
		-e POSTGRES_PASSWORD=$(DB_USER) \
		-e POSTGRES_DB=$(DB_NAME) \
		-v glitch-pgdata:/var/lib/postgresql/data \
		-p $(DB_PORT):5432 \
		--health-cmd="pg_isready -U $(DB_USER)" \
		--health-interval=5s \
		--health-timeout=3s \
		--health-retries=5 \
		postgres:16-alpine
	@echo "PostgreSQL started on port $(DB_PORT)"

# Stop and remove PostgreSQL container
db-down:
	@docker stop $(DB_CONTAINER) 2>/dev/null || true
	@docker rm $(DB_CONTAINER) 2>/dev/null || true
	@echo "PostgreSQL stopped"

# Drop and recreate database
db-reset: db-down
	@docker volume rm glitch-pgdata 2>/dev/null || true
	@$(MAKE) db-up
	@echo "Database reset complete"

# Connect to PostgreSQL with psql
db-psql:
	@docker exec -it $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME)
