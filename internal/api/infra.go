package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
)

// InfraAPI handles infrastructure management endpoints.
type InfraAPI struct{}

// NewInfraAPI creates a new InfraAPI handler.
func NewInfraAPI() *InfraAPI {
	return &InfraAPI{}
}

// ServeHTTP dispatches infrastructure API requests.
func (i *InfraAPI) ServeHTTP(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method == http.MethodOptions {
		return handleOptions(w)
	}

	switch {
	case strings.HasPrefix(apiPath, "/v1/servers"):
		return i.handleServers(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/deployments"):
		return i.handleDeployments(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/containers"):
		return i.handleContainers(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/clusters"):
		return i.handleClusters(w, r, apiPath)
	}

	writeJSON(w, http.StatusNotFound, map[string]interface{}{
		"error":   "not_found",
		"message": "Unknown infrastructure endpoint",
	})
	return http.StatusNotFound
}

// --- Servers ---

func (i *InfraAPI) handleServers(w http.ResponseWriter, r *http.Request, apiPath string) int {
	id := extractID(apiPath, "/v1/servers")

	if id == "" {
		// Collection endpoints: GET (list) or POST (provision)
		switch r.Method {
		case http.MethodGet:
			return i.listServers(w, r)
		case http.MethodPost:
			return i.provisionServer(w, r)
		default:
			return methodNotAllowed(w, "GET, POST, OPTIONS")
		}
	}

	// Sub-resource check
	sub := subResource(apiPath, "/v1/servers")
	if sub == "metrics" {
		if r.Method != http.MethodGet {
			return methodNotAllowed(w, "GET, OPTIONS")
		}
		return i.serverMetrics(w, r, id)
	}

	// Individual server: GET or DELETE
	switch r.Method {
	case http.MethodGet:
		return i.getServer(w, r, id)
	case http.MethodDelete:
		return i.deleteServer(w, r, id)
	default:
		return methodNotAllowed(w, "GET, DELETE, OPTIONS")
	}
}

func (i *InfraAPI) listServers(w http.ResponseWriter, r *http.Request) int {
	const total = 85
	page, perPage := parsePagination(r)

	start := (page - 1) * perPage
	if start >= total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	servers := make([]map[string]interface{}, 0, end-start)
	for idx := start; idx < end; idx++ {
		servers = append(servers, i.generateServer(idx, false))
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	paginatedJSON(w, r, servers, total)
	return http.StatusOK
}

func (i *InfraAPI) getServer(w http.ResponseWriter, r *http.Request, id string) int {
	rng := pathSeed("/v1/servers/" + id)
	idx := rng.Intn(85)
	server := i.generateServer(idx, true)
	server["id"] = id

	// Additional detail fields
	server["network_interfaces"] = i.generateNetworkInterfaces(rng)
	server["running_processes_count"] = 40 + rng.Intn(260)
	server["installed_packages"] = i.generateInstalledPackages(rng)

	writeJSON(w, http.StatusOK, server)
	return http.StatusOK
}

func (i *InfraAPI) provisionServer(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed(fmt.Sprintf("/v1/servers/provision/%s", randHex(8)))
	server := map[string]interface{}{
		"id":         deterministicUUID(rng),
		"hostname":   "new-server-" + fmt.Sprintf("%02d", rng.Intn(99)),
		"status":     "provisioning",
		"type":       "web",
		"region":     "us-east-1",
		"created_at": deterministicTimestamp(rng),
		"message":    "Server provisioning initiated",
	}
	writeJSON(w, http.StatusCreated, server)
	return http.StatusCreated
}

func (i *InfraAPI) deleteServer(w http.ResponseWriter, r *http.Request, id string) int {
	addCommonHeaders(w)
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent
}

func (i *InfraAPI) serverMetrics(w http.ResponseWriter, r *http.Request, id string) int {
	rng := pathSeed("/v1/servers/" + id + "/metrics")

	samples := make([]map[string]interface{}, 12)
	baseCPU := 10.0 + rng.Float64()*50.0
	baseMem := 20.0 + rng.Float64()*60.0
	baseDisk := 15.0 + rng.Float64()*50.0
	baseNetIn := 5.0 + rng.Float64()*95.0
	baseNetOut := 2.0 + rng.Float64()*48.0

	for j := 0; j < 12; j++ {
		samples[j] = map[string]interface{}{
			"timestamp":            fmt.Sprintf("2025-12-01T%02d:%02d:00Z", 10+j/12, (j*5)%60),
			"cpu_usage_percent":    clampFloat(baseCPU+rng.Float64()*20.0-10.0, 0, 100),
			"memory_usage_percent": clampFloat(baseMem+rng.Float64()*10.0-5.0, 0, 100),
			"disk_usage_percent":   clampFloat(baseDisk+rng.Float64()*4.0-2.0, 0, 100),
			"network_in_mbps":      clampFloat(baseNetIn+rng.Float64()*20.0-10.0, 0, 1000),
			"network_out_mbps":     clampFloat(baseNetOut+rng.Float64()*10.0-5.0, 0, 1000),
		}
	}

	resp := map[string]interface{}{
		"server_id":      id,
		"interval":       "5m",
		"data_points":    12,
		"metrics":        samples,
	}
	writeJSON(w, http.StatusOK, resp)
	return http.StatusOK
}

func (i *InfraAPI) generateServer(idx int, detailed bool) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("/v1/servers/item/%d", idx))

	serverTypes := []string{"web", "db", "cache", "worker", "lb"}
	statuses := []string{"running", "stopped", "error", "maintenance"}
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"}
	osList := []string{"Ubuntu 22.04", "Ubuntu 24.04", "Debian 12", "Amazon Linux 2023", "CentOS Stream 9", "Rocky Linux 9"}

	sType := serverTypes[rng.Intn(len(serverTypes))]
	region := regions[rng.Intn(len(regions))]
	status := statuses[rng.Intn(len(statuses))]

	hostname := generateHostname(rng, sType, idx)

	cpuCores := []int{2, 4, 8, 16, 32, 64}[rng.Intn(6)]
	memoryGB := []int{4, 8, 16, 32, 64, 128, 256}[rng.Intn(7)]
	diskGB := []int{50, 100, 200, 500, 1000, 2000}[rng.Intn(6)]

	load1 := rng.Float64() * float64(cpuCores)
	load5 := rng.Float64() * float64(cpuCores)
	load15 := rng.Float64() * float64(cpuCores)

	return map[string]interface{}{
		"id":           deterministicUUID(rng),
		"hostname":     hostname,
		"ip_address":   generatePrivateIP(rng),
		"status":       status,
		"type":         sType,
		"region":       region,
		"cpu_cores":    cpuCores,
		"memory_gb":    memoryGB,
		"disk_gb":      diskGB,
		"os":           osList[rng.Intn(len(osList))],
		"uptime_hours":  rng.Intn(8760),
		"load_avg":     []float64{roundFloat(load1, 2), roundFloat(load5, 2), roundFloat(load15, 2)},
		"created_at":   deterministicTimestamp(rng),
	}
}

func (i *InfraAPI) generateNetworkInterfaces(rng *rand.Rand) []map[string]interface{} {
	count := 1 + rng.Intn(3)
	ifaces := make([]map[string]interface{}, count)
	names := []string{"eth0", "eth1", "ens5", "ens6", "bond0"}
	for j := 0; j < count; j++ {
		ifaces[j] = map[string]interface{}{
			"name":       names[j%len(names)],
			"ip_address": generatePrivateIP(rng),
			"mac":        generateMAC(rng),
			"speed_mbps": []int{1000, 10000, 25000}[rng.Intn(3)],
			"state":      "up",
		}
	}
	return ifaces
}

func (i *InfraAPI) generateInstalledPackages(rng *rand.Rand) []map[string]interface{} {
	allPkgs := []struct {
		name    string
		version string
	}{
		{"nginx", "1.24.0"}, {"postgresql-16", "16.2"}, {"redis-server", "7.2.4"},
		{"docker-ce", "25.0.3"}, {"openssh-server", "9.6"}, {"curl", "8.5.0"},
		{"vim", "9.1"}, {"htop", "3.3.0"}, {"tmux", "3.4"}, {"git", "2.43.0"},
		{"python3", "3.12.3"}, {"node", "20.11.0"}, {"go", "1.22.1"},
		{"prometheus-node-exporter", "1.7.0"}, {"fail2ban", "1.0.2"},
		{"certbot", "2.8.0"}, {"logrotate", "3.21.0"}, {"cron", "3.0"},
		{"rsync", "3.2.7"}, {"wget", "1.21.4"},
	}

	count := 5 + rng.Intn(len(allPkgs)-5)
	pkgs := make([]map[string]interface{}, count)
	perm := rng.Perm(len(allPkgs))
	for j := 0; j < count; j++ {
		p := allPkgs[perm[j]]
		pkgs[j] = map[string]interface{}{
			"name":    p.name,
			"version": p.version,
		}
	}
	return pkgs
}

// --- Deployments ---

func (i *InfraAPI) handleDeployments(w http.ResponseWriter, r *http.Request, apiPath string) int {
	id := extractID(apiPath, "/v1/deployments")

	if id == "" {
		switch r.Method {
		case http.MethodGet:
			return i.listDeployments(w, r)
		case http.MethodPost:
			return i.triggerDeployment(w, r)
		default:
			return methodNotAllowed(w, "GET, POST, OPTIONS")
		}
	}

	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}
	return i.getDeployment(w, r, id)
}

func (i *InfraAPI) listDeployments(w http.ResponseWriter, r *http.Request) int {
	const total = 200
	page, perPage := parsePagination(r)

	start := (page - 1) * perPage
	if start >= total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	deployments := make([]map[string]interface{}, 0, end-start)
	for idx := start; idx < end; idx++ {
		deployments = append(deployments, i.generateDeployment(idx, false))
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	paginatedJSON(w, r, deployments, total)
	return http.StatusOK
}

func (i *InfraAPI) getDeployment(w http.ResponseWriter, r *http.Request, id string) int {
	rng := pathSeed("/v1/deployments/" + id)
	idx := rng.Intn(200)
	dep := i.generateDeployment(idx, true)
	dep["id"] = id

	// Build log detail
	dep["build_log"] = i.generateBuildLog(rng)

	writeJSON(w, http.StatusOK, dep)
	return http.StatusOK
}

func (i *InfraAPI) triggerDeployment(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed(fmt.Sprintf("/v1/deployments/trigger/%s", randHex(8)))
	dep := map[string]interface{}{
		"id":          deterministicUUID(rng),
		"service":     "api-gateway",
		"environment": "staging",
		"status":      "deploying",
		"version":     fmt.Sprintf("v%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100)),
		"git_sha":     randHex(20),
		"deployed_by": deterministicEmail(rng, "deployer"),
		"deployed_at": deterministicTimestamp(rng),
		"message":     "Deployment initiated",
	}
	writeJSON(w, http.StatusCreated, dep)
	return http.StatusCreated
}

func (i *InfraAPI) generateDeployment(idx int, detailed bool) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("/v1/deployments/item/%d", idx))

	services := []string{
		"api-gateway", "user-service", "payment-service", "notification-service",
		"auth-service", "search-service", "billing-service", "analytics-engine",
		"data-pipeline", "media-processor", "email-worker", "report-generator",
	}
	environments := []string{"prod", "staging", "dev"}
	statuses := []string{"running", "deploying", "failed", "rolled_back"}

	service := services[rng.Intn(len(services))]
	env := environments[rng.Intn(len(environments))]
	status := statuses[rng.Intn(len(statuses))]
	version := fmt.Sprintf("v%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100))

	sha := make([]byte, 20)
	for j := range sha {
		sha[j] = "0123456789abcdef"[rng.Intn(16)]
	}

	firstNames := []string{"alice", "bob", "charlie", "diana", "eric", "fiona", "george", "hannah"}
	deployer := firstNames[rng.Intn(len(firstNames))]

	var rollbackTo interface{}
	if status == "rolled_back" {
		rollbackTo = fmt.Sprintf("v%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100))
	} else {
		rollbackTo = nil
	}

	return map[string]interface{}{
		"id":          deterministicUUID(rng),
		"service":     service,
		"environment": env,
		"status":      status,
		"version":     version,
		"git_sha":     string(sha),
		"deployed_by": deterministicEmail(rng, deployer),
		"deployed_at": deterministicTimestamp(rng),
		"rollback_to": rollbackTo,
	}
}

func (i *InfraAPI) generateBuildLog(rng *rand.Rand) []string {
	templates := []string{
		"[%s] Cloning repository...",
		"[%s] Checking out commit %s",
		"[%s] Installing dependencies...",
		"[%s] Running linter... OK",
		"[%s] Running unit tests... %d passed, 0 failed",
		"[%s] Building Docker image...",
		"[%s] Pushing image to registry: %s",
		"[%s] Updating Kubernetes deployment...",
		"[%s] Waiting for rollout to complete...",
		"[%s] Health check passed on %d/%d pods",
		"[%s] Deployment complete. Duration: %ds",
	}

	lines := make([]string, len(templates))
	baseMin := rng.Intn(60)
	for j, tmpl := range templates {
		ts := fmt.Sprintf("2025-12-01T14:%02d:%02dZ", baseMin+j/2, (j*12)%60)
		switch j {
		case 1:
			sha := make([]byte, 7)
			for k := range sha {
				sha[k] = "0123456789abcdef"[rng.Intn(16)]
			}
			lines[j] = fmt.Sprintf(tmpl, ts, string(sha))
		case 4:
			lines[j] = fmt.Sprintf(tmpl, ts, 42+rng.Intn(200))
		case 6:
			lines[j] = fmt.Sprintf(tmpl, ts, fmt.Sprintf("registry.internal/%s:%s", "service", randHex(8)))
		case 9:
			pods := 2 + rng.Intn(6)
			lines[j] = fmt.Sprintf(tmpl, ts, pods, pods)
		case 10:
			lines[j] = fmt.Sprintf(tmpl, ts, 30+rng.Intn(270))
		default:
			lines[j] = fmt.Sprintf(tmpl, ts)
		}
	}
	return lines
}

// --- Containers ---

func (i *InfraAPI) handleContainers(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}
	return i.listContainers(w, r)
}

func (i *InfraAPI) listContainers(w http.ResponseWriter, r *http.Request) int {
	const total = 340
	page, perPage := parsePagination(r)

	start := (page - 1) * perPage
	if start >= total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	containers := make([]map[string]interface{}, 0, end-start)
	for idx := start; idx < end; idx++ {
		containers = append(containers, i.generateContainer(idx))
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	paginatedJSON(w, r, containers, total)
	return http.StatusOK
}

func (i *InfraAPI) generateContainer(idx int) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("/v1/containers/item/%d", idx))

	images := []string{
		"nginx:1.25-alpine", "postgres:16-bookworm", "redis:7.2-alpine",
		"node:20-slim", "python:3.12-slim", "golang:1.22-alpine",
		"grafana/grafana:10.3", "prom/prometheus:v2.49", "envoyproxy/envoy:v1.29",
		"hashicorp/consul:1.17", "vault:1.15", "rabbitmq:3.13-management",
		"mongo:7.0", "elasticsearch:8.12", "memcached:1.6-alpine",
		"traefik:v3.0", "minio/minio:latest", "clickhouse/clickhouse-server:24",
	}
	statuses := []string{"running", "stopped", "exited", "created"}

	image := images[rng.Intn(len(images))]
	status := statuses[rng.Intn(len(statuses))]

	// Short hex container ID (12 chars, like Docker)
	idBytes := make([]byte, 12)
	for j := range idBytes {
		idBytes[j] = "0123456789abcdef"[rng.Intn(16)]
	}

	// Container name from image
	nameParts := strings.Split(strings.Split(image, ":")[0], "/")
	baseName := nameParts[len(nameParts)-1]
	name := fmt.Sprintf("%s-%d", baseName, rng.Intn(100))

	// Ports
	portCount := rng.Intn(3) + 1
	ports := make([]string, portCount)
	commonPorts := []int{80, 443, 3000, 5432, 6379, 8080, 8443, 9090, 9200, 27017}
	for j := 0; j < portCount; j++ {
		hostPort := 10000 + rng.Intn(55000)
		containerPort := commonPorts[rng.Intn(len(commonPorts))]
		ports[j] = fmt.Sprintf("%d:%d/tcp", hostPort, containerPort)
	}

	cpuPercent := roundFloat(rng.Float64()*25.0, 2)
	memoryMB := roundFloat(64.0+rng.Float64()*1936.0, 1)

	return map[string]interface{}{
		"id":          string(idBytes),
		"image":       image,
		"status":      status,
		"ports":       ports,
		"cpu_percent": cpuPercent,
		"memory_mb":   memoryMB,
		"created_at":  deterministicTimestamp(rng),
		"name":        name,
	}
}

// --- Clusters ---

func (i *InfraAPI) handleClusters(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}
	return i.listClusters(w, r)
}

func (i *InfraAPI) listClusters(w http.ResponseWriter, r *http.Request) int {
	const total = 5

	clusters := make([]map[string]interface{}, total)
	for idx := 0; idx < total; idx++ {
		clusters[idx] = i.generateCluster(idx)
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	paginatedJSON(w, r, clusters, total)
	return http.StatusOK
}

func (i *InfraAPI) generateCluster(idx int) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("/v1/clusters/item/%d", idx))

	providers := []string{"aws", "gcp", "azure"}
	statuses := []string{"active", "provisioning", "upgrading", "degraded"}
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"}
	names := []string{"production-main", "staging-alpha", "dev-sandbox", "data-processing", "ml-training"}
	versions := []string{"1.28.4", "1.29.1", "1.30.0", "1.27.9"}

	name := names[idx%len(names)]
	provider := providers[idx%len(providers)]
	region := regions[idx%len(regions)]

	return map[string]interface{}{
		"id":         deterministicUUID(rng),
		"name":       name,
		"provider":   provider,
		"version":    versions[rng.Intn(len(versions))],
		"node_count": 3 + rng.Intn(18),
		"status":     statuses[rng.Intn(len(statuses))],
		"region":     region,
		"created_at": deterministicTimestamp(rng),
	}
}

// --- Helpers ---

func generateHostname(rng *rand.Rand, serverType string, idx int) string {
	prefixes := map[string][]string{
		"web":    {"web-prod", "web-staging", "web-edge", "frontend"},
		"db":     {"db-primary", "db-replica", "db-analytics", "db-archive"},
		"cache":  {"cache-edge", "cache-session", "cache-data", "redis-cluster"},
		"worker": {"worker-bg", "worker-queue", "worker-cron", "celery"},
		"lb":     {"lb-external", "lb-internal", "haproxy", "nginx-lb"},
	}

	options := prefixes[serverType]
	if len(options) == 0 {
		options = []string{"srv"}
	}
	prefix := options[rng.Intn(len(options))]

	suffixes := []string{"us", "eu", "ap", "01", "02", "03"}
	suffix := suffixes[rng.Intn(len(suffixes))]

	return fmt.Sprintf("%s-%s-%02d", prefix, suffix, idx%100)
}

func generatePrivateIP(rng *rand.Rand) string {
	if rng.Intn(2) == 0 {
		return fmt.Sprintf("10.%d.%d.%d", rng.Intn(256), rng.Intn(256), 1+rng.Intn(254))
	}
	return fmt.Sprintf("172.16.%d.%d", rng.Intn(16), 1+rng.Intn(254))
}

func generateMAC(rng *rand.Rand) string {
	octets := make([]string, 6)
	for j := 0; j < 6; j++ {
		octets[j] = fmt.Sprintf("%02x", rng.Intn(256))
	}
	// Set locally administered bit
	b, _ := strconv.ParseUint(octets[0], 16, 8)
	b = (b | 0x02) & 0xFE // locally administered, unicast
	octets[0] = fmt.Sprintf("%02x", b)
	return strings.Join(octets, ":")
}

func roundFloat(val float64, decimals int) float64 {
	pow := 1.0
	for d := 0; d < decimals; d++ {
		pow *= 10.0
	}
	return float64(int(val*pow+0.5)) / pow
}

func clampFloat(val, min, max float64) float64 {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return roundFloat(val, 2)
}
