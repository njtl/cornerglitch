package attacks

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/glitchWebServer/internal/scanner"
)

// TLSModule generates attack requests targeting TLS configuration weaknesses
// and provides active TLS probing helpers for version detection, cipher suite
// enumeration, certificate analysis, ALPN probing, and downgrade testing.
type TLSModule struct{}

func (m *TLSModule) Name() string     { return "tls" }
func (m *TLSModule) Category() string { return "tls" }

// GenerateRequests returns HTTP-level requests that test TLS-related behaviors:
// HSTS header presence, TLS upgrade headers, HTTP→HTTPS redirect behavior,
// and mixed-case scheme in Host header.
func (m *TLSModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.hstsProbes(target)...)
	reqs = append(reqs, m.tlsUpgradeHeaders(target)...)
	reqs = append(reqs, m.httpToHTTPSRedirect(target)...)
	reqs = append(reqs, m.mixedCaseSchemeHost(target)...)

	return reqs
}

// ---------------------------------------------------------------------------
// HSTS Header Probes
// ---------------------------------------------------------------------------

func (m *TLSModule) hstsProbes(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/login", "/admin", "/api/v1/users"}

	for _, path := range paths {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{},
			Category:    "TLS",
			SubCategory: "hsts-check",
			Description: fmt.Sprintf("Check Strict-Transport-Security header on %s", path),
		})
	}

	// HSTS with various Accept headers to check if HSTS varies by content type.
	acceptTypes := []struct {
		accept string
		desc   string
	}{
		{"text/html", "HTML"},
		{"application/json", "JSON"},
		{"application/xml", "XML"},
		{"*/*", "wildcard"},
	}
	for _, at := range acceptTypes {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Accept": at.accept},
			Category:    "TLS",
			SubCategory: "hsts-content-type",
			Description: fmt.Sprintf("HSTS check with Accept: %s", at.desc),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// TLS Upgrade Headers
// ---------------------------------------------------------------------------

func (m *TLSModule) tlsUpgradeHeaders(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/admin", "/api/v1/users"}

	upgrades := []struct {
		value string
		desc  string
	}{
		{"TLS/1.0", "TLS 1.0 upgrade"},
		{"TLS/1.1", "TLS 1.1 upgrade"},
		{"TLS/1.2", "TLS 1.2 upgrade"},
		{"TLS/1.3", "TLS 1.3 upgrade"},
	}

	for _, path := range paths {
		for _, u := range upgrades {
			reqs = append(reqs, scanner.AttackRequest{
				Method: "GET",
				Path:   path,
				Headers: map[string]string{
					"Upgrade":    u.value,
					"Connection": "Upgrade",
				},
				Category:    "TLS",
				SubCategory: "tls-upgrade",
				Description: fmt.Sprintf("Upgrade: %s on %s", u.desc, path),
			})
		}

		// Upgrade-Insecure-Requests header test.
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"Upgrade-Insecure-Requests": "1",
			},
			Category:    "TLS",
			SubCategory: "upgrade-insecure",
			Description: fmt.Sprintf("Upgrade-Insecure-Requests on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// HTTP to HTTPS Redirect Behavior
// ---------------------------------------------------------------------------

func (m *TLSModule) httpToHTTPSRedirect(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Parse the target to construct HTTP variant if target is HTTPS.
	u, err := url.Parse(target)
	if err != nil {
		return reqs
	}

	paths := []string{"/", "/login", "/admin", "/api/v1/users", "/.env", "/wp-admin"}

	for _, path := range paths {
		// Test if HTTP requests get redirected to HTTPS.
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{},
			Category:    "TLS",
			SubCategory: "http-redirect",
			Description: fmt.Sprintf("Check HTTP→HTTPS redirect on %s", path),
		})

		// Test with X-Forwarded-Proto to simulate proxy stripping TLS.
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"X-Forwarded-Proto": "http",
			},
			Category:    "TLS",
			SubCategory: "forwarded-proto",
			Description: fmt.Sprintf("X-Forwarded-Proto: http on %s", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			Category:    "TLS",
			SubCategory: "forwarded-proto",
			Description: fmt.Sprintf("X-Forwarded-Proto: https on %s", path),
		})
	}

	// POST to sensitive endpoints with forged proto headers.
	sensitivePaths := []string{"/login", "/admin/api/config"}
	for _, path := range sensitivePaths {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   path,
			Headers: map[string]string{
				"X-Forwarded-Proto":  "https",
				"X-Forwarded-Scheme": "https",
				"X-URL-Scheme":       "https",
			},
			Body:        "username=admin&password=admin",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "TLS",
			SubCategory: "proto-spoofing",
			Description: fmt.Sprintf("Proto spoofing via multiple headers on %s", path),
		})
	}

	_ = u // target parsed for future use

	return reqs
}

// ---------------------------------------------------------------------------
// Mixed-Case Scheme in Host Header
// ---------------------------------------------------------------------------

func (m *TLSModule) mixedCaseSchemeHost(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	u, err := url.Parse(target)
	if err != nil {
		return reqs
	}

	host := u.Host

	hostVariations := []struct {
		hostVal string
		desc    string
	}{
		{"HTTPS://" + host, "HTTPS scheme prefix in Host"},
		{"hTtPs://" + host, "Mixed-case HTTPS in Host"},
		{"HTTP://" + host, "HTTP scheme prefix in Host"},
		{"hTtP://" + host, "Mixed-case HTTP in Host"},
		{strings.ToUpper(host), "Uppercase hostname"},
		{"https%3A%2F%2F" + host, "URL-encoded scheme in Host"},
	}

	paths := []string{"/", "/admin"}

	for _, path := range paths {
		for _, h := range hostVariations {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "GET",
				Path:        path,
				Headers:     map[string]string{"Host": h.hostVal},
				Category:    "TLS",
				SubCategory: "mixed-case-host",
				Description: fmt.Sprintf("%s on %s", h.desc, path),
			})
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Active TLS Probing Helpers
// ---------------------------------------------------------------------------

// TLSProbeResult holds the outcome of a single TLS probe attempt.
type TLSProbeResult struct {
	Success  bool   `json:"success"`
	Protocol string `json:"protocol,omitempty"` // negotiated protocol (e.g. "h2", "http/1.1")
	Version  uint16 `json:"version,omitempty"`  // negotiated TLS version
	Cipher   uint16 `json:"cipher,omitempty"`   // negotiated cipher suite
	Error    string `json:"error,omitempty"`
}

// TLSVersionInfo describes a TLS version probe result.
type TLSVersionInfo struct {
	Name      string `json:"name"`
	Version   uint16 `json:"version"`
	Supported bool   `json:"supported"`
	Error     string `json:"error,omitempty"`
}

// CertInfo holds analyzed certificate information.
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IsExpired   bool      `json:"is_expired"`
	ExpiresSoon bool      `json:"expires_soon"` // within 30 days
	DNSNames    []string  `json:"dns_names,omitempty"`
	HostMatch   bool      `json:"host_match"`
	SelfSigned  bool      `json:"self_signed"`
	KeyType     string    `json:"key_type"` // "RSA-2048", "EC-P256", etc.
	KeyBits     int       `json:"key_bits"`
	ChainDepth  int       `json:"chain_depth"`
	Error       string    `json:"error,omitempty"`
}

// CipherProbeResult describes whether a specific weak cipher was accepted.
type CipherProbeResult struct {
	Name     string `json:"name"`
	ID       uint16 `json:"id"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// ALPNProbeResult describes which ALPN protocol was negotiated.
type ALPNProbeResult struct {
	Protocol   string `json:"protocol"`
	Supported  bool   `json:"supported"`
	Negotiated string `json:"negotiated,omitempty"`
	Error      string `json:"error,omitempty"`
}

// TLSTargetReport aggregates all active TLS probe results for a target.
type TLSTargetReport struct {
	Target     string              `json:"target"`
	Versions   []TLSVersionInfo    `json:"versions"`
	Ciphers    []CipherProbeResult `json:"ciphers"`
	Cert       *CertInfo           `json:"cert,omitempty"`
	ALPN       []ALPNProbeResult   `json:"alpn"`
	HTTP2      bool                `json:"http2"`
	Downgrade  *DowngradeResult    `json:"downgrade,omitempty"`
	ProbedAt   time.Time           `json:"probed_at"`
}

// DowngradeResult records the result of a TLS downgrade attempt.
type DowngradeResult struct {
	Attempted       bool   `json:"attempted"`
	DowngradeWorked bool   `json:"downgrade_worked"`
	MaxOffered      uint16 `json:"max_offered"`
	Negotiated      uint16 `json:"negotiated"`
	Error           string `json:"error,omitempty"`
}

// defaultDialTimeout is the timeout for TLS probe connections.
const defaultDialTimeout = 5 * time.Second

// ProbeTarget runs all active TLS probes against the given target URL and
// returns a comprehensive TLSTargetReport.
func (m *TLSModule) ProbeTarget(target string) (*TLSTargetReport, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "443" // default to 443 for TLS probing even on http targets
		}
	}
	addr := net.JoinHostPort(host, port)

	report := &TLSTargetReport{
		Target:   target,
		ProbedAt: time.Now(),
	}

	report.Versions = probeVersions(addr, host)
	report.Ciphers = probeWeakCiphers(addr, host)
	report.Cert = analyzeCert(addr, host)
	report.ALPN = probeALPN(addr, host)
	report.HTTP2 = detectHTTP2(report.ALPN)
	report.Downgrade = probeDowngrade(addr, host)

	return report, nil
}

// ---------------------------------------------------------------------------
// TLS Version Probing
// ---------------------------------------------------------------------------

// tlsVersions maps human-readable names to TLS version constants.
var tlsVersions = []struct {
	name    string
	version uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

func probeVersions(addr, serverName string) []TLSVersionInfo {
	results := make([]TLSVersionInfo, 0, len(tlsVersions))

	for _, v := range tlsVersions {
		info := TLSVersionInfo{
			Name:    v.name,
			Version: v.version,
		}

		cfg := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec — intentional for scanner
			MinVersion:         v.version,
			MaxVersion:         v.version,
		}

		conn, err := dialTLS(addr, cfg)
		if err != nil {
			info.Supported = false
			info.Error = err.Error()
		} else {
			info.Supported = true
			conn.Close()
		}

		results = append(results, info)
	}

	return results
}

// ---------------------------------------------------------------------------
// Cipher Suite Enumeration (weak ciphers)
// ---------------------------------------------------------------------------

// weakCiphers lists known weak cipher suites to test for acceptance.
// Go's crypto/tls only allows configuring TLS 1.0-1.2 cipher suites.
var weakCiphers = []struct {
	name string
	id   uint16
}{
	{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	{"TLS_RSA_WITH_RC4_128_SHA", tls.TLS_RSA_WITH_RC4_128_SHA},
	{"TLS_RSA_WITH_AES_128_CBC_SHA", tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	{"TLS_RSA_WITH_AES_256_CBC_SHA", tls.TLS_RSA_WITH_AES_256_CBC_SHA},
	{"TLS_ECDHE_RSA_WITH_RC4_128_SHA", tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
}

func probeWeakCiphers(addr, serverName string) []CipherProbeResult {
	results := make([]CipherProbeResult, 0, len(weakCiphers))

	for _, c := range weakCiphers {
		result := CipherProbeResult{
			Name: c.name,
			ID:   c.id,
		}

		cfg := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec — intentional for scanner
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12, // cipher suite config only applies to TLS 1.0-1.2
			CipherSuites:       []uint16{c.id},
		}

		conn, err := dialTLS(addr, cfg)
		if err != nil {
			result.Accepted = false
			result.Error = err.Error()
		} else {
			result.Accepted = true
			conn.Close()
		}

		results = append(results, result)
	}

	return results
}

// ---------------------------------------------------------------------------
// Certificate Analysis
// ---------------------------------------------------------------------------

func analyzeCert(addr, serverName string) *CertInfo {
	info := &CertInfo{}

	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec — intentional for scanner
	}

	conn, err := dialTLS(addr, cfg)
	if err != nil {
		info.Error = fmt.Sprintf("connection failed: %s", err)
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		info.Error = "no peer certificates presented"
		return info
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	info.Subject = cert.Subject.CommonName
	info.Issuer = cert.Issuer.CommonName
	info.NotBefore = cert.NotBefore
	info.NotAfter = cert.NotAfter
	info.IsExpired = now.After(cert.NotAfter)
	info.ExpiresSoon = !info.IsExpired && cert.NotAfter.Before(now.Add(30*24*time.Hour))
	info.DNSNames = cert.DNSNames
	info.ChainDepth = len(state.PeerCertificates)

	// Check hostname match.
	info.HostMatch = cert.VerifyHostname(serverName) == nil

	// Check self-signed: issuer == subject and only one cert in chain.
	info.SelfSigned = cert.Subject.CommonName == cert.Issuer.CommonName &&
		len(state.PeerCertificates) == 1

	// Key type and size.
	info.KeyType, info.KeyBits = classifyKey(cert)

	return info
}

// classifyKey returns a human-readable key type and bit size from a certificate.
func classifyKey(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		// RSA keys implement Size() returning bytes.
		bits := pub.Size() * 8
		return fmt.Sprintf("RSA-%d", bits), bits
	case interface {
		Params() *struct {
			P, N, B *big.Int
			Gx, Gy  *big.Int
			BitSize int
			Name    string
		}
	}:
		// This won't match — handle EC below.
		return "EC-unknown", 0
	default:
		// Fallback: use the certificate's PublicKeyAlgorithm.
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			return "RSA", 0
		case x509.ECDSA:
			return classifyECKey(cert)
		case x509.Ed25519:
			return "Ed25519-256", 256
		default:
			return cert.PublicKeyAlgorithm.String(), 0
		}
	}
}

// classifyECKey attempts to determine EC key curve and size.
func classifyECKey(cert *x509.Certificate) (string, int) {
	// Try to get curve info via the standard interfaces.
	type ecPublicKey interface {
		Params() *struct {
			P, N, B *big.Int
			Gx, Gy  *big.Int
			BitSize int
			Name    string
		}
	}

	// Use reflect-free approach: check key algorithm from cert.
	// The PublicKey field for ECDSA is *ecdsa.PublicKey, which has Curve.Params().
	// Since we can't import crypto/ecdsa without it being used, use a type switch.
	type curveParamer interface {
		Curve() interface{ Params() interface{ BitSize() int } }
	}

	// Simplest approach: read the signature algorithm for hints.
	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA256:
		return "EC-P256", 256
	case x509.ECDSAWithSHA384:
		return "EC-P384", 384
	case x509.ECDSAWithSHA512:
		return "EC-P521", 521
	default:
		return "ECDSA", 0
	}
}

// ---------------------------------------------------------------------------
// ALPN Probing
// ---------------------------------------------------------------------------

// alpnProtocols lists the ALPN protocol identifiers to test.
var alpnProtocols = []string{"h2", "http/1.1", "h2c", "spdy/3.1"}

func probeALPN(addr, serverName string) []ALPNProbeResult {
	results := make([]ALPNProbeResult, 0, len(alpnProtocols))

	for _, proto := range alpnProtocols {
		result := ALPNProbeResult{
			Protocol: proto,
		}

		cfg := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec — intentional for scanner
			NextProtos:         []string{proto},
		}

		conn, err := dialTLS(addr, cfg)
		if err != nil {
			result.Supported = false
			result.Error = err.Error()
		} else {
			state := conn.ConnectionState()
			result.Negotiated = state.NegotiatedProtocol
			result.Supported = state.NegotiatedProtocol == proto
			conn.Close()
		}

		results = append(results, result)
	}

	return results
}

// ---------------------------------------------------------------------------
// HTTP/2 Detection
// ---------------------------------------------------------------------------

func detectHTTP2(alpnResults []ALPNProbeResult) bool {
	for _, r := range alpnResults {
		if r.Protocol == "h2" && r.Supported {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// TLS Downgrade Testing
// ---------------------------------------------------------------------------

func probeDowngrade(addr, serverName string) *DowngradeResult {
	result := &DowngradeResult{
		Attempted:  true,
		MaxOffered: tls.VersionTLS12,
	}

	// Attempt to connect with MaxVersion=TLS1.0 to see if server accepts downgrade.
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec — intentional for scanner
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	}

	conn, err := dialTLS(addr, cfg)
	if err != nil {
		result.DowngradeWorked = false
		result.Error = err.Error()
		return result
	}

	state := conn.ConnectionState()
	result.Negotiated = state.Version
	result.DowngradeWorked = state.Version == tls.VersionTLS10
	conn.Close()

	return result
}

// ---------------------------------------------------------------------------
// Helper: dial with TLS
// ---------------------------------------------------------------------------

func dialTLS(addr string, cfg *tls.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
