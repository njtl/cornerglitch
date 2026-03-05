// Package tlschaos provides TLS configuration chaos for the Glitch server.
// It generates self-signed certificates, manipulates TLS versions and cipher
// suites, and provides per-client TLS config adaptation.
package tlschaos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// ChaosLevel controls the intensity of TLS chaos.
type ChaosLevel int

const (
	LevelClean     ChaosLevel = 0 // Valid TLS 1.3, strong ciphers, valid cert
	LevelDowngrade ChaosLevel = 1 // Allow TLS 1.0/1.1, force TLS 1.2
	LevelWeakCipher ChaosLevel = 2 // Weak cipher suites (3DES, etc.)
	LevelCertChaos ChaosLevel = 3 // Wrong hostname, expired, self-signed
	LevelNightmare ChaosLevel = 4 // All of above + ALPN lies, session chaos
)

// Engine manages TLS chaos configuration.
type Engine struct {
	mu    sync.RWMutex
	level ChaosLevel

	// Certificates for different chaos modes
	validCert   tls.Certificate
	expiredCert tls.Certificate
	wrongHost   tls.Certificate
	weakKeyCert tls.Certificate

	// Base hostnames for cert generation
	hostname string

	// Stats
	requestCount int64
}

// NewEngine creates a new TLS chaos engine.
// certFile/keyFile are optional — if empty, self-signed certs are generated.
func NewEngine(certFile, keyFile, hostname string) (*Engine, error) {
	e := &Engine{
		hostname: hostname,
	}
	if hostname == "" {
		e.hostname = "localhost"
	}

	// Load or generate the valid certificate
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading cert/key: %w", err)
		}
		e.validCert = cert
	} else {
		cert, err := generateCert(e.hostname, time.Now(), time.Now().Add(365*24*time.Hour), nil)
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert: %w", err)
		}
		e.validCert = cert
	}

	// Generate chaos certs
	var err error
	e.expiredCert, err = generateCert(e.hostname, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), nil)
	if err != nil {
		return nil, fmt.Errorf("generating expired cert: %w", err)
	}

	e.wrongHost, err = generateCert("evil.example.com", time.Now(), time.Now().Add(365*24*time.Hour), nil)
	if err != nil {
		return nil, fmt.Errorf("generating wrong-host cert: %w", err)
	}

	// Weak key cert (RSA-1024 equivalent — use P-224 which is considered weak)
	weakKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating weak key: %w", err)
	}
	e.weakKeyCert, err = generateCert(e.hostname, time.Now(), time.Now().Add(365*24*time.Hour), weakKey)
	if err != nil {
		return nil, fmt.Errorf("generating weak-key cert: %w", err)
	}

	return e, nil
}

// SetLevel sets the chaos level (accepts int for dashboard interface compatibility).
func (e *Engine) SetLevel(level int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if level < 0 {
		level = 0
	}
	if level > 4 {
		level = 4
	}
	e.level = ChaosLevel(level)
}

// Level returns the current chaos level as int.
func (e *Engine) Level() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return int(e.level)
}

// ChaosLevelValue returns the typed chaos level.
func (e *Engine) ChaosLevelValue() ChaosLevel {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.level
}

// TLSConfig returns a *tls.Config configured for the current chaos level.
func (e *Engine) TLSConfig() *tls.Config {
	e.mu.RLock()
	level := e.level
	e.mu.RUnlock()

	cfg := &tls.Config{
		GetCertificate:   e.getCertificate,
		GetConfigForClient: e.getConfigForClient,
	}

	switch level {
	case LevelClean:
		cfg.MinVersion = tls.VersionTLS13
		cfg.Certificates = []tls.Certificate{e.validCert}

	case LevelDowngrade:
		cfg.MinVersion = tls.VersionTLS10
		cfg.MaxVersion = tls.VersionTLS12
		cfg.Certificates = []tls.Certificate{e.validCert}

	case LevelWeakCipher:
		cfg.MinVersion = tls.VersionTLS10
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CipherSuites = weakCipherSuites()
		cfg.Certificates = []tls.Certificate{e.validCert}

	case LevelCertChaos:
		cfg.MinVersion = tls.VersionTLS12
		// Don't set Certificates — force all cert selection through getCertificate callback

	case LevelNightmare:
		cfg.MinVersion = tls.VersionTLS10
		cfg.CipherSuites = weakCipherSuites()
		cfg.NextProtos = []string{"h2", "http/1.1", "spdy/3.1", "h2c"} // ALPN lies
		// Don't set Certificates — use getCertificate for cert chaos rotation
		cfg.Renegotiation = tls.RenegotiateOnceAsClient
	}

	return cfg
}

// getCertificate selects a certificate based on chaos level.
func (e *Engine) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	e.mu.RLock()
	level := e.level
	e.mu.RUnlock()

	if level < LevelCertChaos {
		return &e.validCert, nil
	}

	e.mu.Lock()
	e.requestCount++
	count := e.requestCount
	e.mu.Unlock()

	// Rotate through chaos certs
	switch count % 4 {
	case 0:
		return &e.validCert, nil
	case 1:
		return &e.expiredCert, nil
	case 2:
		return &e.wrongHost, nil
	case 3:
		return &e.weakKeyCert, nil
	}
	return &e.validCert, nil
}

// getConfigForClient adapts TLS config per-client.
func (e *Engine) getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	e.mu.RLock()
	level := e.level
	e.mu.RUnlock()

	if level < LevelNightmare {
		return nil, nil // Use default config
	}

	// In nightmare mode, vary config per client
	cfg := e.TLSConfig()

	// Check if client supports only modern TLS
	hasModernOnly := true
	for _, v := range hello.SupportedVersions {
		if v < tls.VersionTLS12 {
			hasModernOnly = false
			break
		}
	}

	if hasModernOnly {
		// Force downgrade for modern clients
		cfg.MaxVersion = tls.VersionTLS12
	}

	// Vary ALPN based on what client requests
	if len(hello.SupportedProtos) > 0 {
		// Lie about protocol support
		cfg.NextProtos = []string{"spdy/3.1", "h2c", "http/1.0"}
	}

	return cfg, nil
}

// SaveCert writes the valid certificate to disk.
func (e *Engine) SaveCert(certPath, keyPath string) error {
	// Extract the leaf cert and key from the valid cert
	cert := e.validCert

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	for _, c := range cert.Certificate {
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unsupported key type")
	}
	b, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	return nil
}

// generateCert creates a self-signed certificate.
func generateCert(hostname string, notBefore, notAfter time.Time, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Glitch Chaos Testing"},
			CommonName:   hostname,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostname)
	}
	// Include localhost only if hostname isn't something intentionally wrong
	if hostname != "evil.example.com" {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
		if hostname != "localhost" {
			template.DNSNames = append(template.DNSNames, "localhost")
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// weakCipherSuites returns deliberately weak cipher suites for chaos testing.
func weakCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}
}
