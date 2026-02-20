package honeypot

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// LureGenerator produces realistic-looking fake responses for honeypot paths.
// All generated content is deterministic (seeded from request path via SHA-256)
// and designed to entice scanners into further interaction.
type LureGenerator struct{}

// NewLureGenerator creates a new lure response generator.
func NewLureGenerator() *LureGenerator {
	return &LureGenerator{}
}

// Serve dispatches to the appropriate lure handler based on type and writes the
// response. Returns the HTTP status code written.
func (l *LureGenerator) Serve(w http.ResponseWriter, r *http.Request, lureType LureType) int {
	w.Header().Set("X-Glitch-Honeypot", "true")

	rng := l.rngFromPath(r.URL.Path)

	switch lureType {
	case LureAdminPanel:
		return l.serveAdminPanel(w, r, rng)
	case LureConfigFile:
		return l.serveConfigFile(w, r, rng)
	case LureBackupDump:
		return l.serveBackupDump(w, r, rng)
	case LureLoginPage:
		return l.serveLoginPage(w, r, rng)
	case LureAPIKey:
		return l.serveAPIKey(w, r, rng)
	case LureDebugInfo:
		return l.serveDebugInfo(w, r, rng)
	case LureGitExposure:
		return l.serveGitExposure(w, r, rng)
	case LureEnvFile:
		return l.serveEnvFile(w, r, rng)
	case LureDBDump:
		return l.serveDBDump(w, r, rng)
	case LureShellAccess:
		return l.serveShellAccess(w, r, rng)
	case LureWordPress:
		return l.serveWordPress(w, r, rng)
	case LurePhpMyAdmin:
		return l.servePhpMyAdmin(w, r, rng)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
		return http.StatusNotFound
	}
}

// rngFromPath creates a deterministic RNG seeded from the request path.
func (l *LureGenerator) rngFromPath(path string) *rand.Rand {
	h := sha256.Sum256([]byte(path))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	return rand.New(rand.NewSource(seed))
}

// fakeHex generates a hex string of the given byte-length using the RNG.
func fakeHex(rng *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	var sb strings.Builder
	for _, v := range b {
		fmt.Fprintf(&sb, "%02x", v)
	}
	return sb.String()
}

// fakeBase64 generates a base64-ish string of the given length.
func fakeBase64(rng *rand.Rand, n int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rng.Intn(len(chars))]
	}
	return string(b)
}

// fakeToken generates a prefixed token string.
func fakeToken(rng *rand.Rand, prefix string, length int) string {
	return prefix + fakeBase64(rng, length)
}

// fakeBcrypt generates a bcrypt-looking hash.
func fakeBcrypt(rng *rand.Rand) string {
	return "$2b$12$" + fakeBase64(rng, 53)
}

// -----------------------------------------------------------------------
// Individual lure generators
// -----------------------------------------------------------------------

func (l *LureGenerator) serveAdminPanel(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	csrfToken := fakeHex(rng, 32)
	sessionHint := fakeHex(rng, 16)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Glitch CMS v4.2.1 - Administration</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .login-container { background: #16213e; border-radius: 8px; padding: 40px; width: 400px; box-shadow: 0 10px 40px rgba(0,0,0,0.4); }
    .logo { text-align: center; margin-bottom: 30px; }
    .logo h1 { font-size: 24px; color: #e94560; }
    .logo p { font-size: 12px; color: #666; margin-top: 4px; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; margin-bottom: 6px; font-size: 14px; color: #aaa; }
    .form-group input { width: 100%%; padding: 12px; border: 1px solid #333; border-radius: 4px; background: #0f3460; color: #eee; font-size: 14px; }
    .form-group input:focus { outline: none; border-color: #e94560; }
    .btn { width: 100%%; padding: 12px; border: none; border-radius: 4px; background: #e94560; color: #fff; font-size: 16px; cursor: pointer; }
    .btn:hover { background: #c73650; }
    .footer { text-align: center; margin-top: 24px; font-size: 11px; color: #555; }
    .footer a { color: #e94560; text-decoration: none; }
    .alert { background: #533; border: 1px solid #e94560; border-radius: 4px; padding: 10px; margin-bottom: 16px; font-size: 13px; color: #faa; display: none; }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="logo">
      <h1>Glitch CMS v4.2.1</h1>
      <p>Content Management System</p>
    </div>
    <div class="alert" id="login-error">Invalid credentials. Please try again.</div>
    <form method="POST" action="%s">
      <input type="hidden" name="_csrf" value="%s">
      <input type="hidden" name="_session_hint" value="%s">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="admin" autocomplete="username" required>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Enter password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn">Sign In</button>
    </form>
    <div class="footer">
      <p>Powered by Glitch Framework &copy; 2024</p>
      <p style="margin-top:8px"><a href="/admin/forgot-password">Forgot password?</a> | <a href="/admin/help">Help</a></p>
    </div>
  </div>
</body>
</html>`, r.URL.Path, csrfToken, sessionHint)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (l *LureGenerator) serveConfigFile(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	path := strings.ToLower(r.URL.Path)

	switch {
	case strings.HasSuffix(path, ".php"):
		return l.serveConfigPHP(w, rng)
	case strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml"):
		return l.serveConfigYAML(w, rng)
	case strings.HasSuffix(path, ".json"):
		return l.serveConfigJSON(w, rng)
	default:
		return l.serveConfigEnv(w, rng)
	}
}

func (l *LureGenerator) serveConfigEnv(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/plain")

	appKey := fakeBase64(rng, 32)
	dbPass := fakeToken(rng, "", 12)
	awsKey := "AKIA" + fakeBase64(rng, 16)
	awsSecret := fakeBase64(rng, 40)
	appSecret := fakeHex(rng, 32)

	content := fmt.Sprintf(`APP_NAME=GlitchApp
APP_ENV=production
APP_KEY=base64:%s
APP_DEBUG=false
APP_URL=https://app.glitchcorp.internal

LOG_CHANNEL=stack
LOG_LEVEL=warning

DB_CONNECTION=mysql
DB_HOST=db-prod-01.glitchcorp.internal
DB_PORT=3306
DB_DATABASE=glitch_production
DB_USERNAME=glitch_app
DB_PASSWORD=%s

BROADCAST_DRIVER=redis
CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis
SESSION_LIFETIME=120

REDIS_HOST=cache-prod-01.glitchcorp.internal
REDIS_PASSWORD=%s
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@mg.glitchcorp.com
MAIL_PASSWORD=%s

AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=glitch-prod-assets

STRIPE_KEY=pk_live_%s
STRIPE_SECRET=sk_live_%s

APP_SECRET=%s
JWT_SECRET=%s
`, appKey, dbPass, fakeToken(rng, "", 16), fakeToken(rng, "", 20),
		awsKey, awsSecret,
		fakeBase64(rng, 24), fakeBase64(rng, 24),
		appSecret, fakeHex(rng, 32))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveConfigPHP(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/plain")

	content := fmt.Sprintf(`<?php
return [
    'database' => [
        'driver'   => 'mysql',
        'host'     => 'db-prod-01.glitchcorp.internal',
        'port'     => 3306,
        'database' => 'glitch_production',
        'username' => 'glitch_app',
        'password' => '%s',
        'charset'  => 'utf8mb4',
        'collation'=> 'utf8mb4_unicode_ci',
        'prefix'   => '',
        'strict'   => true,
    ],

    'redis' => [
        'default' => [
            'host'     => 'cache-prod-01.glitchcorp.internal',
            'password' => '%s',
            'port'     => 6379,
            'database' => 0,
        ],
    ],

    'mail' => [
        'driver'   => 'smtp',
        'host'     => 'smtp.mailgun.org',
        'port'     => 587,
        'username' => 'postmaster@mg.glitchcorp.com',
        'password' => '%s',
    ],

    'services' => [
        'stripe' => [
            'key'    => 'pk_live_%s',
            'secret' => 'sk_live_%s',
        ],
        'aws' => [
            'key'    => 'AKIA%s',
            'secret' => '%s',
            'region' => 'us-east-1',
            'bucket' => 'glitch-prod-assets',
        ],
    ],

    'app' => [
        'key'    => 'base64:%s',
        'cipher' => 'AES-256-CBC',
    ],
];
`, fakeToken(rng, "", 12), fakeToken(rng, "", 16),
		fakeToken(rng, "", 20),
		fakeBase64(rng, 24), fakeBase64(rng, 24),
		fakeBase64(rng, 16), fakeBase64(rng, 40),
		fakeBase64(rng, 32))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveConfigYAML(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/yaml")

	content := fmt.Sprintf(`# Glitch Application Configuration
# WARNING: This file contains production credentials

app:
  name: GlitchApp
  env: production
  debug: false
  secret_key: "%s"

database:
  primary:
    adapter: postgresql
    host: db-prod-01.glitchcorp.internal
    port: 5432
    database: glitch_production
    username: glitch_app
    password: "%s"
    pool: 25
    timeout: 5000
  replica:
    adapter: postgresql
    host: db-replica-01.glitchcorp.internal
    port: 5432
    database: glitch_production
    username: glitch_readonly
    password: "%s"
    pool: 10

redis:
  host: cache-prod-01.glitchcorp.internal
  port: 6379
  password: "%s"
  db: 0

aws:
  access_key_id: "AKIA%s"
  secret_access_key: "%s"
  region: us-east-1
  s3:
    bucket: glitch-prod-assets
    endpoint: null

smtp:
  host: smtp.mailgun.org
  port: 587
  username: postmaster@mg.glitchcorp.com
  password: "%s"

jwt:
  secret: "%s"
  expiration: 3600
  refresh_expiration: 86400
`, fakeHex(rng, 32), fakeToken(rng, "", 16),
		fakeToken(rng, "", 12), fakeToken(rng, "", 16),
		fakeBase64(rng, 16), fakeBase64(rng, 40),
		fakeToken(rng, "", 20), fakeHex(rng, 32))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveConfigJSON(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "application/json")

	content := fmt.Sprintf(`{
  "app": {
    "name": "GlitchApp",
    "env": "production",
    "debug": false,
    "secret": "%s"
  },
  "database": {
    "host": "db-prod-01.glitchcorp.internal",
    "port": 3306,
    "name": "glitch_production",
    "user": "glitch_app",
    "password": "%s"
  },
  "redis": {
    "host": "cache-prod-01.glitchcorp.internal",
    "port": 6379,
    "password": "%s"
  },
  "api_keys": {
    "stripe_publishable": "pk_live_%s",
    "stripe_secret": "sk_live_%s",
    "sendgrid": "SG.%s",
    "twilio_sid": "AC%s",
    "twilio_token": "%s"
  },
  "aws": {
    "access_key_id": "AKIA%s",
    "secret_access_key": "%s",
    "region": "us-east-1"
  },
  "jwt": {
    "secret": "%s",
    "algorithm": "HS256",
    "expiration": 3600
  }
}
`, fakeHex(rng, 32), fakeToken(rng, "", 16),
		fakeToken(rng, "", 16),
		fakeBase64(rng, 24), fakeBase64(rng, 24),
		fakeBase64(rng, 32),
		fakeHex(rng, 16), fakeHex(rng, 16),
		fakeBase64(rng, 16), fakeBase64(rng, 40),
		fakeHex(rng, 32))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveBackupDump(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	path := strings.ToLower(r.URL.Path)

	if strings.HasSuffix(path, ".zip") || strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz") || strings.HasSuffix(path, ".rar") || strings.HasSuffix(path, ".7z") {
		return l.serveBackupArchive(w, rng)
	}
	return l.serveBackupSQL(w, rng)
}

func (l *LureGenerator) serveBackupSQL(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "application/sql")
	w.Header().Set("Content-Disposition", "attachment; filename=backup.sql")

	dbNames := []string{"production_db", "glitch_main", "app_data", "customer_db"}
	dbName := dbNames[rng.Intn(len(dbNames))]

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`-- MySQL dump 10.13  Distrib 8.0.33, for Linux (x86_64)
--
-- Host: db-prod-01.glitchcorp.internal    Database: %s
-- ------------------------------------------------------
-- Server version	8.0.33-0ubuntu0.22.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;

--
-- Table structure for table `+"`users`"+`
--

DROP TABLE IF EXISTS `+"`users`"+`;
CREATE TABLE `+"`users`"+` (
  `+"`id`"+` int NOT NULL AUTO_INCREMENT,
  `+"`email`"+` varchar(255) NOT NULL,
  `+"`password_hash`"+` varchar(255) NOT NULL,
  `+"`full_name`"+` varchar(255) DEFAULT NULL,
  `+"`role`"+` enum('admin','editor','viewer') DEFAULT 'viewer',
  `+"`api_token`"+` varchar(64) DEFAULT NULL,
  `+"`created_at`"+` datetime DEFAULT CURRENT_TIMESTAMP,
  `+"`updated_at`"+` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`+"`id`"+`),
  UNIQUE KEY `+"`idx_email`"+` (`+"`email`"+`),
  KEY `+"`idx_role`"+` (`+"`role`"+`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `+"`users`"+`
--

LOCK TABLES `+"`users`"+` WRITE;
`, dbName))

	firstNames := []string{"admin", "john.smith", "jane.doe", "bob.wilson", "alice.chen", "carlos.garcia", "sarah.jones", "mike.taylor", "emma.brown", "dev.ops"}
	domains := []string{"glitchcorp.com", "example.com", "glitchcorp.internal"}
	roles := []string{"admin", "editor", "viewer", "admin", "editor"}

	numUsers := rng.Intn(6) + 5
	if numUsers > len(firstNames) {
		numUsers = len(firstNames)
	}

	sb.WriteString("INSERT INTO `users` VALUES\n")
	for i := 0; i < numUsers; i++ {
		email := fmt.Sprintf("%s@%s", firstNames[i], domains[rng.Intn(len(domains))])
		hash := fakeBcrypt(rng)
		role := roles[rng.Intn(len(roles))]
		token := fakeHex(rng, 32)
		name := strings.ReplaceAll(firstNames[i], ".", " ")
		// Capitalize each word
		words := strings.Split(name, " ")
		for j, w := range words {
			if len(w) > 0 {
				words[j] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		name = strings.Join(words, " ")

		sep := ","
		if i == numUsers-1 {
			sep = ";"
		}
		sb.WriteString(fmt.Sprintf("  (%d,'%s','%s','%s','%s','%s','2024-%02d-%02d 08:%02d:%02d','2024-%02d-%02d 14:%02d:%02d')%s\n",
			i+1, email, hash, name, role, token,
			rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60),
			rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60),
			sep))
	}

	sb.WriteString(`UNLOCK TABLES;

--
-- Table structure for table ` + "`sessions`" + `
--

DROP TABLE IF EXISTS ` + "`sessions`" + `;
CREATE TABLE ` + "`sessions`" + ` (
  ` + "`id`" + ` varchar(128) NOT NULL,
  ` + "`user_id`" + ` int DEFAULT NULL,
  ` + "`ip_address`" + ` varchar(45) DEFAULT NULL,
  ` + "`user_agent`" + ` text,
  ` + "`payload`" + ` longtext NOT NULL,
  ` + "`last_activity`" + ` int NOT NULL,
  PRIMARY KEY (` + "`id`" + `),
  KEY ` + "`idx_user_id`" + ` (` + "`user_id`" + `)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table structure for table ` + "`api_keys`" + `
--

DROP TABLE IF EXISTS ` + "`api_keys`" + `;
CREATE TABLE ` + "`api_keys`" + ` (
  ` + "`id`" + ` int NOT NULL AUTO_INCREMENT,
  ` + "`user_id`" + ` int NOT NULL,
  ` + "`key_hash`" + ` varchar(255) NOT NULL,
  ` + "`prefix`" + ` varchar(8) NOT NULL,
  ` + "`name`" + ` varchar(255) DEFAULT NULL,
  ` + "`last_used_at`" + ` datetime DEFAULT NULL,
  ` + "`created_at`" + ` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (` + "`id`" + `),
  KEY ` + "`idx_prefix`" + ` (` + "`prefix`" + `)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;

-- Dump completed
`)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
	return http.StatusOK
}

func (l *LureGenerator) serveBackupArchive(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=backup.tar.gz")

	// Write bytes that look like archive headers but are really structured junk.
	// tar.gz files start with gzip magic bytes, then tar header blocks.
	buf := make([]byte, 2058)
	// Gzip magic number
	buf[0] = 0x1f
	buf[1] = 0x8b
	buf[2] = 0x08 // deflate
	buf[3] = 0x00 // flags
	// Fake timestamp bytes
	for i := 4; i < 8; i++ {
		buf[i] = byte(rng.Intn(256))
	}
	buf[8] = 0x02 // max compression
	buf[9] = 0xff // OS unknown
	// Fill remainder with random data that a scanner might try to decompress
	for i := 10; i < len(buf); i++ {
		buf[i] = byte(rng.Intn(256))
	}

	w.WriteHeader(http.StatusOK)
	w.Write(buf)
	return http.StatusOK
}

func (l *LureGenerator) serveLoginPage(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	csrfToken := fakeHex(rng, 32)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In - GlitchCorp</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .login-wrapper { width: 100%%; max-width: 420px; }
    .brand { text-align: center; margin-bottom: 24px; }
    .brand h1 { font-size: 28px; color: #2c3e50; font-weight: 300; }
    .brand p { color: #7f8c8d; font-size: 14px; }
    .card { background: #fff; border-radius: 6px; padding: 32px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
    .form-group { margin-bottom: 18px; }
    .form-group label { display: block; font-size: 13px; color: #555; margin-bottom: 6px; font-weight: 500; }
    .form-group input[type="text"], .form-group input[type="password"], .form-group input[type="email"] {
      width: 100%%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; transition: border 0.2s;
    }
    .form-group input:focus { outline: none; border-color: #3498db; }
    .remember-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; font-size: 13px; }
    .remember-row label { color: #666; cursor: pointer; }
    .remember-row a { color: #3498db; text-decoration: none; }
    .remember-row a:hover { text-decoration: underline; }
    .btn-login { width: 100%%; padding: 11px; border: none; border-radius: 4px; background: #3498db; color: #fff; font-size: 15px; cursor: pointer; }
    .btn-login:hover { background: #2980b9; }
    .divider { text-align: center; margin: 18px 0; color: #bbb; font-size: 12px; }
    .sso-btn { width: 100%%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; background: #fff; color: #555; font-size: 14px; cursor: pointer; margin-bottom: 8px; }
    .sso-btn:hover { background: #f9f9f9; }
    .footer-links { text-align: center; margin-top: 20px; font-size: 12px; color: #999; }
    .footer-links a { color: #3498db; text-decoration: none; }
  </style>
</head>
<body>
  <div class="login-wrapper">
    <div class="brand">
      <h1>GlitchCorp</h1>
      <p>Enterprise Platform</p>
    </div>
    <div class="card">
      <form method="POST" action="%s">
        <input type="hidden" name="_token" value="%s">
        <div class="form-group">
          <label for="email">Email Address</label>
          <input type="email" id="email" name="email" placeholder="you@company.com" required>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="Enter your password" required>
        </div>
        <div class="remember-row">
          <label><input type="checkbox" name="remember" value="1"> Remember me</label>
          <a href="/auth/forgot-password">Forgot password?</a>
        </div>
        <button type="submit" class="btn-login">Sign In</button>
      </form>
      <div class="divider">or continue with</div>
      <button class="sso-btn" onclick="window.location='/auth/sso/saml'">Single Sign-On (SSO)</button>
      <button class="sso-btn" onclick="window.location='/auth/sso/google'">Sign in with Google</button>
    </div>
    <div class="footer-links">
      <p>Don't have an account? <a href="/auth/register">Request access</a></p>
      <p style="margin-top:8px"><a href="/terms">Terms</a> | <a href="/privacy">Privacy</a> | <a href="/support">Support</a></p>
    </div>
  </div>
</body>
</html>`, r.URL.Path, csrfToken)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (l *LureGenerator) serveAPIKey(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "application/json")

	content := fmt.Sprintf(`{
  "api_key": "sk_live_%s",
  "secret_key": "sk_secret_%s",
  "client_id": "app_%s",
  "client_secret": "%s",
  "webhook_secret": "whsec_%s",
  "publishable_key": "pk_live_%s",
  "access_token": "%s",
  "refresh_token": "%s",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write admin",
  "created_at": "2024-%02d-%02dT%02d:%02d:00Z",
  "environment": "production",
  "organization_id": "org_%s"
}`, fakeBase64(rng, 32), fakeBase64(rng, 32),
		fakeHex(rng, 12), fakeBase64(rng, 40),
		fakeBase64(rng, 24), fakeBase64(rng, 24),
		fakeToken(rng, "glitchcorp_", 48), fakeToken(rng, "grt_", 48),
		rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60),
		fakeHex(rng, 12))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveDebugInfo(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	path := strings.ToLower(r.URL.Path)

	switch {
	case strings.Contains(path, "actuator"):
		return l.serveActuator(w, rng)
	case strings.Contains(path, "pprof"):
		return l.servePprof(w, rng)
	default:
		return l.serveServerStatus(w, rng)
	}
}

func (l *LureGenerator) serveActuator(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "application/json")

	uptime := rng.Intn(864000) + 3600
	heapUsed := rng.Intn(512) + 64
	heapMax := heapUsed + rng.Intn(512) + 256
	threads := rng.Intn(200) + 20
	cpuLoad := float64(rng.Intn(80)+5) / 100.0

	content := fmt.Sprintf(`{
  "status": "UP",
  "components": {
    "db": {
      "status": "UP",
      "details": {
        "database": "PostgreSQL",
        "validationQuery": "isValid()",
        "host": "db-prod-01.glitchcorp.internal",
        "port": 5432
      }
    },
    "redis": {
      "status": "UP",
      "details": {
        "version": "7.0.11",
        "host": "cache-prod-01.glitchcorp.internal",
        "port": 6379
      }
    },
    "diskSpace": {
      "status": "UP",
      "details": {
        "total": 107374182400,
        "free": %d,
        "threshold": 10485760
      }
    }
  },
  "env": {
    "activeProfiles": ["production"],
    "propertySources": [
      {
        "name": "systemEnvironment",
        "properties": {
          "DATABASE_URL": {"value": "postgres://glitch_app:%s@db-prod-01.glitchcorp.internal:5432/production"},
          "REDIS_URL": {"value": "redis://:%s@cache-prod-01.glitchcorp.internal:6379"},
          "AWS_ACCESS_KEY_ID": {"value": "AKIA%s"},
          "AWS_SECRET_ACCESS_KEY": {"value": "******"},
          "SPRING_PROFILES_ACTIVE": {"value": "production"},
          "SERVER_PORT": {"value": "8080"},
          "JAVA_OPTS": {"value": "-Xmx%dm -Xms%dm"}
        }
      }
    ]
  },
  "metrics": {
    "jvm.memory.used": %d,
    "jvm.memory.max": %d,
    "jvm.threads.live": %d,
    "system.cpu.usage": %.4f,
    "process.uptime": %d,
    "http.server.requests.count": %d,
    "http.server.requests.error.count": %d
  },
  "beans": {
    "dataSource": {"type": "com.zaxxer.hikari.HikariDataSource", "scope": "singleton"},
    "redisTemplate": {"type": "org.springframework.data.redis.core.RedisTemplate", "scope": "singleton"},
    "entityManagerFactory": {"type": "org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean", "scope": "singleton"}
  }
}`, int64(rng.Intn(50)+10)*1073741824,
		fakeToken(rng, "", 12), fakeToken(rng, "", 16),
		fakeBase64(rng, 16),
		heapMax, heapUsed/2,
		heapUsed*1048576, heapMax*1048576,
		threads, cpuLoad, uptime,
		rng.Intn(1000000)+10000, rng.Intn(5000)+100)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) servePprof(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	numGoroutines := rng.Intn(200) + 20
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("goroutine profile: total %d\n\n", numGoroutines))

	stacks := []string{
		`goroutine %d [IO wait, %d minutes]:
internal/poll.runtime_pollWait(0x%s, 0x72)
	runtime/netpoll.go:343 +0x85
internal/poll.(*pollDesc).waitRead(...)
	internal/poll/fd_poll_runtime.go:89
internal/poll.(*FD).Read(0xc000%s, {0xc000%s, 0x1000, 0x1000})
	internal/poll/fd_unix.go:164 +0x27a
net.(*netFD).Read(0xc000%s, {0xc000%s, 0x1000, 0x1000})
	net/fd_posix.go:55 +0x29
net.(*conn).Read(0xc000%s, {0xc000%s, 0x1000, 0x1000})
	net/net.go:179 +0x45`,
		`goroutine %d [select, %d minutes]:
net/http.(*persistConn).readLoop(0xc000%s)
	net/http/transport.go:2205 +0xb5c
created by net/http.(*Transport).dialConnFor in goroutine 1
	net/http/transport.go:1782 +0x1ce`,
		`goroutine %d [chan receive, %d minutes]:
database/sql.(*DB).connectionOpener(0xc000%s, {0x%s, 0xc000%s})
	database/sql/sql.go:1218 +0x5e
created by database/sql.OpenDB in goroutine 1
	database/sql/sql.go:791 +0x188`,
	}

	for i := 0; i < numGoroutines && i < 15; i++ {
		tmpl := stacks[rng.Intn(len(stacks))]
		goroutineID := rng.Intn(10000) + 1
		minutes := rng.Intn(120) + 1
		// Fill all the format placeholders
		line := tmpl
		line = strings.Replace(line, "%d", fmt.Sprintf("%d", goroutineID), 1)
		line = strings.Replace(line, "%d", fmt.Sprintf("%d", minutes), 1)
		for strings.Contains(line, "%s") {
			line = strings.Replace(line, "%s", fakeHex(rng, 6), 1)
		}
		sb.WriteString(line)
		sb.WriteString("\n\n")
	}

	sb.WriteString("# runtime.MemStats\n")
	sb.WriteString(fmt.Sprintf("# Alloc = %d\n", rng.Intn(500000000)+10000000))
	sb.WriteString(fmt.Sprintf("# TotalAlloc = %d\n", rng.Intn(5000000000)+100000000))
	sb.WriteString(fmt.Sprintf("# Sys = %d\n", rng.Intn(1000000000)+50000000))
	sb.WriteString(fmt.Sprintf("# NumGC = %d\n", rng.Intn(50000)+100))
	sb.WriteString(fmt.Sprintf("# NumGoroutine = %d\n", numGoroutines))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
	return http.StatusOK
}

func (l *LureGenerator) serveServerStatus(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	uptime := fmt.Sprintf("%d days %d hours %d minutes", rng.Intn(365)+1, rng.Intn(24), rng.Intn(60))
	totalAccesses := rng.Intn(10000000) + 100000
	totalTraffic := rng.Intn(500) + 10
	busyWorkers := rng.Intn(50) + 5
	idleWorkers := rng.Intn(200) + 50

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Apache Status</title></head>
<body><h1>Apache Server Status for web-prod-01.glitchcorp.internal (via 10.0.1.%d)</h1>
<dl>
<dt>Server Version: Apache/2.4.57 (Ubuntu) OpenSSL/3.0.10</dt>
<dt>Server MPM: event</dt>
<dt>Server Built: 2024-04-01T00:00:00</dt>
</dl>
<dl>
<dt>Current Time: 2024-06-15 14:32:01</dt>
<dt>Server uptime: %s</dt>
<dt>Server load: %.2f %.2f %.2f</dt>
<dt>Total accesses: %d - Total Traffic: %d GB</dt>
<dt>CPU Usage: u%.2f s%.2f cu0 cs0 - %.4f%%%% CPU load</dt>
<dt>%.1f requests/sec - %.2f kB/request - %.2f MB/second</dt>
<dt>%d requests currently being processed, %d idle workers</dt>
</dl>
<pre>`, rng.Intn(254)+1,
		uptime,
		float64(rng.Intn(300)+10)/100.0, float64(rng.Intn(250)+10)/100.0, float64(rng.Intn(200)+10)/100.0,
		totalAccesses, totalTraffic,
		float64(rng.Intn(1000))/100.0, float64(rng.Intn(500))/100.0, float64(rng.Intn(10000))/10000.0,
		float64(totalAccesses)/86400.0, float64(rng.Intn(50)+5), float64(totalTraffic*1024)/86400.0,
		busyWorkers, idleWorkers))

	// Scoreboard
	scoreChars := []byte("_SRWKDCLGI.")
	for i := 0; i < busyWorkers+idleWorkers; i++ {
		if i < busyWorkers {
			sb.WriteByte(scoreChars[rng.Intn(len(scoreChars)-1)])
		} else {
			sb.WriteByte('_')
		}
	}

	sb.WriteString(`</pre>
<p>Scoreboard Key:<br>
"_" Waiting for Connection, "S" Starting up, "R" Reading Request,
"W" Sending Reply, "K" Keepalive (read), "D" DNS Lookup,
"C" Closing connection, "L" Logging, "G" Gracefully finishing,
"I" Idle cleanup of worker, "." Open slot with no current process</p>
</body></html>`)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
	return http.StatusOK
}

func (l *LureGenerator) serveGitExposure(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/plain")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/config") || strings.HasSuffix(path, "/.git/config"):
		return l.serveGitConfig(w, rng)
	case strings.HasSuffix(path, "/HEAD") || strings.HasSuffix(path, "/.git/HEAD"):
		return l.serveGitHead(w, rng)
	case strings.Contains(path, "/logs/"):
		return l.serveGitReflog(w, rng)
	default:
		return l.serveGitConfig(w, rng)
	}
}

func (l *LureGenerator) serveGitConfig(w http.ResponseWriter, rng *rand.Rand) int {
	orgs := []string{"glitchcorp", "glitch-internal", "acmecorp-dev", "glitchplatform"}
	repos := []string{"web-app", "api-server", "platform-core", "admin-portal", "infrastructure", "deployment-scripts"}
	org := orgs[rng.Intn(len(orgs))]
	repo := repos[rng.Intn(len(repos))]

	content := fmt.Sprintf(`[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true

[remote "origin"]
	url = git@github.com:%s/%s.git
	fetch = +refs/heads/*:refs/remotes/origin/*

[branch "main"]
	remote = origin
	merge = refs/heads/main

[branch "production"]
	remote = origin
	merge = refs/heads/production

[user]
	name = deploy-bot
	email = deploy@%s.com
`, org, repo, org)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveGitHead(w http.ResponseWriter, rng *rand.Rand) int {
	branches := []string{"main", "master", "production", "develop", "staging"}
	branch := branches[rng.Intn(len(branches))]

	content := fmt.Sprintf("ref: refs/heads/%s\n", branch)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveGitReflog(w http.ResponseWriter, rng *rand.Rand) int {
	authors := []string{"deploy-bot", "john.smith", "jane.doe", "ci-runner", "admin"}
	actions := []string{
		"commit: Update production config",
		"commit: Fix database connection pooling",
		"commit: Add API rate limiting",
		"commit: Merge branch 'feature/auth-overhaul'",
		"commit: Update dependencies",
		"commit: Fix XSS vulnerability in admin panel",
		"commit: Add Redis caching layer",
		"commit: Update SSL certificates",
		"pull: Fast-forward",
		"checkout: moving from develop to main",
		"merge: Merge branch 'hotfix/security-patch'",
		"commit: Remove hardcoded credentials",
		"commit: Add monitoring endpoints",
	}

	var sb strings.Builder
	numEntries := rng.Intn(12) + 5
	for i := 0; i < numEntries; i++ {
		oldHash := fakeHex(rng, 20)
		newHash := fakeHex(rng, 20)
		author := authors[rng.Intn(len(authors))]
		action := actions[rng.Intn(len(actions))]
		timestamp := 1718000000 - rng.Intn(2592000) + i*3600

		sb.WriteString(fmt.Sprintf("%s %s %s <%s@glitchcorp.com> %d +0000\t%s\n",
			oldHash, newHash, author, author, timestamp, action))
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
	return http.StatusOK
}

func (l *LureGenerator) serveEnvFile(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/plain")

	content := fmt.Sprintf(`DATABASE_URL=postgres://admin:%s@db.internal:5432/production
DATABASE_REPLICA_URL=postgres://readonly:%s@db-replica.internal:5432/production
REDIS_URL=redis://:%s@cache.internal:6379
REDIS_CLUSTER_URL=redis://:%s@cache-cluster.internal:6380

SECRET_KEY=%s
ENCRYPTION_KEY=%s
JWT_SECRET=%s

STRIPE_SECRET_KEY=sk_live_%s
STRIPE_WEBHOOK_SECRET=whsec_%s
STRIPE_PUBLISHABLE_KEY=pk_live_%s

SENDGRID_API_KEY=SG.%s.%s
MAILGUN_API_KEY=key-%s

AWS_ACCESS_KEY_ID=AKIA%s
AWS_SECRET_ACCESS_KEY=%s
AWS_S3_BUCKET=glitchcorp-prod-assets
AWS_REGION=us-east-1

TWILIO_ACCOUNT_SID=AC%s
TWILIO_AUTH_TOKEN=%s

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T%s/B%s/%s
SLACK_BOT_TOKEN=xoxb-%s

SENTRY_DSN=https://%s@o%d.ingest.sentry.io/%d

GITHUB_CLIENT_ID=%s
GITHUB_CLIENT_SECRET=%s

GOOGLE_OAUTH_CLIENT_ID=%s.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-%s

NEWRELIC_LICENSE_KEY=%s
DATADOG_API_KEY=%s

SESSION_SECRET=%s
COOKIE_SIGNING_KEY=%s
`,
		fakeToken(rng, "", 16), fakeToken(rng, "", 12),
		fakeToken(rng, "", 16), fakeToken(rng, "", 16),
		fakeHex(rng, 16), fakeHex(rng, 32), fakeHex(rng, 32),
		fakeBase64(rng, 24), fakeBase64(rng, 24), fakeBase64(rng, 24),
		fakeBase64(rng, 22), fakeBase64(rng, 22), fakeHex(rng, 16),
		fakeBase64(rng, 16), fakeBase64(rng, 40),
		fakeHex(rng, 16), fakeHex(rng, 16),
		fakeBase64(rng, 9), fakeBase64(rng, 9), fakeBase64(rng, 24),
		fakeBase64(rng, 32),
		fakeHex(rng, 16), rng.Intn(999999)+100000, rng.Intn(999999)+100000,
		fakeHex(rng, 10), fakeHex(rng, 20),
		fmt.Sprintf("%d-%s", rng.Intn(999999999)+100000000, fakeBase64(rng, 20)),
		fakeBase64(rng, 24),
		fakeHex(rng, 20), fakeHex(rng, 16),
		fakeHex(rng, 32), fakeHex(rng, 32))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveDBDump(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "application/sql")
	w.Header().Set("Content-Disposition", "attachment; filename=dump.sql")

	dbNames := []string{"production_db", "glitch_main", "customer_data", "app_production"}
	dbName := dbNames[rng.Intn(len(dbNames))]

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`-- MySQL dump 10.13  Distrib 8.0.33, for Linux (x86_64)
--
-- Host: db-prod-01.glitchcorp.internal    Database: %s
-- Server version	8.0.33
-- ------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;

-- --------------------------------------------------------
-- Table structure for table `+"`users`"+`
-- --------------------------------------------------------

DROP TABLE IF EXISTS `+"`users`"+`;
CREATE TABLE `+"`users`"+` (
  `+"`id`"+` int NOT NULL AUTO_INCREMENT,
  `+"`email`"+` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `+"`password_hash`"+` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `+"`full_name`"+` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `+"`phone`"+` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `+"`role`"+` enum('superadmin','admin','manager','user') COLLATE utf8mb4_unicode_ci DEFAULT 'user',
  `+"`is_active`"+` tinyint(1) DEFAULT '1',
  `+"`last_login`"+` datetime DEFAULT NULL,
  `+"`created_at`"+` datetime DEFAULT CURRENT_TIMESTAMP,
  `+"`updated_at`"+` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`+"`id`"+`),
  UNIQUE KEY `+"`idx_users_email`"+` (`+"`email`"+`)
) ENGINE=InnoDB AUTO_INCREMENT=256 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Dumping data for table `+"`users`"+`
-- --------------------------------------------------------

LOCK TABLES `+"`users`"+` WRITE;
INSERT INTO `+"`users`"+` VALUES
`, dbName))

	emails := []string{
		"admin@glitchcorp.com",
		"john.smith@glitchcorp.com",
		"jane.doe@glitchcorp.com",
		"robert.wilson@glitchcorp.com",
		"alice.chen@glitchcorp.com",
		"carlos.garcia@glitchcorp.com",
		"sarah.jones@glitchcorp.com",
		"michael.taylor@glitchcorp.com",
		"emily.brown@glitchcorp.com",
		"david.kim@glitchcorp.com",
	}
	names := []string{
		"System Administrator",
		"John Smith",
		"Jane Doe",
		"Robert Wilson",
		"Alice Chen",
		"Carlos Garcia",
		"Sarah Jones",
		"Michael Taylor",
		"Emily Brown",
		"David Kim",
	}
	phones := []string{
		"+1-555-0100",
		"+1-555-0101",
		"+1-555-0102",
		"+1-555-0103",
		"+1-555-0104",
		"+1-555-0105",
		"+1-555-0106",
		"+1-555-0107",
		"+1-555-0108",
		"+1-555-0109",
	}
	roles := []string{"superadmin", "admin", "manager", "user", "user", "user", "manager", "user", "user", "admin"}

	numUsers := rng.Intn(4) + 7
	if numUsers > len(emails) {
		numUsers = len(emails)
	}

	for i := 0; i < numUsers; i++ {
		hash := fakeBcrypt(rng)
		active := 1
		if rng.Intn(10) == 0 {
			active = 0
		}
		sep := ","
		if i == numUsers-1 {
			sep = ";"
		}
		sb.WriteString(fmt.Sprintf("  (%d,'%s','%s','%s','%s','%s',%d,'2024-%02d-%02d %02d:%02d:%02d','2024-%02d-%02d %02d:%02d:%02d','2024-%02d-%02d %02d:%02d:%02d')%s\n",
			i+1, emails[i], hash, names[i], phones[i], roles[i], active,
			rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60),
			rng.Intn(6)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60),
			rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60),
			sep))
	}

	sb.WriteString(`UNLOCK TABLES;

-- --------------------------------------------------------
-- Table structure for table ` + "`payments`" + `
-- --------------------------------------------------------

DROP TABLE IF EXISTS ` + "`payments`" + `;
CREATE TABLE ` + "`payments`" + ` (
  ` + "`id`" + ` int NOT NULL AUTO_INCREMENT,
  ` + "`user_id`" + ` int NOT NULL,
  ` + "`amount`" + ` decimal(10,2) NOT NULL,
  ` + "`currency`" + ` char(3) COLLATE utf8mb4_unicode_ci DEFAULT 'USD',
  ` + "`stripe_charge_id`" + ` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  ` + "`status`" + ` enum('pending','completed','failed','refunded') COLLATE utf8mb4_unicode_ci DEFAULT 'pending',
  ` + "`created_at`" + ` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (` + "`id`" + `),
  KEY ` + "`idx_payments_user_id`" + ` (` + "`user_id`" + `),
  CONSTRAINT ` + "`fk_payments_user`" + ` FOREIGN KEY (` + "`user_id`" + `) REFERENCES ` + "`users`" + ` (` + "`id`" + `)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table ` + "`oauth_tokens`" + `
-- --------------------------------------------------------

DROP TABLE IF EXISTS ` + "`oauth_tokens`" + `;
CREATE TABLE ` + "`oauth_tokens`" + ` (
  ` + "`id`" + ` int NOT NULL AUTO_INCREMENT,
  ` + "`user_id`" + ` int NOT NULL,
  ` + "`access_token`" + ` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  ` + "`refresh_token`" + ` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  ` + "`expires_at`" + ` datetime NOT NULL,
  ` + "`created_at`" + ` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (` + "`id`" + `),
  KEY ` + "`idx_tokens_user_id`" + ` (` + "`user_id`" + `)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

`)

	// Add some oauth token data
	sb.WriteString("LOCK TABLES `oauth_tokens` WRITE;\n")
	sb.WriteString("INSERT INTO `oauth_tokens` VALUES\n")
	numTokens := rng.Intn(5) + 3
	for i := 0; i < numTokens; i++ {
		sep := ","
		if i == numTokens-1 {
			sep = ";"
		}
		sb.WriteString(fmt.Sprintf("  (%d,%d,'%s','%s','2025-%02d-%02d %02d:%02d:%02d','2024-%02d-%02d %02d:%02d:%02d')%s\n",
			i+1, rng.Intn(numUsers)+1,
			fakeToken(rng, "glc_", 64), fakeToken(rng, "glr_", 64),
			rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60),
			rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60),
			sep))
	}
	sb.WriteString("UNLOCK TABLES;\n\n")

	sb.WriteString(`/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;

-- Dump completed on 2024-06-15 03:00:01
`)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
	return http.StatusOK
}

func (l *LureGenerator) serveShellAccess(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/plain")

	kernelVersions := []string{
		"5.4.0-150-generic",
		"5.15.0-76-generic",
		"6.1.0-21-generic",
		"5.10.0-28-generic",
	}
	hostnames := []string{
		"web-prod-01",
		"app-server-03",
		"api-gateway-02",
		"backend-prod-01",
	}

	hostname := hostnames[rng.Intn(len(hostnames))]
	kernel := kernelVersions[rng.Intn(len(kernelVersions))]

	uptimeDays := rng.Intn(365) + 1
	uptimeHours := rng.Intn(24)
	uptimeMinutes := rng.Intn(60)
	numUsers := rng.Intn(3) + 1
	load1 := float64(rng.Intn(300)+10) / 100.0
	load5 := float64(rng.Intn(250)+10) / 100.0
	load15 := float64(rng.Intn(200)+10) / 100.0

	memTotal := (rng.Intn(32) + 4) * 1024 * 1024 // kB
	memUsed := memTotal * (rng.Intn(40) + 50) / 100
	memFree := memTotal - memUsed
	memAvail := memFree + rng.Intn(memFree/4+1)
	buffers := rng.Intn(500000) + 50000
	cached := rng.Intn(2000000) + 200000
	swapTotal := memTotal / 2
	swapUsed := rng.Intn(swapTotal/4 + 1)
	swapFree := swapTotal - swapUsed

	diskTotal := rng.Intn(500) + 50
	diskUsed := rng.Intn(diskTotal*60/100) + diskTotal*20/100
	diskAvail := diskTotal - diskUsed
	diskPct := diskUsed * 100 / diskTotal
	shmTotal := rng.Intn(16) + 2
	shmUsed := rng.Intn(500) + 10

	content := fmt.Sprintf(`uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux %s %s #167-Ubuntu SMP Tue Jun 11 20:05:23 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

 %02d:%02d:%02d up %d days, %d:%02d, %d users, load average: %.2f, %.2f, %.2f

USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
www-data pts/0    10.0.1.%d        09:15    0.00s  0.12s  0.00s /bin/bash
root     pts/1    10.0.1.1         08:30    1:32   0.08s  0.02s -bash

HOSTNAME=%s
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/var/www
SHELL=/bin/bash
PWD=/var/www/html
SERVER_SOFTWARE=Apache/2.4.57
DOCUMENT_ROOT=/var/www/html

total %d
drwxr-xr-x  8 www-data www-data  4096 Jun 10 14:22 .
drwxr-xr-x  3 root     root      4096 Jan 15 09:00 ..
-rw-r--r--  1 www-data www-data   220 Jan 15 09:00 .bash_logout
-rw-r--r--  1 www-data www-data  3771 Jan 15 09:00 .bashrc
drwx------  2 www-data www-data  4096 Feb 10 11:30 .cache
drwxr-xr-x  2 www-data www-data  4096 Jun 10 14:22 .ssh
-rw-------  1 www-data www-data  1679 Mar 22 08:15 .ssh/id_rsa
-rw-r--r--  1 www-data www-data   400 Mar 22 08:15 .ssh/id_rsa.pub
-rw-r--r--  1 www-data www-data   888 Mar 22 08:15 .ssh/known_hosts
drwxr-xr-x  6 www-data www-data  4096 Jun 10 14:20 html
-rw-r--r--  1 www-data www-data   741 Jun  5 16:33 .env
-rw-r--r--  1 www-data www-data  2048 Jun  8 09:12 config.php
drwxr-xr-x  2 www-data www-data  4096 Jun  1 11:00 backups

MemTotal:       %d kB
MemFree:        %d kB
MemAvailable:   %d kB
Buffers:        %d kB
Cached:         %d kB
SwapTotal:      %d kB
SwapFree:       %d kB

Filesystem      Size  Used Avail Use%%%% Mounted on
/dev/sda1       %dG   %dG   %dG  %d%%%% /
tmpfs           %dG   %dM   %dG   1%%%% /dev/shm
`, hostname, kernel,
		rng.Intn(24), rng.Intn(60), rng.Intn(60),
		uptimeDays, uptimeHours, uptimeMinutes, numUsers,
		load1, load5, load15,
		rng.Intn(254)+1,
		hostname,
		rng.Intn(100)+40,
		memTotal, memFree, memAvail,
		buffers, cached,
		swapTotal, swapFree,
		diskTotal, diskUsed, diskAvail, diskPct,
		shmTotal, shmUsed, shmTotal)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
	return http.StatusOK
}

func (l *LureGenerator) serveWordPress(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	path := strings.ToLower(r.URL.Path)

	switch {
	case strings.Contains(path, "xmlrpc"):
		return l.serveWPXMLRPC(w, rng)
	case strings.Contains(path, "wp-admin"):
		return l.serveWPAdminRedirect(w, r)
	default:
		return l.serveWPLogin(w, r, rng)
	}
}

func (l *LureGenerator) serveWPLogin(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	siteTitles := []string{"GlitchCorp Blog", "My WordPress Site", "Corporate News", "GlitchPress"}
	siteTitle := siteTitles[rng.Intn(len(siteTitles))]
	csrfToken := fakeHex(rng, 10)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en-US">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Log In &lsaquo; %s &#8212; WordPress</title>
  <meta name="robots" content="max-image-preview:large, noindex, noarchive">
  <style>
    html { background: #f0f0f1; }
    body { background: #f0f0f1; min-width: 0; color: #3c434a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; font-size: 13px; line-height: 1.4; }
    a { color: #2271b1; }
    #login { width: 320px; padding: 8%%%% 0 0; margin: auto; }
    #login h1 a { background-image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgNDAwIj48cGF0aCBmaWxsPSIjMDA3MzlkIiBkPSJNMTU4IDgxYy0xNCAxMC0yMCAyMi0yMCA0MnMxMSAzMSAyMCA0MmMtMTAgMTItMjAgMjItMjAgNDJzNiAzMiAyMCA0MmMtMTAgMTAtMjAgMjAtMjAgNDBzNiAzMiAyMCA0MiIvPjwvc3ZnPg==); display: block; width: 84px; height: 84px; margin: 0 auto 25px; background-size: 84px; text-indent: -9999px; }
    .login form { margin-top: 20px; margin-left: 0; padding: 26px 24px 34px; font-weight: 400; background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
    .login label { font-size: 14px; font-weight: 600; }
    .login input[type="text"], .login input[type="password"] { width: 100%%%%; padding: 3px 5px; margin: 2px 6px 16px 0; border: 1px solid #8c8f94; border-radius: 4px; font-size: 24px; line-height: 1.3; }
    .login .button-primary { float: right; padding: 3px 14px; min-height: 32px; background: #2271b1; border-color: #2271b1; color: #fff; border-radius: 3px; cursor: pointer; font-size: 13px; }
    .login .forgetmenot label { font-size: 12px; font-weight: 400; }
    #nav, #backtoblog { font-size: 13px; padding: 0 24px 0; }
    #nav a, #backtoblog a { color: #50575e; }
    .privacy-policy-page-link { text-align: center; margin-top: 16px; }
  </style>
</head>
<body class="login login-action-login wp-core-ui locale-en-us">
  <div id="login">
    <h1><a href="https://wordpress.org/">%s</a></h1>
    <form name="loginform" id="loginform" action="%s" method="post">
      <p>
        <label for="user_login">Username or Email Address</label>
        <input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required>
      </p>
      <p>
        <label for="user_pass">Password</label>
        <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password" required>
      </p>
      <p class="forgetmenot">
        <label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label>
      </p>
      <p class="submit">
        <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
        <input type="hidden" name="redirect_to" value="/wp-admin/">
        <input type="hidden" name="testcookie" value="1">
        <input type="hidden" name="_wpnonce" value="%s">
      </p>
    </form>
    <p id="nav">
      <a href="/wp-login.php?action=lostpassword">Lost your password?</a>
    </p>
    <p id="backtoblog">
      <a href="/">&larr; Go to %s</a>
    </p>
    <div class="privacy-policy-page-link">
      <a href="/privacy-policy/">Privacy Policy</a>
    </div>
  </div>
</body>
</html>`, siteTitle, siteTitle, r.URL.Path, csrfToken, siteTitle)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (l *LureGenerator) serveWPXMLRPC(w http.ResponseWriter, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/xml; charset=UTF-8")

	methods := []string{
		"system.multicall", "system.listMethods", "system.getCapabilities",
		"wp.getUsersBlogs", "wp.newPost", "wp.editPost", "wp.deletePost",
		"wp.getPost", "wp.getPosts", "wp.newTerm", "wp.editTerm",
		"wp.deleteTerm", "wp.getTerm", "wp.getTerms", "wp.getTaxonomy",
		"wp.getTaxonomies", "wp.getUser", "wp.getUsers", "wp.getProfile",
		"wp.editProfile", "wp.getPage", "wp.getPages", "wp.newPage",
		"wp.editPage", "wp.deletePage", "wp.getAuthors", "wp.getCategories",
		"wp.getTags", "wp.newCategory", "wp.deleteCategory",
		"wp.getCommentCount", "wp.getComment", "wp.getComments",
		"wp.newComment", "wp.editComment", "wp.deleteComment",
		"wp.getOptions", "wp.setOptions", "wp.getMediaItem",
		"wp.getMediaLibrary", "wp.uploadFile",
		"blogger.getUsersBlogs", "blogger.getUserInfo",
		"metaWeblog.newPost", "metaWeblog.editPost", "metaWeblog.getPost",
		"metaWeblog.getRecentPosts", "metaWeblog.getCategories",
		"metaWeblog.newMediaObject",
		"pingback.ping", "pingback.extensions.getPingbacks",
	}

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
`)
	for _, m := range methods {
		sb.WriteString(fmt.Sprintf("            <value><string>%s</string></value>\n", m))
	}
	sb.WriteString(`          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>`)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
	return http.StatusOK
}

func (l *LureGenerator) serveWPAdminRedirect(w http.ResponseWriter, r *http.Request) int {
	http.Redirect(w, r, "/wp-login.php?redirect_to="+r.URL.Path, http.StatusFound)
	return http.StatusFound
}

func (l *LureGenerator) servePhpMyAdmin(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	version := fmt.Sprintf("5.%d.%d", rng.Intn(3)+1, rng.Intn(5))
	csrfToken := fakeHex(rng, 32)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex,nofollow">
  <title>phpMyAdmin</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: sans-serif; background: #e7e9ed; }
    #page_content { width: 100%%; }
    .container { max-width: 500px; margin: 50px auto; }
    #logo { text-align: center; margin-bottom: 20px; }
    #logo h1 { font-size: 28px; color: #333; font-weight: 400; }
    #logo h1 span { color: #f89406; }
    #logo .version { font-size: 12px; color: #999; }
    .login-panel { background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 30px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    .login-panel h2 { font-size: 16px; color: #333; margin-bottom: 20px; font-weight: 400; border-bottom: 1px solid #eee; padding-bottom: 10px; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 13px; color: #555; margin-bottom: 4px; }
    .form-group input[type="text"], .form-group input[type="password"] { width: 100%%; padding: 8px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; }
    .form-group select { width: 100%%; padding: 8px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; background: #fff; }
    .btn-go { padding: 8px 20px; background: #f89406; border: 1px solid #e08305; border-radius: 3px; color: #fff; font-size: 14px; cursor: pointer; }
    .btn-go:hover { background: #e08305; }
    .server-info { font-size: 11px; color: #888; margin-top: 16px; text-align: center; }
  </style>
</head>
<body>
  <div id="page_content">
    <div class="container">
      <div id="logo">
        <h1>php<span>My</span>Admin</h1>
        <div class="version">Version %s</div>
      </div>
      <div class="login-panel">
        <h2>Log in</h2>
        <form method="post" action="%s" class="login">
          <input type="hidden" name="token" value="%s">
          <input type="hidden" name="set_session" value="%s">
          <div class="form-group">
            <label for="input_username">Username:</label>
            <input type="text" name="pma_username" id="input_username" value="" autofocus required>
          </div>
          <div class="form-group">
            <label for="input_password">Password:</label>
            <input type="password" name="pma_password" id="input_password" value="" required>
          </div>
          <div class="form-group">
            <label for="select_server">Server Choice:</label>
            <select name="server" id="select_server">
              <option value="1">db-prod-01.glitchcorp.internal</option>
              <option value="2">db-replica-01.glitchcorp.internal</option>
              <option value="3">db-staging-01.glitchcorp.internal</option>
            </select>
          </div>
          <button type="submit" class="btn-go" id="input_go">Go</button>
        </form>
        <div class="server-info">
          MySQL server: db-prod-01.glitchcorp.internal &mdash; Server version: 8.0.33-0ubuntu0.22.04.1
        </div>
      </div>
    </div>
  </div>
</body>
</html>`, version, r.URL.Path, csrfToken, fakeHex(rng, 16))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}
