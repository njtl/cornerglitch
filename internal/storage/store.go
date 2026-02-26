package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// DefaultDSN is the default PostgreSQL connection string.
const DefaultDSN = "postgres://glitch:glitch@localhost:5432/glitch?sslmode=disable"

// Store is the main storage interface for Glitch persistence.
// All writes are insert-only with versioning. Reads fetch the latest version.
type Store struct {
	db  *sql.DB
	mu  sync.RWMutex
	dsn string
}

// New creates a new Store and connects to PostgreSQL.
// It reads the connection string from GLITCH_DB_URL env var,
// falling back to DefaultDSN.
// On success, it runs pending migrations automatically.
func New(ctx context.Context) (*Store, error) {
	dsn := os.Getenv("GLITCH_DB_URL")
	if dsn == "" {
		dsn = DefaultDSN
	}
	return NewWithDSN(ctx, dsn)
}

// NewWithDSN creates a Store with an explicit DSN.
func NewWithDSN(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	// Verify connectivity
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	s := &Store{db: db, dsn: dsn}

	// Run migrations
	if err := Migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	log.Printf("[storage] connected to PostgreSQL, migrations applied")
	return s, nil
}

// DB returns the underlying *sql.DB for advanced queries.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Close closes the database connection pool.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// ---------------------------------------------------------------------------
// Config versioning — insert-only with version numbers
// ---------------------------------------------------------------------------

// SaveConfig inserts a new version of a config entity.
// The version number is auto-calculated as max(version)+1 for the entity.
func (s *Store) SaveConfig(ctx context.Context, entity string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal config data: %w", err)
	}

	var maxVersion int
	err = s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM config_versions WHERE entity = $1`,
		entity,
	).Scan(&maxVersion)
	if err != nil {
		return fmt.Errorf("get max version for %s: %w", entity, err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO config_versions (entity, version, data) VALUES ($1, $2, $3::jsonb)`,
		entity, maxVersion+1, jsonData,
	)
	if err != nil {
		return fmt.Errorf("insert config version for %s: %w", entity, err)
	}
	return nil
}

// LoadConfig loads the latest version of a config entity into dst.
// Returns false if no config exists for the entity.
func (s *Store) LoadConfig(ctx context.Context, entity string, dst interface{}) (bool, error) {
	var jsonData []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT data FROM config_current WHERE entity = $1
	`, entity).Scan(&jsonData)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query config for %s: %w", entity, err)
	}
	if err := json.Unmarshal(jsonData, dst); err != nil {
		return false, fmt.Errorf("unmarshal config for %s: %w", entity, err)
	}
	return true, nil
}

// LoadConfigVersion loads a specific version of a config entity.
func (s *Store) LoadConfigVersion(ctx context.Context, entity string, version int, dst interface{}) (bool, error) {
	var jsonData []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT data FROM config_versions
		WHERE entity = $1 AND version = $2
	`, entity, version).Scan(&jsonData)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query config %s v%d: %w", entity, version, err)
	}
	if err := json.Unmarshal(jsonData, dst); err != nil {
		return false, fmt.Errorf("unmarshal config %s v%d: %w", entity, version, err)
	}
	return true, nil
}

// ConfigVersion returns the latest version number for a config entity.
// Returns 0 if no versions exist.
func (s *Store) ConfigVersion(ctx context.Context, entity string) (int, error) {
	var version int
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 0) FROM config_versions WHERE entity = $1
	`, entity).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("query config version for %s: %w", entity, err)
	}
	return version, nil
}

// ListConfigHistory returns the version history for a config entity.
func (s *Store) ListConfigHistory(ctx context.Context, entity string, limit int) ([]ConfigHistoryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, version, created_at FROM config_versions
		WHERE entity = $1
		ORDER BY version DESC
		LIMIT $2
	`, entity, limit)
	if err != nil {
		return nil, fmt.Errorf("query config history for %s: %w", entity, err)
	}
	defer rows.Close()

	var entries []ConfigHistoryEntry
	for rows.Next() {
		var e ConfigHistoryEntry
		if err := rows.Scan(&e.ID, &e.Version, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Entity = entity
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ConfigHistoryEntry is a lightweight record of a config version.
type ConfigHistoryEntry struct {
	ID        int64     `json:"id"`
	Entity    string    `json:"entity"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Full config export/import — saves all entities as one snapshot
// ---------------------------------------------------------------------------

// SaveFullConfig saves a complete ConfigExport by writing each entity
// as a new version in config_versions.
func (s *Store) SaveFullConfig(ctx context.Context, export *FullConfigExport) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	entities := map[string]interface{}{
		"feature_flags":    export.Features,
		"admin_config":     export.Config,
		"vuln_config":      export.VulnConfig,
		"error_weights":    export.ErrorWeights,
		"page_type_weights": export.PageTypeWeights,
	}
	if export.Blocking != nil {
		entities["blocking"] = export.Blocking
	}

	for entity, data := range entities {
		if data == nil {
			continue
		}
		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", entity, err)
		}

		var maxVersion int
		err = tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(version), 0) FROM config_versions WHERE entity = $1`,
			entity,
		).Scan(&maxVersion)
		if err != nil {
			return fmt.Errorf("get max version for %s: %w", entity, err)
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO config_versions (entity, version, data) VALUES ($1, $2, $3::jsonb)`,
			entity, maxVersion+1, jsonData,
		)
		if err != nil {
			return fmt.Errorf("insert %s: %w", entity, err)
		}
	}

	return tx.Commit()
}

// LoadFullConfig loads the latest version of all config entities.
func (s *Store) LoadFullConfig(ctx context.Context) (*FullConfigExport, error) {
	export := &FullConfigExport{}

	rows, err := s.db.QueryContext(ctx, `
		SELECT entity, data FROM config_current
	`)
	if err != nil {
		return nil, fmt.Errorf("query config_current: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var entity string
		var jsonData []byte
		if err := rows.Scan(&entity, &jsonData); err != nil {
			return nil, err
		}

		switch entity {
		case "feature_flags":
			var v map[string]bool
			if err := json.Unmarshal(jsonData, &v); err != nil {
				return nil, fmt.Errorf("unmarshal feature_flags: %w", err)
			}
			export.Features = v
		case "admin_config":
			var v map[string]interface{}
			if err := json.Unmarshal(jsonData, &v); err != nil {
				return nil, fmt.Errorf("unmarshal admin_config: %w", err)
			}
			export.Config = v
		case "vuln_config":
			var v map[string]interface{}
			if err := json.Unmarshal(jsonData, &v); err != nil {
				return nil, fmt.Errorf("unmarshal vuln_config: %w", err)
			}
			export.VulnConfig = v
		case "error_weights":
			var v map[string]float64
			if err := json.Unmarshal(jsonData, &v); err != nil {
				return nil, fmt.Errorf("unmarshal error_weights: %w", err)
			}
			export.ErrorWeights = v
		case "page_type_weights":
			var v map[string]float64
			if err := json.Unmarshal(jsonData, &v); err != nil {
				return nil, fmt.Errorf("unmarshal page_type_weights: %w", err)
			}
			export.PageTypeWeights = v
		case "blocking":
			var v map[string]interface{}
			if err := json.Unmarshal(jsonData, &v); err != nil {
				return nil, fmt.Errorf("unmarshal blocking: %w", err)
			}
			export.Blocking = v
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Return nil if nothing was found (no DB config yet)
	if export.Features == nil && export.Config == nil {
		return nil, nil
	}

	return export, nil
}

// FullConfigExport mirrors dashboard.ConfigExport for storage.
// This avoids importing internal/dashboard from storage.
type FullConfigExport struct {
	Features        map[string]bool        `json:"features"`
	Config          map[string]interface{} `json:"config"`
	VulnConfig      map[string]interface{} `json:"vuln_config"`
	ErrorWeights    map[string]float64     `json:"error_weights,omitempty"`
	PageTypeWeights map[string]float64     `json:"page_type_weights,omitempty"`
	Blocking        map[string]interface{} `json:"blocking,omitempty"`
}
