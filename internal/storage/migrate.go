// Package storage provides PostgreSQL storage with insert-only versioning.
package storage

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migration represents a single SQL migration file.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Migrate applies all pending migrations to the database.
// It reads SQL files from the embedded migrations/ directory,
// checks schema_migrations for already-applied versions,
// and applies new migrations in order. Each migration runs
// in its own transaction.
func Migrate(ctx context.Context, db *sql.DB) error {
	// Ensure schema_migrations table exists (bootstrap).
	// This is idempotent — IF NOT EXISTS handles repeat calls.
	if err := ensureMigrationsTable(ctx, db); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	// Load all migration files from embedded FS.
	migrations, err := loadMigrations()
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}

	// Get already-applied versions.
	applied, err := getAppliedVersions(ctx, db)
	if err != nil {
		return fmt.Errorf("get applied versions: %w", err)
	}

	// Apply pending migrations in order.
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		log.Printf("[migrate] applying migration %03d: %s", m.Version, m.Name)
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("apply migration %03d (%s): %w", m.Version, m.Name, err)
		}
		log.Printf("[migrate] applied migration %03d: %s", m.Version, m.Name)
	}

	return nil
}

// ensureMigrationsTable creates the schema_migrations table if it doesn't exist.
// This bootstraps the migration system on a fresh database.
func ensureMigrationsTable(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INT             PRIMARY KEY,
			name        VARCHAR(255)    NOT NULL,
			applied_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

// loadMigrations reads all .sql files from the embedded migrations directory,
// parses their version numbers from the filename prefix, and returns them sorted.
func loadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	var migrations []Migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		version, err := parseVersion(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("parse version from %s: %w", entry.Name(), err)
		}

		data, err := migrationsFS.ReadFile(path.Join("migrations", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    entry.Name(),
			SQL:     string(data),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// parseVersion extracts the version number from a migration filename.
// Expected format: "001_description.sql" → 1
func parseVersion(filename string) (int, error) {
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid migration filename: %s (expected NNN_name.sql)", filename)
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid version prefix in %s: %w", filename, err)
	}
	return v, nil
}

// getAppliedVersions returns a set of already-applied migration versions.
func getAppliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// applyMigration runs a single migration inside a transaction.
// If the migration SQL already contains BEGIN/COMMIT, it strips them
// to avoid nested transaction errors.
func applyMigration(ctx context.Context, db *sql.DB, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — rollback on commit is a no-op

	// Strip BEGIN/COMMIT from migration SQL since we wrap in our own tx.
	sqlBody := stripTransactionStatements(m.SQL)

	if _, err := tx.ExecContext(ctx, sqlBody); err != nil {
		return fmt.Errorf("exec sql: %w", err)
	}

	// Record the migration (unless the SQL already did it via INSERT INTO schema_migrations).
	// We use ON CONFLICT to handle both cases safely.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO schema_migrations (version, name)
		VALUES ($1, $2)
		ON CONFLICT (version) DO NOTHING
	`, m.Version, m.Name); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}

	return tx.Commit()
}

// stripTransactionStatements removes standalone BEGIN; and COMMIT; statements
// from migration SQL so it can be wrapped in the runner's own transaction.
func stripTransactionStatements(sql string) string {
	lines := strings.Split(sql, "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.ToUpper(line))
		if trimmed == "BEGIN;" || trimmed == "COMMIT;" {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}
