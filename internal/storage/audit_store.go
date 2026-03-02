package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/glitchWebServer/internal/audit"
)

// SaveAuditEntry inserts a single audit log entry.
func (s *Store) SaveAuditEntry(ctx context.Context, entry *audit.Entry) error {
	oldVal, err := marshalNullableJSON(entry.OldValue)
	if err != nil {
		return fmt.Errorf("marshal old_value: %w", err)
	}
	newVal, err := marshalNullableJSON(entry.NewValue)
	if err != nil {
		return fmt.Errorf("marshal new_value: %w", err)
	}
	details, err := marshalNullableJSON(entry.Details)
	if err != nil {
		return fmt.Errorf("marshal details: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_log (timestamp, actor, action, resource, old_value, new_value, details, client_ip, status)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9)
	`, entry.Timestamp, entry.Actor, entry.Action, entry.Resource,
		oldVal, newVal, details,
		nullString(entry.ClientIP), entry.Status)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// SaveAuditBatch inserts multiple audit log entries in a single transaction.
// This satisfies the audit.AuditStore interface (called from the async dbWriter).
func (s *Store) SaveAuditBatch(entries []audit.Entry) error {
	if len(entries) == 0 {
		return nil
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO audit_log (timestamp, actor, action, resource, old_value, new_value, details, client_ip, status)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9)
	`)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for i := range entries {
		e := &entries[i]
		oldVal, err := marshalNullableJSON(e.OldValue)
		if err != nil {
			return fmt.Errorf("marshal old_value: %w", err)
		}
		newVal, err := marshalNullableJSON(e.NewValue)
		if err != nil {
			return fmt.Errorf("marshal new_value: %w", err)
		}
		details, err := marshalNullableJSON(e.Details)
		if err != nil {
			return fmt.Errorf("marshal details: %w", err)
		}

		_, err = stmt.ExecContext(ctx, e.Timestamp, e.Actor, e.Action, e.Resource,
			oldVal, newVal, details,
			nullString(e.ClientIP), e.Status)
		if err != nil {
			return fmt.Errorf("insert audit entry: %w", err)
		}
	}

	return tx.Commit()
}

// QueryAuditLog queries the audit_log table with filtering and pagination.
// Returns matching entries, total count, and any error.
func (s *Store) QueryAuditLog(ctx context.Context, opts audit.QueryOpts) ([]audit.Entry, int, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 200 {
		opts.Limit = 200
	}

	// Build WHERE clause dynamically based on filters.
	var conditions []string
	var args []interface{}
	argIdx := 1

	if opts.Actor != "" {
		conditions = append(conditions, fmt.Sprintf("actor = $%d", argIdx))
		args = append(args, opts.Actor)
		argIdx++
	}
	if opts.Action != "" {
		// Prefix match: "config" matches "config.change", "config.import", etc.
		conditions = append(conditions, fmt.Sprintf("action LIKE $%d", argIdx))
		args = append(args, opts.Action+"%")
		argIdx++
	}
	if opts.Resource != "" {
		// Prefix match on resource
		conditions = append(conditions, fmt.Sprintf("resource LIKE $%d", argIdx))
		args = append(args, opts.Resource+"%")
		argIdx++
	}
	if opts.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, opts.Status)
		argIdx++
	}
	if opts.From != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, *opts.From)
		argIdx++
	}
	if opts.To != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, *opts.To)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count for pagination.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_log %s", whereClause)
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit entries: %w", err)
	}

	// Fetch the page of entries.
	dataQuery := fmt.Sprintf(`
		SELECT id, timestamp, actor, action, resource,
		       old_value, new_value, details, COALESCE(client_ip, ''), status
		FROM audit_log
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	args = append(args, opts.Limit, opts.Offset)

	rows, err := s.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var entries []audit.Entry
	for rows.Next() {
		var e audit.Entry
		var oldVal, newVal, details sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &e.Action, &e.Resource,
			&oldVal, &newVal, &details, &e.ClientIP, &e.Status); err != nil {
			return nil, 0, err
		}
		if oldVal.Valid {
			var v interface{}
			if err := json.Unmarshal([]byte(oldVal.String), &v); err == nil {
				e.OldValue = v
			}
		}
		if newVal.Valid {
			var v interface{}
			if err := json.Unmarshal([]byte(newVal.String), &v); err == nil {
				e.NewValue = v
			}
		}
		if details.Valid {
			var v map[string]interface{}
			if err := json.Unmarshal([]byte(details.String), &v); err == nil {
				e.Details = v
			}
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return entries, total, nil
}

// GetAuditDistinctValues returns distinct actors, actions, and statuses
// from the audit_log table for building filter dropdowns.
func (s *Store) GetAuditDistinctValues(ctx context.Context) (audit.FilterInfo, error) {
	var info audit.FilterInfo

	// Actors
	actors, err := s.queryDistinct(ctx, "SELECT DISTINCT actor FROM audit_log ORDER BY actor")
	if err != nil {
		return info, fmt.Errorf("distinct actors: %w", err)
	}
	info.Actors = actors

	// Actions
	actions, err := s.queryDistinct(ctx, "SELECT DISTINCT action FROM audit_log ORDER BY action")
	if err != nil {
		return info, fmt.Errorf("distinct actions: %w", err)
	}
	info.Actions = actions

	// Statuses
	statuses, err := s.queryDistinct(ctx, "SELECT DISTINCT status FROM audit_log ORDER BY status")
	if err != nil {
		return info, fmt.Errorf("distinct statuses: %w", err)
	}
	info.Statuses = statuses

	return info, nil
}

// queryDistinct runs a query that returns a single string column and collects results.
func (s *Store) queryDistinct(ctx context.Context, query string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vals []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	return vals, rows.Err()
}

// marshalNullableJSON marshals a value to JSON bytes, returning nil for nil input.
// This ensures NULL is stored in PostgreSQL for absent values rather than "null".
func marshalNullableJSON(v interface{}) (interface{}, error) {
	if v == nil {
		return nil, nil
	}
	// Check for empty map
	if m, ok := v.(map[string]interface{}); ok && len(m) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// CountAuditEntries returns the total number of audit log entries.
func (s *Store) CountAuditEntries(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&count)
	return count, err
}

// PruneAuditLog deletes audit entries older than the given duration.
func (s *Store) PruneAuditLog(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM audit_log WHERE timestamp < $1
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune audit log: %w", err)
	}
	return result.RowsAffected()
}
