package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// RequestLogEntry represents a sampled request log entry.
type RequestLogEntry struct {
	ID           int64     `json:"id"`
	ClientID     string    `json:"client_id,omitempty"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	StatusCode   int       `json:"status_code"`
	LatencyMs    float64   `json:"latency_ms"`
	ResponseType string    `json:"response_type,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// SaveRequest inserts a sampled request log entry.
func (s *Store) SaveRequest(ctx context.Context, entry *RequestLogEntry) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO request_log
			(client_id, method, path, status_code, latency_ms, response_type, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, nullString(entry.ClientID), entry.Method, entry.Path,
		entry.StatusCode, entry.LatencyMs,
		nullString(entry.ResponseType), nullString(entry.UserAgent))
	if err != nil {
		return fmt.Errorf("insert request log: %w", err)
	}
	return nil
}

// SaveRequestBatch inserts multiple request log entries in a single transaction.
func (s *Store) SaveRequestBatch(ctx context.Context, entries []RequestLogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO request_log
			(client_id, method, path, status_code, latency_ms, response_type, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		_, err := stmt.ExecContext(ctx, nullString(e.ClientID), e.Method, e.Path,
			e.StatusCode, e.LatencyMs,
			nullString(e.ResponseType), nullString(e.UserAgent))
		if err != nil {
			return fmt.Errorf("insert request: %w", err)
		}
	}

	return tx.Commit()
}

// ListRequests returns recent request log entries, newest first.
func (s *Store) ListRequests(ctx context.Context, limit int) ([]RequestLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryRequests(ctx, `
		SELECT id, COALESCE(client_id, ''), method, path, status_code,
		       latency_ms, COALESCE(response_type, ''), COALESCE(user_agent, ''), created_at
		FROM request_log
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
}

// ListRequestsByClient returns request log entries for a specific client.
func (s *Store) ListRequestsByClient(ctx context.Context, clientID string, limit int) ([]RequestLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryRequests(ctx, `
		SELECT id, COALESCE(client_id, ''), method, path, status_code,
		       latency_ms, COALESCE(response_type, ''), COALESCE(user_agent, ''), created_at
		FROM request_log
		WHERE client_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, clientID, limit)
}

// GetRequestsInRange returns request log entries within a time range.
func (s *Store) GetRequestsInRange(ctx context.Context, from, to time.Time, limit int) ([]RequestLogEntry, error) {
	if limit <= 0 {
		limit = 1000
	}
	return s.queryRequests(ctx, `
		SELECT id, COALESCE(client_id, ''), method, path, status_code,
		       latency_ms, COALESCE(response_type, ''), COALESCE(user_agent, ''), created_at
		FROM request_log
		WHERE created_at >= $1 AND created_at <= $2
		ORDER BY created_at DESC
		LIMIT $3
	`, from, to, limit)
}

// PruneRequests deletes request log entries older than the given duration.
func (s *Store) PruneRequests(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM request_log WHERE created_at < $1
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune requests: %w", err)
	}
	return result.RowsAffected()
}

// CountRequests returns the total number of request log entries.
func (s *Store) CountRequests(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM request_log`).Scan(&count)
	return count, err
}

func (s *Store) queryRequests(ctx context.Context, query string, args ...interface{}) ([]RequestLogEntry, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query requests: %w", err)
	}
	defer rows.Close()

	var entries []RequestLogEntry
	for rows.Next() {
		var e RequestLogEntry
		if err := rows.Scan(&e.ID, &e.ClientID, &e.Method, &e.Path,
			&e.StatusCode, &e.LatencyMs, &e.ResponseType, &e.UserAgent,
			&e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// RequestStats holds aggregated request statistics.
type RequestStats struct {
	TotalRequests int64          `json:"total_requests"`
	ByMethod      map[string]int `json:"by_method"`
	ByStatus      map[int]int    `json:"by_status"`
	AvgLatencyMs  float64        `json:"avg_latency_ms"`
}

// GetRequestStats returns aggregated request statistics.
func (s *Store) GetRequestStats(ctx context.Context) (*RequestStats, error) {
	stats := &RequestStats{
		ByMethod: make(map[string]int),
		ByStatus: make(map[int]int),
	}

	// Total and avg latency
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(AVG(latency_ms), 0) FROM request_log
	`).Scan(&stats.TotalRequests, &stats.AvgLatencyMs)
	if err != nil {
		return nil, fmt.Errorf("request stats total: %w", err)
	}

	// By method
	rows, err := s.db.QueryContext(ctx, `
		SELECT method, COUNT(*) FROM request_log GROUP BY method
	`)
	if err != nil {
		return nil, fmt.Errorf("request stats by method: %w", err)
	}
	for rows.Next() {
		var method string
		var count int
		if err := rows.Scan(&method, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.ByMethod[method] = count
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// By status code bucket
	rows2, err := s.db.QueryContext(ctx, `
		SELECT status_code, COUNT(*) FROM request_log GROUP BY status_code
	`)
	if err != nil {
		return nil, fmt.Errorf("request stats by status: %w", err)
	}
	for rows2.Next() {
		var status, count int
		if err := rows2.Scan(&status, &count); err != nil {
			rows2.Close()
			return nil, err
		}
		stats.ByStatus[status] = count
	}
	rows2.Close()

	return stats, rows2.Err()
}

// GetPathsInTimeWindow returns distinct paths accessed within a time window.
// This mirrors the metrics.Collector.GetPathsInTimeWindow() used by scaneval
// for false-negative classification.
func (s *Store) GetPathsInTimeWindow(ctx context.Context, from, to time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT path FROM request_log
		WHERE created_at >= $1 AND created_at <= $2
		ORDER BY path
	`, from, to)
	if err != nil {
		return nil, fmt.Errorf("paths in window: %w", err)
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var p sql.NullString
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if p.Valid {
			paths = append(paths, p.String)
		}
	}
	return paths, rows.Err()
}
