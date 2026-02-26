package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// MetricsSnapshot represents a periodic server metrics snapshot.
type MetricsSnapshot struct {
	ID                int64           `json:"id"`
	TotalRequests     int64           `json:"total_requests"`
	TotalErrors       int64           `json:"total_errors"`
	Total2xx          int64           `json:"total_2xx"`
	Total4xx          int64           `json:"total_4xx"`
	Total5xx          int64           `json:"total_5xx"`
	ActiveConnections int             `json:"active_connections"`
	UniqueClients     int             `json:"unique_clients"`
	SnapshotData      json.RawMessage `json:"snapshot_data,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
}

// SaveMetricsSnapshot inserts a new metrics snapshot.
func (s *Store) SaveMetricsSnapshot(ctx context.Context, snap *MetricsSnapshot) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO metrics_snapshots
			(total_requests, total_errors, total_2xx, total_4xx, total_5xx,
			 active_connections, unique_clients, snapshot_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
		RETURNING id
	`, snap.TotalRequests, snap.TotalErrors, snap.Total2xx, snap.Total4xx, snap.Total5xx,
		snap.ActiveConnections, snap.UniqueClients, nullJSON(snap.SnapshotData)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert metrics snapshot: %w", err)
	}
	return id, nil
}

// ListMetricsSnapshots returns recent metrics snapshots, newest first.
func (s *Store) ListMetricsSnapshots(ctx context.Context, limit int) ([]MetricsSnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, total_requests, total_errors, total_2xx, total_4xx, total_5xx,
		       active_connections, unique_clients, snapshot_data, created_at
		FROM metrics_snapshots
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query metrics snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []MetricsSnapshot
	for rows.Next() {
		var m MetricsSnapshot
		var snapData sql.NullString
		if err := rows.Scan(&m.ID, &m.TotalRequests, &m.TotalErrors,
			&m.Total2xx, &m.Total4xx, &m.Total5xx,
			&m.ActiveConnections, &m.UniqueClients, &snapData, &m.CreatedAt); err != nil {
			return nil, err
		}
		if snapData.Valid {
			m.SnapshotData = json.RawMessage(snapData.String)
		}
		snapshots = append(snapshots, m)
	}
	return snapshots, rows.Err()
}

// GetMetricsInRange returns metrics snapshots within a time range.
func (s *Store) GetMetricsInRange(ctx context.Context, from, to time.Time, limit int) ([]MetricsSnapshot, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, total_requests, total_errors, total_2xx, total_4xx, total_5xx,
		       active_connections, unique_clients, snapshot_data, created_at
		FROM metrics_snapshots
		WHERE created_at >= $1 AND created_at <= $2
		ORDER BY created_at DESC
		LIMIT $3
	`, from, to, limit)
	if err != nil {
		return nil, fmt.Errorf("query metrics range: %w", err)
	}
	defer rows.Close()

	var snapshots []MetricsSnapshot
	for rows.Next() {
		var m MetricsSnapshot
		var snapData sql.NullString
		if err := rows.Scan(&m.ID, &m.TotalRequests, &m.TotalErrors,
			&m.Total2xx, &m.Total4xx, &m.Total5xx,
			&m.ActiveConnections, &m.UniqueClients, &snapData, &m.CreatedAt); err != nil {
			return nil, err
		}
		if snapData.Valid {
			m.SnapshotData = json.RawMessage(snapData.String)
		}
		snapshots = append(snapshots, m)
	}
	return snapshots, rows.Err()
}

// PruneMetrics deletes metrics snapshots older than the given duration.
func (s *Store) PruneMetrics(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM metrics_snapshots WHERE created_at < $1
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune metrics: %w", err)
	}
	return result.RowsAffected()
}

// ---------------------------------------------------------------------------
// Client profiles — versioned per client_id
// ---------------------------------------------------------------------------

// ClientProfileRecord represents a client profile snapshot.
type ClientProfileRecord struct {
	ID            int64           `json:"id"`
	ClientID      string          `json:"client_id"`
	Version       int             `json:"version"`
	TotalRequests int64           `json:"total_requests"`
	BotScore      int             `json:"bot_score"`
	AdaptiveMode  string          `json:"adaptive_mode"`
	ProfileData   json.RawMessage `json:"profile_data"`
	CreatedAt     time.Time       `json:"created_at"`
}

// SaveClientProfile inserts a new version of a client profile.
func (s *Store) SaveClientProfile(ctx context.Context, rec *ClientProfileRecord) error {
	var maxVersion int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM client_profiles WHERE client_id = $1`,
		rec.ClientID,
	).Scan(&maxVersion)
	if err != nil {
		return fmt.Errorf("get max version for client %s: %w", rec.ClientID, err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO client_profiles
			(client_id, version, total_requests, bot_score, adaptive_mode, profile_data)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		rec.ClientID, maxVersion+1, rec.TotalRequests, rec.BotScore, rec.AdaptiveMode, rec.ProfileData,
	)
	if err != nil {
		return fmt.Errorf("insert client profile %s: %w", rec.ClientID, err)
	}
	return nil
}

// LoadClientProfile loads the latest profile for a client.
func (s *Store) LoadClientProfile(ctx context.Context, clientID string) (*ClientProfileRecord, error) {
	var r ClientProfileRecord
	var snapData sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, client_id, version, total_requests, bot_score,
		       adaptive_mode, profile_data, created_at
		FROM client_profiles_current
		WHERE client_id = $1
	`, clientID).Scan(&r.ID, &r.ClientID, &r.Version, &r.TotalRequests,
		&r.BotScore, &r.AdaptiveMode, &snapData, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load client profile %s: %w", clientID, err)
	}
	if snapData.Valid {
		r.ProfileData = json.RawMessage(snapData.String)
	}
	return &r, nil
}

// ListClientProfiles returns the latest profile for all known clients.
func (s *Store) ListClientProfiles(ctx context.Context, limit int) ([]ClientProfileRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, client_id, version, total_requests, bot_score,
		       adaptive_mode, profile_data, created_at
		FROM client_profiles_current
		ORDER BY total_requests DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list client profiles: %w", err)
	}
	defer rows.Close()

	var profiles []ClientProfileRecord
	for rows.Next() {
		var r ClientProfileRecord
		var snapData sql.NullString
		if err := rows.Scan(&r.ID, &r.ClientID, &r.Version, &r.TotalRequests,
			&r.BotScore, &r.AdaptiveMode, &snapData, &r.CreatedAt); err != nil {
			return nil, err
		}
		if snapData.Valid {
			r.ProfileData = json.RawMessage(snapData.String)
		}
		profiles = append(profiles, r)
	}
	return profiles, rows.Err()
}

// PruneClientProfiles removes old versions, keeping the latest N per client.
func (s *Store) PruneClientProfiles(ctx context.Context, keepVersions int) (int64, error) {
	if keepVersions <= 0 {
		keepVersions = 10
	}
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM client_profiles
		WHERE id NOT IN (
			SELECT id FROM (
				SELECT id, ROW_NUMBER() OVER (PARTITION BY client_id ORDER BY version DESC) AS rn
				FROM client_profiles
			) ranked
			WHERE rn <= $1
		)
	`, keepVersions)
	if err != nil {
		return 0, fmt.Errorf("prune client profiles: %w", err)
	}
	return result.RowsAffected()
}

// nullJSON returns nil for empty/nil RawMessage, the value otherwise.
func nullJSON(data json.RawMessage) interface{} {
	if len(data) == 0 {
		return nil
	}
	return data
}
