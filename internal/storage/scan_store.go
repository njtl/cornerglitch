package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ScanRecord represents a scan history entry for storage.
type ScanRecord struct {
	ID            int64           `json:"id"`
	ScannerName   string          `json:"scanner_name"`
	Status        string          `json:"status"`
	Grade         string          `json:"grade,omitempty"`
	DetectionRate float64         `json:"detection_rate"`
	Report        json.RawMessage `json:"report"`
	CreatedAt     time.Time       `json:"created_at"`
}

// SaveScan appends a scan result to the history.
func (s *Store) SaveScan(ctx context.Context, rec *ScanRecord) (int64, error) {
	if rec.Report == nil {
		rec.Report = json.RawMessage("{}")
	}

	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO scan_history (scanner_name, status, grade, detection_rate, report)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		RETURNING id
	`, rec.ScannerName, rec.Status, nullString(rec.Grade), rec.DetectionRate, rec.Report).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	return id, nil
}

// SaveScanFromReport saves a scan result from an arbitrary report struct.
func (s *Store) SaveScanFromReport(ctx context.Context, scannerName, status, grade string, detectionRate float64, report interface{}) (int64, error) {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return 0, fmt.Errorf("marshal report: %w", err)
	}
	return s.SaveScan(ctx, &ScanRecord{
		ScannerName:   scannerName,
		Status:        status,
		Grade:         grade,
		DetectionRate: detectionRate,
		Report:        reportJSON,
	})
}

// ListScans returns recent scan results, newest first.
func (s *Store) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scanner_name, status, COALESCE(grade, ''), detection_rate, report, created_at
		FROM scan_history
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	var scans []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.ScannerName, &r.Status, &r.Grade, &r.DetectionRate, &r.Report, &r.CreatedAt); err != nil {
			return nil, err
		}
		scans = append(scans, r)
	}
	return scans, rows.Err()
}

// GetScan returns a single scan result by ID.
func (s *Store) GetScan(ctx context.Context, id int64) (*ScanRecord, error) {
	var r ScanRecord
	err := s.db.QueryRowContext(ctx, `
		SELECT id, scanner_name, status, COALESCE(grade, ''), detection_rate, report, created_at
		FROM scan_history WHERE id = $1
	`, id).Scan(&r.ID, &r.ScannerName, &r.Status, &r.Grade, &r.DetectionRate, &r.Report, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get scan %d: %w", id, err)
	}
	return &r, nil
}

// ListScansByPrefix returns recent scan results filtered by scanner_name prefix, newest first.
func (s *Store) ListScansByPrefix(ctx context.Context, prefix string, limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scanner_name, status, COALESCE(grade, ''), detection_rate, report, created_at
		FROM scan_history
		WHERE scanner_name LIKE $1
		ORDER BY created_at DESC
		LIMIT $2
	`, prefix+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("query scans by prefix: %w", err)
	}
	defer rows.Close()

	var scans []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.ScannerName, &r.Status, &r.Grade, &r.DetectionRate, &r.Report, &r.CreatedAt); err != nil {
			return nil, err
		}
		scans = append(scans, r)
	}
	return scans, rows.Err()
}

// CountScans returns the total number of scan records.
func (s *Store) CountScans(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_history`).Scan(&count)
	return count, err
}

// nullString returns a sql.NullString — NULL for empty, valid otherwise.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
