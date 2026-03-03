-- Migration 003: Add index on scan_history.scanner_name for prefix queries.
-- The ListScansByPrefix query uses LIKE 'prefix%' which benefits from a btree index.
CREATE INDEX IF NOT EXISTS idx_scan_history_scanner_name
    ON scan_history (scanner_name);
