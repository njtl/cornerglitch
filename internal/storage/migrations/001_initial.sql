-- 001_initial.sql — Glitch PostgreSQL Schema
--
-- Design principle: INSERT-ONLY with versioning.
-- Instead of UPDATE/DELETE, we INSERT new rows with incrementing version numbers.
-- Views provide the "current state" by selecting the latest version per entity/key.
-- This gives us full history, auditability, and safe concurrent access.

BEGIN;

-- ============================================================================
-- 1. config_versions — Full config snapshots (versioned, insert-only)
-- ============================================================================
-- Each config entity (feature_flags, admin_config, vuln_config, etc.) gets a
-- new row on every change. The version number auto-increments per entity.
-- To get current config: query the config_current view.

CREATE TABLE config_versions (
    id          BIGSERIAL       PRIMARY KEY,
    version     INT             NOT NULL,
    entity      VARCHAR(50)     NOT NULL,
    data        JSONB           NOT NULL,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Each (entity, version) pair is unique
    CONSTRAINT uq_config_entity_version UNIQUE (entity, version)
);

-- Fast lookup: "give me the latest version of entity X"
CREATE INDEX idx_config_versions_entity_version
    ON config_versions (entity, version DESC);

-- View: current config per entity (latest version wins)
CREATE VIEW config_current AS
SELECT DISTINCT ON (entity)
    id, version, entity, data, created_at
FROM config_versions
ORDER BY entity, version DESC;

COMMENT ON TABLE config_versions IS
    'Insert-only config store. Each row is a full snapshot of one config entity. Never update or delete — insert a new version instead.';
COMMENT ON VIEW config_current IS
    'Latest config per entity. Uses DISTINCT ON to pick the highest version for each entity.';


-- ============================================================================
-- 2. scan_history — Append-only scan results
-- ============================================================================
-- Every scanner evaluation run gets a row. Results are never modified.

CREATE TABLE scan_history (
    id              BIGSERIAL       PRIMARY KEY,
    scanner_name    VARCHAR(100)    NOT NULL,
    status          VARCHAR(20)     NOT NULL,
    grade           VARCHAR(10),
    detection_rate  FLOAT,
    report          JSONB           NOT NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Most queries want recent scans first
CREATE INDEX idx_scan_history_created_at
    ON scan_history (created_at DESC);

COMMENT ON TABLE scan_history IS
    'Append-only log of scanner evaluation results. Each row is one scanner run with its full ComparisonReport in JSONB.';


-- ============================================================================
-- 3. metrics_snapshots — Periodic server metrics snapshots
-- ============================================================================
-- Snapshots are taken periodically (e.g., every 30s) and appended.
-- snapshot_data holds per-client profiles, top paths, error distributions, etc.

CREATE TABLE metrics_snapshots (
    id                  BIGSERIAL       PRIMARY KEY,
    total_requests      BIGINT,
    total_errors        BIGINT,
    total_2xx           BIGINT,
    total_4xx           BIGINT,
    total_5xx           BIGINT,
    active_connections  INT,
    unique_clients      INT,
    snapshot_data       JSONB,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Time-series queries: recent snapshots first
CREATE INDEX idx_metrics_snapshots_created_at
    ON metrics_snapshots (created_at DESC);

COMMENT ON TABLE metrics_snapshots IS
    'Periodic metrics snapshots. Append-only time series of server state. snapshot_data JSONB holds per-client profiles, top paths, and error distributions.';


-- ============================================================================
-- 4. client_profiles — Per-client behavior tracking (versioned, insert-only)
-- ============================================================================
-- Each client gets a new row when their profile changes (new adaptive mode,
-- updated bot score, etc.). Version increments per client_id.

CREATE TABLE client_profiles (
    id              BIGSERIAL       PRIMARY KEY,
    client_id       VARCHAR(100)    NOT NULL,
    version         INT             NOT NULL,
    total_requests  BIGINT,
    bot_score       INT,
    adaptive_mode   VARCHAR(50),
    profile_data    JSONB           NOT NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_client_profile_version UNIQUE (client_id, version)
);

-- Fast lookup: "give me the latest profile for client X"
CREATE INDEX idx_client_profiles_client_version
    ON client_profiles (client_id, version DESC);

-- View: current profile per client (latest version wins)
CREATE VIEW client_profiles_current AS
SELECT DISTINCT ON (client_id)
    id, client_id, version, total_requests, bot_score,
    adaptive_mode, profile_data, created_at
FROM client_profiles
ORDER BY client_id, version DESC;

COMMENT ON TABLE client_profiles IS
    'Insert-only per-client profile store. Each row is a snapshot of one client''s state. Never update — insert a new version.';
COMMENT ON VIEW client_profiles_current IS
    'Latest profile per client_id. Uses DISTINCT ON to pick the highest version for each client.';


-- ============================================================================
-- 5. request_log — Sampled request log for historical analysis
-- ============================================================================
-- Not every request is logged — the application samples at a configurable rate.
-- This table grows fast; consider partitioning by month for large deployments.
--
-- Partitioning note: For production use with high traffic, convert this to a
-- partitioned table:
--   CREATE TABLE request_log (...) PARTITION BY RANGE (created_at);
--   CREATE TABLE request_log_2026_01 PARTITION OF request_log
--       FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
-- For now, we use a simple table with an index.

CREATE TABLE request_log (
    id              BIGSERIAL       PRIMARY KEY,
    client_id       VARCHAR(100),
    method          VARCHAR(10),
    path            VARCHAR(2048),
    status_code     INT,
    latency_ms      FLOAT,
    response_type   VARCHAR(50),
    user_agent      TEXT,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Time-series access pattern
CREATE INDEX idx_request_log_created_at
    ON request_log (created_at DESC);

COMMENT ON TABLE request_log IS
    'Sampled request log. Append-only. Application controls sampling rate. Consider monthly partitioning for high-traffic deployments.';


-- ============================================================================
-- 6. schema_migrations — Tracks applied migrations
-- ============================================================================
-- The migration runner checks this table to determine which migrations
-- have already been applied. Each migration is applied exactly once.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INT             PRIMARY KEY,
    name        VARCHAR(255)    NOT NULL,
    applied_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE schema_migrations IS
    'Tracks which migration files have been applied. The migration runner skips versions already present here.';


-- Record this migration
INSERT INTO schema_migrations (version, name) VALUES (1, '001_initial.sql');

COMMIT;
