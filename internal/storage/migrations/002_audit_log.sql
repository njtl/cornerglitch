-- 002_audit_log.sql — Audit log table for tracking all state changes and actions
--
-- Design: append-only event log. Every configuration change, user action, and
-- system event is recorded with who, what, when, and before/after values.
-- Entries are never updated or deleted — this is an immutable audit trail.

BEGIN;

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor       VARCHAR(100) NOT NULL DEFAULT 'system',
    action      VARCHAR(100) NOT NULL,
    resource    VARCHAR(200) NOT NULL,
    old_value   JSONB,
    new_value   JSONB,
    details     JSONB,
    client_ip   VARCHAR(45),
    status      VARCHAR(20) NOT NULL DEFAULT 'success',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log (resource, timestamp DESC);

COMMENT ON TABLE audit_log IS
    'Append-only audit trail. Records every configuration change, user action, and system event with before/after values. Never update or delete rows.';

-- Record this migration
INSERT INTO schema_migrations (version, name) VALUES (2, '002_audit_log.sql');

COMMIT;
