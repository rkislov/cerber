CREATE TABLE IF NOT EXISTS alerts (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 agent_id TEXT NOT NULL REFERENCES agents(id),
 asset_id TEXT NOT NULL REFERENCES assets(id),
 kind TEXT NOT NULL CHECK(kind IN ('agent_offline','inventory_stale','event_delivery_stalled','event_queue_growing','event_health_stale','sensor_no_traffic','sensor_receive_errors','sensor_template_errors','sensor_policy_pending')),
 severity TEXT NOT NULL,
 raised_at TEXT NOT NULL,
 resolved_at TEXT,
 resolution TEXT,
 acknowledged_at TEXT,
 acknowledged_by TEXT,
 evidence TEXT NOT NULL CHECK(json_valid(evidence))
);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_active_identity ON alerts(agent_id,kind) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS alerts_resolution_sequence ON alerts(resolved_at,sequence DESC);
