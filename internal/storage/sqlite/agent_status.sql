CREATE TABLE IF NOT EXISTS agent_status (
 agent_id TEXT PRIMARY KEY REFERENCES agents(id),
 last_seen_at TEXT NOT NULL,
 last_report_at TEXT,
 latest_inventory_at TEXT,
 latest_inventory_id TEXT REFERENCES inventories(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS agent_heartbeats (
 agent_id TEXT PRIMARY KEY REFERENCES agents(id),
 received_at TEXT NOT NULL,
 payload TEXT NOT NULL CHECK(json_valid(payload))
);
