CREATE TABLE IF NOT EXISTS agents (
 id TEXT PRIMARY KEY,
 asset_id TEXT NOT NULL REFERENCES assets(id),
 token_hash TEXT NOT NULL,
 created_at TEXT NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
);
CREATE TABLE IF NOT EXISTS agent_receipts (
 agent_id TEXT NOT NULL REFERENCES agents(id),
 report_id TEXT NOT NULL,
 digest TEXT NOT NULL,
 receipt TEXT NOT NULL CHECK(json_valid(receipt)),
 PRIMARY KEY(agent_id,report_id)
);
CREATE TABLE IF NOT EXISTS agent_queue (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 agent_id TEXT NOT NULL,
 report_id TEXT NOT NULL,
 payload TEXT NOT NULL CHECK(json_valid(payload)),
 UNIQUE(agent_id,report_id)
);
