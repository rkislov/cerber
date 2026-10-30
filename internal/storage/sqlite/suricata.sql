CREATE TABLE IF NOT EXISTS suricata_signer (id INTEGER PRIMARY KEY CHECK(id=1), private_key BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS suricata_bundles (id TEXT PRIMARY KEY, manifest TEXT NOT NULL CHECK(json_valid(manifest)), data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS suricata_assignments (agent_id TEXT PRIMARY KEY REFERENCES agents(id), payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE TABLE IF NOT EXISTS suricata_history (seq INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL, at TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE INDEX IF NOT EXISTS suricata_history_agent ON suricata_history(agent_id,seq DESC);
