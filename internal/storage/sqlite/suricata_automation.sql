CREATE TABLE IF NOT EXISTS suricata_feeds (major INTEGER PRIMARY KEY CHECK(major IN (7,8)), payload TEXT NOT NULL CHECK(json_valid(payload)), lease TEXT NOT NULL DEFAULT '',lease_until TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS suricata_group_rules (group_id TEXT PRIMARY KEY REFERENCES agent_groups(id),payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE TABLE IF NOT EXISTS suricata_auto_bundles (id TEXT PRIMARY KEY REFERENCES suricata_bundles(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS suricata_automation_history (seq INTEGER PRIMARY KEY AUTOINCREMENT,subject TEXT NOT NULL,at TEXT NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE INDEX IF NOT EXISTS suricata_automation_subject ON suricata_automation_history(subject,seq DESC);
CREATE TABLE IF NOT EXISTS suricata_rollouts (group_id TEXT PRIMARY KEY REFERENCES agent_groups(id),payload TEXT NOT NULL CHECK(json_valid(payload)));
