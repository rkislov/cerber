CREATE TABLE assets (
 id TEXT PRIMARY KEY,
 ip TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE targets (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE target_assets (
 target_id TEXT NOT NULL REFERENCES targets(id),
 asset_id TEXT NOT NULL REFERENCES assets(id),
 PRIMARY KEY (target_id,asset_id)
);
CREATE TABLE tasks (
 id TEXT PRIMARY KEY,
 target_id TEXT NOT NULL REFERENCES targets(id),
 hosts TEXT NOT NULL CHECK(json_valid(hosts)),
 config TEXT NOT NULL CHECK(json_valid(config)),
 status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','interrupted')),
 created_at TEXT NOT NULL,
 started_at TEXT,
 finished_at TEXT,
 error TEXT NOT NULL DEFAULT '',
 knowledge_snapshot TEXT CHECK(knowledge_snapshot IS NULL OR json_valid(knowledge_snapshot))
);
CREATE TABLE observations (
 task_id TEXT NOT NULL REFERENCES tasks(id),
 asset_id TEXT NOT NULL REFERENCES assets(id),
 ip TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 protocol TEXT NOT NULL CHECK(protocol = 'tcp'),
 state TEXT NOT NULL CHECK(state IN ('open','closed','timeout','error')),
 detail TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 PRIMARY KEY(task_id,asset_id,port,protocol)
);
CREATE TABLE outbox (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 schema_version INTEGER NOT NULL,
 kind TEXT NOT NULL,
 aggregate_id TEXT NOT NULL,
 source TEXT NOT NULL,
 occurred_at TEXT NOT NULL,
 payload TEXT NOT NULL CHECK(json_valid(payload))
);
CREATE INDEX tasks_status_idx ON tasks(status);
