CREATE TABLE IF NOT EXISTS patch_jobs(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,agent_id TEXT NOT NULL REFERENCES agents(id),request TEXT NOT NULL CHECK(json_valid(request)),state TEXT NOT NULL,preview_id TEXT UNIQUE,created_by TEXT NOT NULL,created_at TEXT NOT NULL,result TEXT CHECK(result IS NULL OR json_valid(result)));
CREATE INDEX IF NOT EXISTS patch_agent ON patch_jobs(agent_id,state,sequence);
CREATE UNIQUE INDEX IF NOT EXISTS patch_active ON patch_jobs(agent_id) WHERE state IN ('queued','running');
