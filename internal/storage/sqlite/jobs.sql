CREATE TABLE IF NOT EXISTS agent_schedules (
 id TEXT PRIMARY KEY,
 agent_id TEXT NOT NULL REFERENCES agents(id),
 kind TEXT NOT NULL CHECK(kind IN ('inventory','updates')),
 refresh_metadata INTEGER NOT NULL,
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2592000),
 next_run_at TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS schedules_due ON agent_schedules(enabled,next_run_at);
CREATE TABLE IF NOT EXISTS agent_jobs (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 agent_id TEXT NOT NULL REFERENCES agents(id),
 schedule_id TEXT REFERENCES agent_schedules(id),
 kind TEXT NOT NULL CHECK(kind IN ('inventory','updates')),
 refresh_metadata INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','partial','failed','canceled','expired','timed_out')),
 created_at TEXT NOT NULL,
 started_at TEXT,
 finished_at TEXT,
 expires_at TEXT NOT NULL,
 created_by TEXT NOT NULL,
 result TEXT CHECK(result IS NULL OR json_valid(result)),
 inventory_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS jobs_agent_queue ON agent_jobs(agent_id,state,sequence);
CREATE INDEX IF NOT EXISTS jobs_expiry ON agent_jobs(state,expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS jobs_one_running ON agent_jobs(agent_id) WHERE state='running';
CREATE UNIQUE INDEX IF NOT EXISTS jobs_schedule_pending ON agent_jobs(schedule_id) WHERE state IN ('queued','running');
CREATE TABLE IF NOT EXISTS agent_job_journal (
 agent_id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL,
 result TEXT CHECK(result IS NULL OR json_valid(result))
);
