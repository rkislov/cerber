CREATE TABLE IF NOT EXISTS agent_groups (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL DEFAULT '',
 archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),
 version INTEGER NOT NULL DEFAULT 1 CHECK(version>0),
 created_by TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_group_members (
 group_id TEXT NOT NULL REFERENCES agent_groups(id),
 agent_id TEXT NOT NULL REFERENCES agents(id),
 added_at TEXT NOT NULL,
 PRIMARY KEY(group_id,agent_id)
);
CREATE INDEX IF NOT EXISTS group_members_agent ON agent_group_members(agent_id);
CREATE TABLE IF NOT EXISTS agent_group_schedules (
 id TEXT PRIMARY KEY,
 group_id TEXT NOT NULL REFERENCES agent_groups(id),
 kind TEXT NOT NULL CHECK(kind IN ('inventory','updates')),
 refresh_metadata INTEGER NOT NULL,
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2592000),
 next_run_at TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS group_schedules_due ON agent_group_schedules(enabled,next_run_at);
CREATE TABLE IF NOT EXISTS agent_group_runs (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 group_id TEXT NOT NULL REFERENCES agent_groups(id),
 group_name TEXT NOT NULL,
 schedule_id TEXT REFERENCES agent_group_schedules(id),
 kind TEXT NOT NULL CHECK(kind IN ('inventory','updates')),
 refresh_metadata INTEGER NOT NULL,
 created_at TEXT NOT NULL,
 created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS group_runs_group ON agent_group_runs(group_id,sequence);
CREATE INDEX IF NOT EXISTS group_runs_schedule ON agent_group_runs(schedule_id);
CREATE TABLE IF NOT EXISTS agent_group_run_members (
 run_id TEXT NOT NULL REFERENCES agent_group_runs(id),
 agent_id TEXT NOT NULL REFERENCES agents(id),
 asset_name TEXT NOT NULL,
 asset_ip TEXT NOT NULL,
 job_id TEXT UNIQUE REFERENCES agent_jobs(id),
 skip_reason TEXT NOT NULL CHECK(skip_reason IN ('','agent_revoked','queue_full','previous_run_pending')),
 PRIMARY KEY(run_id,agent_id),
 CHECK((job_id IS NULL AND skip_reason<>'') OR (job_id IS NOT NULL AND skip_reason=''))
);
CREATE INDEX IF NOT EXISTS group_run_members_agent ON agent_group_run_members(agent_id);
