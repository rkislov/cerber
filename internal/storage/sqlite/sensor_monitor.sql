CREATE TABLE IF NOT EXISTS sensor_samples (
 id INTEGER PRIMARY KEY,
 agent_id TEXT NOT NULL REFERENCES agents(id), input_id TEXT NOT NULL,
 step INTEGER NOT NULL, bucket INTEGER NOT NULL,
 messages INTEGER NOT NULL, bytes INTEGER NOT NULL, stored INTEGER NOT NULL,
 rejected INTEGER NOT NULL, unknown_sets INTEGER NOT NULL,
 seconds REAL NOT NULL, reports INTEGER NOT NULL,
 queue_reports INTEGER NOT NULL, queue_batches INTEGER NOT NULL, queue_bytes INTEGER NOT NULL,
 UNIQUE(agent_id,input_id,step,bucket)
);
CREATE INDEX IF NOT EXISTS sensor_samples_age ON sensor_samples(bucket);
CREATE INDEX IF NOT EXISTS sensor_samples_retention ON sensor_samples(step,bucket);
