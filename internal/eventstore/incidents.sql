CREATE TABLE incidents(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT UNIQUE NOT NULL,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
 state TEXT NOT NULL CHECK(state IN ('new','in_progress','contained','resolved','closed')),
 assignee TEXT NOT NULL,
 created_by TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version>0),
 resolution TEXT NOT NULL DEFAULT '',
 outcome TEXT NOT NULL DEFAULT '' CHECK(outcome IN ('','confirmed','false_positive','benign','inconclusive'))
);
CREATE INDEX incident_filter ON incidents(state,severity,sequence);
CREATE TABLE incident_detections(incident_id TEXT NOT NULL REFERENCES incidents(id),detection_id TEXT NOT NULL REFERENCES detections(id),PRIMARY KEY(incident_id,detection_id));
CREATE INDEX incident_by_detection ON incident_detections(detection_id,incident_id);
CREATE TABLE incident_history(sequence INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT NOT NULL REFERENCES incidents(id),kind TEXT NOT NULL,actor TEXT NOT NULL,at TEXT NOT NULL,text TEXT NOT NULL,version INTEGER NOT NULL,UNIQUE(incident_id,version));
CREATE INDEX incident_timeline ON incident_history(incident_id,sequence);
