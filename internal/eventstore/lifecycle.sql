CREATE VIRTUAL TABLE IF NOT EXISTS event_search USING fts5(body, tokenize='unicode61 remove_diacritics 2');
INSERT INTO event_search(rowid,body) SELECT n.sequence,COALESCE(json_extract(n.payload,'$.message'),'')||' '||n.user_name||' '||n.source_ip||' '||COALESCE(json_extract(r.payload,'$.data'),'') FROM normalized_events n LEFT JOIN raw_events r ON r.sequence=n.sequence;
CREATE TRIGGER event_search_insert AFTER INSERT ON normalized_events BEGIN
 INSERT INTO event_search(rowid,body) SELECT NEW.sequence,COALESCE(json_extract(NEW.payload,'$.message'),'')||' '||NEW.user_name||' '||NEW.source_ip||' '||COALESCE((SELECT json_extract(payload,'$.data') FROM raw_events WHERE sequence=NEW.sequence),'');
END;
CREATE TRIGGER event_search_delete AFTER DELETE ON normalized_events BEGIN DELETE FROM event_search WHERE rowid=OLD.sequence;END;
CREATE INDEX normalized_filter_time ON normalized_events(event_time,sequence);
CREATE INDEX normalized_filter_agent_time ON normalized_events(agent_id,event_time,sequence);
CREATE INDEX raw_received_time ON raw_events(received_at,sequence);
CREATE TABLE event_retention(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL,hot_days INTEGER NOT NULL,archive_days INTEGER NOT NULL,version INTEGER NOT NULL,last_success_at TEXT,last_error TEXT NOT NULL DEFAULT '');
INSERT INTO event_retention VALUES(1,0,30,365,1,NULL,'');
CREATE TABLE event_archives(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,created_at TEXT NOT NULL,records INTEGER NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,first_sequence INTEGER NOT NULL,last_sequence INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','expiring','expired')));
CREATE INDEX archive_expiry ON event_archives(state,created_at);
CREATE TABLE event_retention_audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,details TEXT NOT NULL CHECK(json_valid(details)));
CREATE TABLE retired_events(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,source TEXT NOT NULL,cursor TEXT NOT NULL,digest TEXT NOT NULL,archive_id TEXT NOT NULL REFERENCES event_archives(id),UNIQUE(agent_id,source,cursor));

CREATE INDEX normalized_filter_user ON normalized_events(user_name,event_time,sequence);
CREATE INDEX normalized_filter_ip ON normalized_events(source_ip,event_time,sequence);
CREATE INDEX normalized_filter_source ON normalized_events(json_extract(payload,'$.source'),sequence);
