CREATE TABLE inventories (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 asset_id TEXT NOT NULL REFERENCES assets(id),
 collected_at TEXT NOT NULL,
 payload TEXT NOT NULL CHECK(json_valid(payload))
);
CREATE INDEX inventories_asset_time ON inventories(asset_id,collected_at DESC,sequence DESC);
CREATE TABLE update_checks (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 asset_id TEXT NOT NULL REFERENCES assets(id),
 inventory_id TEXT NOT NULL REFERENCES inventories(id),
 checked_at TEXT NOT NULL,
 payload TEXT NOT NULL CHECK(json_valid(payload))
);
CREATE INDEX update_checks_asset_time ON update_checks(asset_id,checked_at DESC,sequence DESC);
