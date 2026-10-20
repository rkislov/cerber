CREATE TABLE IF NOT EXISTS admin_users (
 username TEXT PRIMARY KEY,
 role TEXT NOT NULL CHECK(role IN ('administrator','operator','viewer')),
 disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
 version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
 password_hash TEXT NOT NULL
);
