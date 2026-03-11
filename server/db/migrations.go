package db

const schemaVersion = 4

var migrations = []string{
	// Version 1: Initial schema
	`CREATE TABLE IF NOT EXISTS sessions (
		session_id      TEXT PRIMARY KEY,
		implant_id      TEXT NOT NULL,
		hostname        TEXT,
		username        TEXT,
		os              TEXT,
		arch            TEXT,
		pid             INTEGER,
		integrity_level TEXT,
		transport       TEXT,
		remote_addr     TEXT,
		registered_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_checkin    DATETIME DEFAULT CURRENT_TIMESTAMP,
		alive           BOOLEAN DEFAULT 1
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_implant ON sessions(implant_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_alive ON sessions(alive);

	CREATE TABLE IF NOT EXISTS tasks (
		task_id          TEXT PRIMARY KEY,
		session_id       TEXT NOT NULL,
		task_type        INTEGER NOT NULL,
		data             BLOB,
		timeout_ms       INTEGER DEFAULT 30000,
		created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at     DATETIME,
		success          BOOLEAN,
		result_data      BLOB,
		result_error     TEXT,
		execution_time_ms INTEGER,
		FOREIGN KEY (session_id) REFERENCES sessions(session_id)
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_completed ON tasks(completed_at);

	CREATE TABLE IF NOT EXISTS listeners (
		id         TEXT PRIMARY KEY,
		name       TEXT,
		protocol   INTEGER,
		host       TEXT,
		port       INTEGER,
		active     BOOLEAN DEFAULT 0,
		started_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS builds (
		id          TEXT PRIMARY KEY,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
		operator    TEXT,
		os          TEXT,
		arch        TEXT,
		transport   TEXT,
		callbacks   TEXT,
		secret_hash TEXT,
		evasion     TEXT,
		garbled     BOOLEAN DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS loot (
		id         TEXT PRIMARY KEY,
		type       TEXT,
		source     TEXT,
		session_id TEXT,
		data       BLOB,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (session_id) REFERENCES sessions(session_id)
	);

	CREATE INDEX IF NOT EXISTS idx_loot_session ON loot(session_id);

	CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY
	);

	INSERT OR REPLACE INTO schema_version (version) VALUES (1);`,

	// Version 2: Add session_key column for AES session encryption
	`ALTER TABLE sessions ADD COLUMN session_key BLOB;`,

	// Version 3: Auto-harvest support — tags on loot, tracking table
	`ALTER TABLE loot ADD COLUMN tags TEXT DEFAULT '';

	CREATE TABLE IF NOT EXISTS autoharvest_tasks (
		id         TEXT PRIMARY KEY,
		session_id TEXT NOT NULL,
		task_id    TEXT NOT NULL,
		task_type  TEXT NOT NULL,
		status     TEXT DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (session_id) REFERENCES sessions(session_id)
	);

	CREATE INDEX IF NOT EXISTS idx_autoharvest_session ON autoharvest_tasks(session_id);`,

	// Version 4: H1 — add unique constraint on autoharvest_tasks(session_id, task_type)
	// to prevent race condition in idempotency check
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_autoharvest_unique ON autoharvest_tasks(session_id, task_type);`,
}
