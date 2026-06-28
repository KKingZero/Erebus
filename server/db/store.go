package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite single-writer

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	var version int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		version = 0
	}
	for i := version; i < len(migrations); i++ {
		if _, err := s.db.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		// Update version after each successful migration
		if _, err := s.db.Exec("INSERT OR REPLACE INTO schema_version (version) VALUES (?)", i+1); err != nil {
			return fmt.Errorf("update schema version to %d: %w", i+1, err)
		}
	}
	return nil
}

// --- Sessions ---

func (s *Store) CreateSession(row *SessionRow) error {
	_, err := s.db.Exec(`INSERT INTO sessions
		(session_id, implant_id, hostname, username, os, arch, pid, integrity_level, transport, remote_addr, registered_at, last_checkin, alive, session_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.SessionID, row.ImplantID, row.Hostname, row.Username, row.OS, row.Arch,
		row.PID, row.IntegrityLevel, row.Transport, row.RemoteAddr,
		row.RegisteredAt, row.LastCheckin, row.Alive, row.SessionKey)
	return err
}

func (s *Store) GetSession(sessionID string) (*SessionRow, error) {
	row := &SessionRow{}
	err := s.db.QueryRow(`SELECT session_id, implant_id, hostname, username, os, arch, pid,
		integrity_level, transport, remote_addr, registered_at, last_checkin, alive, session_key
		FROM sessions WHERE session_id = ?`, sessionID).Scan(
		&row.SessionID, &row.ImplantID, &row.Hostname, &row.Username, &row.OS, &row.Arch,
		&row.PID, &row.IntegrityLevel, &row.Transport, &row.RemoteAddr,
		&row.RegisteredAt, &row.LastCheckin, &row.Alive, &row.SessionKey)
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) ListSessions() ([]*SessionRow, error) {
	rows, err := s.db.Query(`SELECT session_id, implant_id, hostname, username, os, arch, pid,
		integrity_level, transport, remote_addr, registered_at, last_checkin, alive, session_key
		FROM sessions ORDER BY registered_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*SessionRow
	for rows.Next() {
		row := &SessionRow{}
		if err := rows.Scan(&row.SessionID, &row.ImplantID, &row.Hostname, &row.Username,
			&row.OS, &row.Arch, &row.PID, &row.IntegrityLevel, &row.Transport,
			&row.RemoteAddr, &row.RegisteredAt, &row.LastCheckin, &row.Alive, &row.SessionKey); err != nil {
			return nil, err
		}
		sessions = append(sessions, row)
	}
	return sessions, rows.Err()
}

func (s *Store) UpdateSessionCheckin(sessionID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_checkin = ?, alive = 1 WHERE session_id = ?`,
		time.Now(), sessionID)
	return err
}

func (s *Store) KillSession(sessionID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET alive = 0 WHERE session_id = ?`, sessionID)
	return err
}

// --- Tasks ---

func (s *Store) CreateTask(row *TaskRow) error {
	_, err := s.db.Exec(`INSERT INTO tasks
		(task_id, session_id, task_type, data, timeout_ms, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		row.TaskID, row.SessionID, row.TaskType, row.Data, row.TimeoutMs, row.CreatedAt)
	return err
}

func (s *Store) CompleteTask(taskID string, success bool, resultData []byte, resultError string, execTimeMs int64) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE tasks SET completed_at = ?, success = ?, result_data = ?,
		result_error = ?, execution_time_ms = ? WHERE task_id = ?`,
		now, success, resultData, resultError, execTimeMs, taskID)
	return err
}

func (s *Store) GetTask(taskID string) (*TaskRow, error) {
	row := &TaskRow{}
	err := s.db.QueryRow(`SELECT task_id, session_id, task_type, data, timeout_ms, created_at,
		completed_at, success, result_data, result_error, execution_time_ms
		FROM tasks WHERE task_id = ?`, taskID).Scan(
		&row.TaskID, &row.SessionID, &row.TaskType, &row.Data, &row.TimeoutMs, &row.CreatedAt,
		&row.CompletedAt, &row.Success, &row.ResultData, &row.ResultError, &row.ExecutionTimeMs)
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) ListTasksBySession(sessionID string) ([]*TaskRow, error) {
	rows, err := s.db.Query(`SELECT task_id, session_id, task_type, data, timeout_ms, created_at,
		completed_at, success, result_data, result_error, execution_time_ms
		FROM tasks WHERE session_id = ? ORDER BY created_at DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*TaskRow
	for rows.Next() {
		row := &TaskRow{}
		if err := rows.Scan(&row.TaskID, &row.SessionID, &row.TaskType, &row.Data, &row.TimeoutMs,
			&row.CreatedAt, &row.CompletedAt, &row.Success, &row.ResultData, &row.ResultError,
			&row.ExecutionTimeMs); err != nil {
			return nil, err
		}
		tasks = append(tasks, row)
	}
	return tasks, rows.Err()
}

// --- Builds ---

func (s *Store) CreateBuild(row *BuildRow) error {
	_, err := s.db.Exec(`INSERT INTO builds
		(id, created_at, operator, os, arch, transport, callbacks, secret_hash, evasion, garbled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.CreatedAt, row.Operator, row.OS, row.Arch, row.Transport,
		row.Callbacks, row.SecretHash, row.Evasion, row.Garbled)
	return err
}

func (s *Store) GetBuildBySecretHash(secretHash string) (*BuildRow, error) {
	row := &BuildRow{}
	err := s.db.QueryRow(`SELECT id, created_at, operator, os, arch, transport, callbacks,
		secret_hash, evasion, garbled FROM builds WHERE secret_hash = ?`, secretHash).Scan(
		&row.ID, &row.CreatedAt, &row.Operator, &row.OS, &row.Arch, &row.Transport,
		&row.Callbacks, &row.SecretHash, &row.Evasion, &row.Garbled)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// --- Loot ---

func (s *Store) CreateLoot(row *LootRow) error {
	_, err := s.db.Exec(`INSERT INTO loot (id, type, source, session_id, data, tags, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.Type, row.Source, row.SessionID, row.Data, row.Tags, row.CreatedAt)
	return err
}

func (s *Store) ListLoot(sessionID string) ([]*LootRow, error) {
	var query string
	var args []interface{}
	if sessionID != "" {
		query = `SELECT id, type, source, session_id, data, tags, created_at FROM loot WHERE session_id = ? ORDER BY created_at DESC`
		args = []interface{}{sessionID}
	} else {
		query = `SELECT id, type, source, session_id, data, tags, created_at FROM loot ORDER BY created_at DESC`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*LootRow
	for rows.Next() {
		row := &LootRow{}
		if err := rows.Scan(&row.ID, &row.Type, &row.Source, &row.SessionID, &row.Data, &row.Tags, &row.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

func (s *Store) GetLoot(id string) (*LootRow, error) {
	row := &LootRow{}
	err := s.db.QueryRow(`SELECT id, type, source, session_id, data, tags, created_at FROM loot WHERE id = ?`, id).Scan(
		&row.ID, &row.Type, &row.Source, &row.SessionID, &row.Data, &row.Tags, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// --- Auto-Harvest ---

func (s *Store) CreateAutoHarvestTask(row *AutoHarvestTaskRow) error {
	_, err := s.db.Exec(`INSERT INTO autoharvest_tasks (id, session_id, task_id, task_type, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		row.ID, row.SessionID, row.TaskID, row.TaskType, row.Status, row.CreatedAt)
	return err
}

func (s *Store) HasAutoHarvested(sessionID string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM autoharvest_tasks WHERE session_id = ?`, sessionID).Scan(&count)
	return count > 0, err
}
