package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"radius-go/internal/security"
)

var (
	ErrAlreadyExists = errors.New("already exists")
	ErrLastAPIKey    = errors.New("cannot disable or delete the last active api key")
	ErrNotFound      = errors.New("not found")
	ErrUnauthorized  = errors.New("unauthorized")
)

type Store struct {
	db         *sql.DB
	bcryptCost int
}

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Disabled     bool
	CreatedAt    string
	UpdatedAt    string
}

type APIKey struct {
	ID         int64
	Name       string
	KeyHash    string
	Disabled   bool
	LastUsedAt sql.NullString
	CreatedAt  string
	UpdatedAt  string
}

type CreatedAPIKey struct {
	APIKey APIKey
	Key    string
}

func Open(ctx context.Context, path string, bcryptCost int) (*Store, bool, error) {
	if bcryptCost < bcrypt.MinCost || bcryptCost > bcrypt.MaxCost {
		return nil, false, fmt.Errorf("invalid bcrypt cost: %d", bcryptCost)
	}

	created := false
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("inspect database file: %w", err)
		}
		created = true
		if dir := filepath.Dir(path); dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, false, fmt.Errorf("create database directory: %w", err)
			}
		}
	}

	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, false, fmt.Errorf("open database: %w", err)
	}

	store := &Store{db: db, bcryptCost: bcryptCost}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, false, err
	}
	if err := store.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, false, err
	}
	return store, created, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) configure(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("enable WAL mode: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}
	return nil
}

func (s *Store) ensureSchema(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
	updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	key_hash TEXT NOT NULL UNIQUE,
	disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	last_used_at TEXT,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
	updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

func (s *Store) CreateUser(ctx context.Context, username, password string) (*User, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO users (username, password_hash)
VALUES (?, ?)
`, username, string(passwordHash))
	if err != nil {
		if isConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read user id: %w", err)
	}
	return s.GetUserByID(ctx, id)
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `
SELECT id, username, password_hash, disabled, created_at, updated_at
FROM users
WHERE id = ?
`, id))
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `
SELECT id, username, password_hash, disabled, created_at, updated_at
FROM users
WHERE username = ?
`, username))
}

func (s *Store) UpdateUserPassword(ctx context.Context, username, password string) (*User, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE users
SET password_hash = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE username = ?
`, string(passwordHash), username)
	if err != nil {
		return nil, fmt.Errorf("update user password: %w", err)
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	return s.GetUserByUsername(ctx, username)
}

func (s *Store) SuspendUser(ctx context.Context, username string) (*User, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE users
SET disabled = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE username = ?
`, username)
	if err != nil {
		return nil, fmt.Errorf("suspend user: %w", err)
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	return s.GetUserByUsername(ctx, username)
}

func (s *Store) DeleteUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return requireAffected(res)
}

func (s *Store) AuthenticateUser(ctx context.Context, username, password string) (bool, string, error) {
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, "user_not_found", nil
		}
		return false, "lookup_failed", err
	}
	if user.Disabled {
		return false, "user_disabled", nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return false, "invalid_password", nil
	}
	return true, "ok", nil
}

func (s *Store) CreateAPIKey(ctx context.Context, name string) (*CreatedAPIKey, error) {
	for attempt := 0; attempt < 3; attempt++ {
		key, err := security.GenerateAPIKey()
		if err != nil {
			return nil, err
		}
		keyHash := security.HashAPIKey(key)
		res, err := s.db.ExecContext(ctx, `
INSERT INTO api_keys (name, key_hash)
VALUES (?, ?)
`, name, keyHash)
		if err != nil {
			if isConstraintError(err) {
				if attempt == 0 {
					return nil, ErrAlreadyExists
				}
				continue
			}
			return nil, fmt.Errorf("create api key: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("read api key id: %w", err)
		}
		apiKey, err := s.GetAPIKeyByID(ctx, id)
		if err != nil {
			return nil, err
		}
		return &CreatedAPIKey{APIKey: *apiKey, Key: key}, nil
	}
	return nil, fmt.Errorf("create api key: repeated key collision")
}

func (s *Store) GetAPIKeyByID(ctx context.Context, id int64) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRowContext(ctx, `
SELECT id, name, key_hash, disabled, last_used_at, created_at, updated_at
FROM api_keys
WHERE id = ?
`, id))
}

func (s *Store) AuthenticateAPIKey(ctx context.Context, key string) (*APIKey, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, ErrUnauthorized
	}
	keyHash := security.HashAPIKey(key)
	apiKey, err := scanAPIKey(s.db.QueryRowContext(ctx, `
SELECT id, name, key_hash, disabled, last_used_at, created_at, updated_at
FROM api_keys
WHERE key_hash = ?
`, keyHash))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	if apiKey.Disabled {
		return nil, ErrUnauthorized
	}
	if _, err := s.db.ExecContext(ctx, `
UPDATE api_keys
SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
	updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?
`, apiKey.ID); err != nil {
		return nil, fmt.Errorf("update api key usage: %w", err)
	}
	return apiKey, nil
}

func (s *Store) SuspendAPIKey(ctx context.Context, id int64) (*APIKey, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	disabled, err := apiKeyDisabled(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if !disabled {
		count, err := activeAPIKeyCount(ctx, tx)
		if err != nil {
			return nil, err
		}
		if count <= 1 {
			return nil, ErrLastAPIKey
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE api_keys
SET disabled = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?
`, id); err != nil {
		return nil, fmt.Errorf("suspend api key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return s.GetAPIKeyByID(ctx, id)
}

func (s *Store) DeleteAPIKey(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	disabled, err := apiKeyDisabled(ctx, tx, id)
	if err != nil {
		return err
	}
	if !disabled {
		count, err := activeAPIKeyCount(ctx, tx)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastAPIKey
		}
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	if err := requireAffected(res); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func scanUser(row *sql.Row) (*User, error) {
	var user User
	var disabled int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &disabled, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}
	user.Disabled = disabled == 1
	return &user, nil
}

func scanAPIKey(row *sql.Row) (*APIKey, error) {
	var apiKey APIKey
	var disabled int
	if err := row.Scan(&apiKey.ID, &apiKey.Name, &apiKey.KeyHash, &disabled, &apiKey.LastUsedAt, &apiKey.CreatedAt, &apiKey.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan api key: %w", err)
	}
	apiKey.Disabled = disabled == 1
	return &apiKey, nil
}

func apiKeyDisabled(ctx context.Context, tx *sql.Tx, id int64) (bool, error) {
	var disabled int
	if err := tx.QueryRowContext(ctx, "SELECT disabled FROM api_keys WHERE id = ?", id).Scan(&disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("read api key: %w", err)
	}
	return disabled == 1, nil
}

func activeAPIKeyCount(ctx context.Context, tx *sql.Tx) (int, error) {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM api_keys WHERE disabled = 0").Scan(&count); err != nil {
		return 0, fmt.Errorf("count active api keys: %w", err)
	}
	return count, nil
}

func requireAffected(res sql.Result) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("read affected rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func isConstraintError(err error) bool {
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrConstraint
}
