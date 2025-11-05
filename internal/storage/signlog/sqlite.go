package signlog

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const dateLayout = "2006-01-02"

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	s := &Store{db: db}
	if err := s.init(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

func (s *Store) init() error {
	createStmt := `CREATE TABLE IF NOT EXISTS sign_logs (
        address TEXT NOT NULL,
        signed_date TEXT NOT NULL,
        login_done INTEGER NOT NULL DEFAULT 0,
        invite_done INTEGER NOT NULL DEFAULT 0,
        share_done INTEGER NOT NULL DEFAULT 0,
        target_invites INTEGER NOT NULL DEFAULT 0,
        completed_invites INTEGER NOT NULL DEFAULT 0,
        target_invites_min INTEGER NOT NULL DEFAULT 0,
        target_invites_max INTEGER NOT NULL DEFAULT 0,
        today_earn TEXT,
        total_earn TEXT,
        balance TEXT,
        PRIMARY KEY(address, signed_date)
    )`
	if _, err := s.db.Exec(createStmt); err != nil {
		return err
	}
	return s.ensureColumns()
}

func (s *Store) ensureColumns() error {
	columns := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(sign_logs)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		columns[strings.ToLower(name)] = true
	}

	alterStatements := []string{}
	addColumn := func(name, definition string) {
		if !columns[name] {
			alterStatements = append(alterStatements, definition)
		}
	}

	addColumn("login_done", `ALTER TABLE sign_logs ADD COLUMN login_done INTEGER NOT NULL DEFAULT 0`)
	addColumn("invite_done", `ALTER TABLE sign_logs ADD COLUMN invite_done INTEGER NOT NULL DEFAULT 0`)
	addColumn("share_done", `ALTER TABLE sign_logs ADD COLUMN share_done INTEGER NOT NULL DEFAULT 0`)
	addColumn("target_invites", `ALTER TABLE sign_logs ADD COLUMN target_invites INTEGER NOT NULL DEFAULT 0`)
	addColumn("completed_invites", `ALTER TABLE sign_logs ADD COLUMN completed_invites INTEGER NOT NULL DEFAULT 0`)
	addColumn("target_invites_min", `ALTER TABLE sign_logs ADD COLUMN target_invites_min INTEGER NOT NULL DEFAULT 0`)
	addColumn("target_invites_max", `ALTER TABLE sign_logs ADD COLUMN target_invites_max INTEGER NOT NULL DEFAULT 0`)
	addColumn("today_earn", `ALTER TABLE sign_logs ADD COLUMN today_earn TEXT`)
	addColumn("total_earn", `ALTER TABLE sign_logs ADD COLUMN total_earn TEXT`)
	addColumn("balance", `ALTER TABLE sign_logs ADD COLUMN balance TEXT`)

	for _, stmt := range alterStatements {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DailyStatus(address string, day time.Time) (loginDone, inviteDone, shareDone bool, target, completed, targetMin, targetMax int, todayEarn, totalEarn, balance string, err error) {
	addr := normalizeAddress(address)
	dateStr := day.UTC().Format(dateLayout)

	var login, invite, share int
	var minVal, maxVal int
	var todayEarnNS, totalEarnNS, balanceNS sql.NullString
	err = s.db.QueryRow(`SELECT login_done, invite_done, share_done, target_invites, completed_invites, target_invites_min, target_invites_max, today_earn, total_earn, balance FROM sign_logs WHERE address = ? AND signed_date = ?`, addr, dateStr).
		Scan(&login, &invite, &share, &target, &completed, &minVal, &maxVal, &todayEarnNS, &totalEarnNS, &balanceNS)
	if err == sql.ErrNoRows {
		return false, false, false, 0, 0, 0, 0, "", "", "", nil
	}
	if err != nil {
		return false, false, false, 0, 0, 0, 0, "", "", "", err
	}
	loginDone = login == 1
	inviteDone = invite == 1
	shareDone = share == 1
	targetMin = minVal
	targetMax = maxVal
	if todayEarnNS.Valid {
		todayEarn = todayEarnNS.String
	}
	if totalEarnNS.Valid {
		totalEarn = totalEarnNS.String
	}
	if balanceNS.Valid {
		balance = balanceNS.String
	}
	return loginDone, inviteDone, shareDone, target, completed, targetMin, targetMax, todayEarn, totalEarn, balance, nil
}

func (s *Store) MarkLogin(address string, day time.Time) error {
	addr := normalizeAddress(address)
	dateStr := day.UTC().Format(dateLayout)

	_, err := s.db.Exec(`INSERT INTO sign_logs(address, signed_date, login_done, invite_done)
    VALUES(?, ?, 1, 0)
    ON CONFLICT(address, signed_date) DO UPDATE SET login_done = 1`, addr, dateStr)
	return err
}

func (s *Store) MarkInvite(address string, day time.Time) error {
	addr := normalizeAddress(address)
	dateStr := day.UTC().Format(dateLayout)

	_, err := s.db.Exec(`INSERT INTO sign_logs(address, signed_date, login_done, invite_done)
    VALUES(?, ?, 0, 1)
    ON CONFLICT(address, signed_date) DO UPDATE SET invite_done = 1`, addr, dateStr)
	return err
}

func (s *Store) SetInviteTarget(address string, day time.Time, target, min, max int) error {
	addr := normalizeAddress(address)
	dateStr := day.UTC().Format(dateLayout)
	done := 0
	if target <= 0 {
		done = 1
	}

	_, err := s.db.Exec(`INSERT INTO sign_logs(address, signed_date, target_invites, completed_invites, invite_done, target_invites_min, target_invites_max)
    VALUES(?, ?, ?, 0, ?, ?, ?)
    ON CONFLICT(address, signed_date) DO UPDATE SET
        target_invites = excluded.target_invites,
        target_invites_min = excluded.target_invites_min,
        target_invites_max = excluded.target_invites_max,
        invite_done = CASE
            WHEN excluded.target_invites = 0 THEN 1
            WHEN completed_invites >= excluded.target_invites AND excluded.target_invites > 0 THEN 1
            ELSE invite_done
        END`, addr, dateStr, target, done, min, max)
	return err
}

func (s *Store) IncrementInvite(address string, day time.Time) (int, error) {
	addr := normalizeAddress(address)
	dateStr := day.UTC().Format(dateLayout)

	_, err := s.db.Exec(`INSERT INTO sign_logs(address, signed_date, target_invites, completed_invites)
    VALUES(?, ?, 0, 1)
    ON CONFLICT(address, signed_date) DO UPDATE
    SET completed_invites = completed_invites + 1,
        invite_done = CASE WHEN completed_invites + 1 >= target_invites AND target_invites > 0 THEN 1 ELSE invite_done END`, addr, dateStr)
	if err != nil {
		return 0, err
	}
	var completed int
	err = s.db.QueryRow(`SELECT completed_invites FROM sign_logs WHERE address = ? AND signed_date = ?`, addr, dateStr).Scan(&completed)
	return completed, err
}

func (s *Store) MarkShare(address string, day time.Time) error {
	addr := normalizeAddress(address)
	dateStr := day.UTC().Format(dateLayout)

	_, err := s.db.Exec(`INSERT INTO sign_logs(address, signed_date, share_done)
    VALUES(?, ?, 1)
    ON CONFLICT(address, signed_date) DO UPDATE SET share_done = 1`, addr, dateStr)
	return err
}

func (s *Store) UpdateEarning(address string, day time.Time, todayEarn, totalEarn, balance string) error {
	addr := normalizeAddress(address)
	dateStr := day.UTC().Format(dateLayout)

	_, err := s.db.Exec(`INSERT INTO sign_logs(address, signed_date, today_earn, total_earn, balance)
    VALUES(?, ?, ?, ?, ?)
    ON CONFLICT(address, signed_date) DO UPDATE SET today_earn = excluded.today_earn, total_earn = excluded.total_earn, balance = excluded.balance`, addr, dateStr, todayEarn, totalEarn, balance)
	return err
}

func normalizeAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}
