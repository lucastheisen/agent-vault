package store

import (
	"context"
	"database/sql"
	"time"
)

// FilterCapabilityRow is the persisted, non-secret capability record.
// TokenHash is SHA-256 of the raw token. SnapshotJSON holds key names only.
type FilterCapabilityRow struct {
	TokenHash       string
	Kind            string
	SourceVaultID   string
	PolicyVaultID   string
	PolicyVaultName string
	ActorUserID     string
	ActorAgentID    string
	SourceSessID    string
	VaultRole       string
	VaultName       string
	Method          string
	Scheme          string
	Authority       string
	EscapedPath     string
	Query           string
	SnapshotJSON    []byte
	ExpiresAt       time.Time
	Consumed        bool
}

// InsertFilterCapability stores a new capability row.
func (s *SQLStore) InsertFilterCapability(ctx context.Context, row FilterCapabilityRow) error {
	_, err := s.db.ExecContext(ctx, s.dialect.Rebind(`
		INSERT INTO filter_capabilities (
			token_hash, kind, source_vault_id, policy_vault_id, policy_vault_name,
			actor_user_id, actor_agent_id, source_sess_id, vault_role, vault_name,
			method, scheme, authority, escaped_path, query, snapshot,
			expires_at, consumed, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		row.TokenHash, row.Kind, row.SourceVaultID, row.PolicyVaultID, row.PolicyVaultName,
		row.ActorUserID, row.ActorAgentID, row.SourceSessID, row.VaultRole, row.VaultName,
		row.Method, row.Scheme, row.Authority, row.EscapedPath, row.Query, string(row.SnapshotJSON),
		s.dialect.FormatTime(row.ExpiresAt), s.dialect.BoolVal(row.Consumed),
		s.dialect.FormatTime(time.Now().UTC()),
	)
	if err != nil {
		return err
	}
	// Opportunistic sweep of expired rows.
	_, _ = s.db.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM filter_capabilities WHERE expires_at < ?`),
		s.dialect.FormatTime(time.Now().UTC()))
	return nil
}

// GetFilterCapability returns the row for tokenHash, or sql.ErrNoRows.
func (s *SQLStore) GetFilterCapability(ctx context.Context, tokenHash string) (*FilterCapabilityRow, error) {
	row := s.db.QueryRowContext(ctx, s.dialect.Rebind(`
		SELECT token_hash, kind, source_vault_id, policy_vault_id, policy_vault_name,
		       actor_user_id, actor_agent_id, source_sess_id, vault_role, vault_name,
		       method, scheme, authority, escaped_path, query, snapshot,
		       expires_at, consumed
		  FROM filter_capabilities WHERE token_hash = ?`), tokenHash)
	return scanFilterCapability(s.dialect, row)
}

// ConsumeFilterContinuation atomically marks a continuation consumed.
// Returns sql.ErrNoRows when missing, already consumed, or expired.
func (s *SQLStore) ConsumeFilterContinuation(ctx context.Context, tokenHash string, now time.Time) (*FilterCapabilityRow, error) {
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`
		UPDATE filter_capabilities
		   SET consumed = ?
		 WHERE token_hash = ? AND kind = ? AND consumed = ? AND expires_at > ?`),
		s.dialect.BoolVal(true), tokenHash, "continuation", s.dialect.BoolVal(false),
		s.dialect.FormatTime(now.UTC()),
	)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, sql.ErrNoRows
	}
	return s.GetFilterCapability(ctx, tokenHash)
}

// GetSessionByTokenHash looks up a session by the stored token hash (sessions.id).
func (s *SQLStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	if tokenHash == "" {
		return nil, sql.ErrNoRows
	}
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, user_id, vault_id, agent_id, vault_role, expires_at, created_at,
		        last_used_at, idle_ttl_seconds, device_label, last_ip, last_user_agent, public_id,
		        label, created_by_actor_id, created_by_actor_type
		 FROM sessions WHERE id = ?`), tokenHash,
	)
	var sess Session
	var storedID string
	var userID, vaultID, agentID, vaultRole sql.NullString
	var expiresAt, lastUsedAt interface{}
	var deviceLabel, lastIP, lastUserAgent, publicID sql.NullString
	var label, createdByActorID, createdByActorType sql.NullString
	var idleSecs sql.NullInt64
	var createdAt interface{}
	if err := row.Scan(&storedID, &userID, &vaultID, &agentID, &vaultRole, &expiresAt, &createdAt,
		&lastUsedAt, &idleSecs, &deviceLabel, &lastIP, &lastUserAgent, &publicID,
		&label, &createdByActorID, &createdByActorType); err != nil {
		return nil, err
	}
	sess.ID = storedID
	sess.UserID = userID.String
	sess.VaultID = vaultID.String
	sess.AgentID = agentID.String
	sess.VaultRole = vaultRole.String
	sess.ExpiresAt, _ = s.dialect.ScanNullableTime(expiresAt)
	sess.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	sess.LastUsedAt, _ = s.dialect.ScanNullableTime(lastUsedAt)
	if idleSecs.Valid {
		sess.IdleTTL = time.Duration(idleSecs.Int64) * time.Second
	}
	sess.DeviceLabel = deviceLabel.String
	sess.LastIP = lastIP.String
	sess.LastUserAgent = lastUserAgent.String
	sess.PublicID = publicID.String
	sess.Label = label.String
	sess.CreatedByActorID = createdByActorID.String
	sess.CreatedByActorType = createdByActorType.String
	return &sess, nil
}

// HashSessionToken is the SHA-256 hex used as sessions.id.
func HashSessionToken(rawToken string) string {
	return hashSessionToken(rawToken)
}

func scanFilterCapability(d Dialect, row *sql.Row) (*FilterCapabilityRow, error) {
	var r FilterCapabilityRow
	var snapshot string
	var expiresAt interface{}
	var consumed interface{}
	if err := row.Scan(
		&r.TokenHash, &r.Kind, &r.SourceVaultID, &r.PolicyVaultID, &r.PolicyVaultName,
		&r.ActorUserID, &r.ActorAgentID, &r.SourceSessID, &r.VaultRole, &r.VaultName,
		&r.Method, &r.Scheme, &r.Authority, &r.EscapedPath, &r.Query, &snapshot,
		&expiresAt, &consumed,
	); err != nil {
		return nil, err
	}
	r.SnapshotJSON = []byte(snapshot)
	var err error
	r.ExpiresAt, err = d.ScanTime(expiresAt)
	if err != nil {
		return nil, err
	}
	r.Consumed, err = d.ScanBool(consumed)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
