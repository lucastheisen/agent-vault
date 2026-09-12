package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const FilterCapabilityTokenPrefix = "av_fcap_"

// CreateFilterCapability persists a capability under a one-way token hash and
// returns the raw opaque bearer exactly once. The caller is responsible for
// ensuring SnapshotJSON contains no credential values; this layer validates
// that it is well-formed and versioned before accepting it.
func (s *SQLStore) CreateFilterCapability(ctx context.Context, capability *FilterCapability) (string, error) {
	if err := validateNewFilterCapability(capability); err != nil {
		return "", err
	}

	rawToken := newPrefixedToken(FilterCapabilityTokenPrefix)
	tokenHash := hashToken(rawToken)
	now := time.Now().UTC()
	if !now.Before(capability.ExpiresAt) {
		return "", fmt.Errorf("CreateFilterCapability: expiry must be in the future")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("CreateFilterCapability: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Opportunistic cleanup keeps the short-lived table bounded even if a
	// process's scheduled sweeper is delayed.
	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind("DELETE FROM filter_capabilities WHERE expires_at <= ?"),
		s.dialect.FormatTime(now)); err != nil {
		return "", fmt.Errorf("CreateFilterCapability: delete expired: %w", err)
	}

	copyCapability := *capability
	copyCapability.State = FilterCapabilityIssued
	copyCapability.CreatedAt = now
	copyCapability.ClaimedAt = nil
	copyCapability.ConsumedAt = nil
	if err := s.validateFilterCapabilitySourceTx(ctx, tx, &copyCapability, now); err != nil {
		return "", err
	}

	req := copyCapability.Request
	_, err = tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO filter_capabilities (
		token_hash, kind, state, source_vault_id, source_session_hash,
		source_actor_id, source_actor_type, source_agent_id,
		target_vault_id, target_vault_name, target_vault_role,
		request_method, request_scheme, request_authority, request_path, request_query,
		snapshot_version, snapshot_json, expires_at, created_at)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		tokenHash, copyCapability.Kind, copyCapability.State,
		copyCapability.SourceVaultID, copyCapability.SourceSessionHash,
		copyCapability.SourceActorID, copyCapability.SourceActorType,
		nullableString(copyCapability.SourceAgentID),
		copyCapability.TargetVaultID, copyCapability.TargetVaultName, copyCapability.TargetVaultRole,
		nullableFilterRequestValue(copyCapability.Kind, req.Method),
		nullableFilterRequestValue(copyCapability.Kind, req.Scheme),
		nullableFilterRequestValue(copyCapability.Kind, req.Authority),
		nullableFilterRequestValue(copyCapability.Kind, req.Path),
		nullableFilterRequestValue(copyCapability.Kind, req.Query),
		copyCapability.SnapshotVersion, string(copyCapability.SnapshotJSON),
		s.dialect.FormatTime(copyCapability.ExpiresAt.UTC()), s.dialect.FormatTime(now),
	)
	if err != nil {
		return "", fmt.Errorf("CreateFilterCapability: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("CreateFilterCapability: commit: %w", err)
	}
	return rawToken, nil
}

// ResolveFilterCapability resolves a reusable policy capability or atomically
// claims a continuation for a CONNECT/forward-proxy authority. A continuation
// presented for the wrong authority is burned, preventing later replay.
func (s *SQLStore) ResolveFilterCapability(ctx context.Context, rawToken, connectAuthority string, now time.Time) (*FilterCapability, error) {
	return s.withLockedFilterCapability(ctx, rawToken, func(tx *sql.Tx, capability *FilterCapability) error {
		if !now.Before(capability.ExpiresAt) || capability.State != FilterCapabilityIssued {
			return ErrInvalidFilterCapability
		}
		if err := s.validateFilterCapabilitySourceTx(ctx, tx, capability, now); err != nil {
			if errors.Is(err, ErrInvalidFilterCapability) {
				if burnErr := s.burnFilterCapabilityTx(ctx, tx, rawToken, capability, now); burnErr != nil {
					return burnErr
				}
			}
			return err
		}

		switch capability.Kind {
		case FilterCapabilityPolicy:
			return nil
		case FilterCapabilityContinuation:
			state := FilterCapabilityClaimed
			column := "claimed_at"
			if capability.Request.Authority != connectAuthority {
				state = FilterCapabilityConsumed
				column = "consumed_at"
			}
			res, err := tx.ExecContext(ctx,
				s.dialect.Rebind("UPDATE filter_capabilities SET state = ?, "+column+" = ? WHERE token_hash = ? AND state = 'issued'"),
				state, s.dialect.FormatTime(now.UTC()), hashToken(rawToken))
			if err != nil {
				return fmt.Errorf("ResolveFilterCapability: update: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return ErrInvalidFilterCapability
			}
			capability.State = state
			stamp := now.UTC()
			if state == FilterCapabilityClaimed {
				capability.ClaimedAt = &stamp
				return nil
			}
			capability.ConsumedAt = &stamp
			return ErrInvalidFilterCapability
		default:
			return ErrInvalidFilterCapability
		}
	})
}

// ConsumeFilterContinuation atomically spends a previously claimed
// continuation. The first request burns the row even when its exact binding is
// wrong, so a mutated request cannot be followed by a corrected replay.
func (s *SQLStore) ConsumeFilterContinuation(ctx context.Context, rawToken string, request FilterRequestBinding, now time.Time) (*FilterCapability, error) {
	return s.withLockedFilterCapability(ctx, rawToken, func(tx *sql.Tx, capability *FilterCapability) error {
		if capability.Kind != FilterCapabilityContinuation ||
			capability.State != FilterCapabilityClaimed ||
			!now.Before(capability.ExpiresAt) {
			return ErrInvalidFilterCapability
		}
		if err := s.validateFilterCapabilitySourceTx(ctx, tx, capability, now); err != nil {
			if errors.Is(err, ErrInvalidFilterCapability) {
				if burnErr := s.burnFilterCapabilityTx(ctx, tx, rawToken, capability, now); burnErr != nil {
					return burnErr
				}
			}
			return err
		}

		res, err := tx.ExecContext(ctx,
			s.dialect.Rebind("UPDATE filter_capabilities SET state = 'consumed', consumed_at = ? WHERE token_hash = ? AND state = 'claimed'"),
			s.dialect.FormatTime(now.UTC()), hashToken(rawToken))
		if err != nil {
			return fmt.Errorf("ConsumeFilterContinuation: update: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrInvalidFilterCapability
		}
		capability.State = FilterCapabilityConsumed
		stamp := now.UTC()
		capability.ConsumedAt = &stamp
		if capability.Request != request {
			return ErrInvalidFilterCapability
		}
		return nil
	})
}

// ValidateFilterPolicyCapability revalidates a reusable policy capability,
// including its initiating authority. Call it for every request in a persistent
// CONNECT tunnel, not only when the tunnel is established.
func (s *SQLStore) ValidateFilterPolicyCapability(ctx context.Context, rawToken string, now time.Time) (*FilterCapability, error) {
	return s.withLockedFilterCapability(ctx, rawToken, func(tx *sql.Tx, capability *FilterCapability) error {
		if capability.Kind != FilterCapabilityPolicy ||
			capability.State != FilterCapabilityIssued ||
			!now.Before(capability.ExpiresAt) {
			return ErrInvalidFilterCapability
		}
		if err := s.validateFilterCapabilitySourceTx(ctx, tx, capability, now); err != nil {
			if errors.Is(err, ErrInvalidFilterCapability) {
				if burnErr := s.burnFilterCapabilityTx(ctx, tx, rawToken, capability, now); burnErr != nil {
					return burnErr
				}
			}
			return err
		}
		return nil
	})
}

// burnFilterCapabilityTx makes an authority failure permanent. Re-granting a
// source actor during the remaining TTL must not revive a capability that was
// observed after revocation.
func (s *SQLStore) burnFilterCapabilityTx(ctx context.Context, tx *sql.Tx, rawToken string, capability *FilterCapability, now time.Time) error {
	res, err := tx.ExecContext(ctx,
		s.dialect.Rebind("UPDATE filter_capabilities SET state = 'consumed', consumed_at = ? WHERE token_hash = ? AND state <> 'consumed'"),
		s.dialect.FormatTime(now.UTC()), hashToken(rawToken))
	if err != nil {
		return fmt.Errorf("filter capability: burn revoked authority: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrInvalidFilterCapability
	}
	capability.State = FilterCapabilityConsumed
	stamp := now.UTC()
	capability.ConsumedAt = &stamp
	return nil
}

// DeleteExpiredFilterCapabilities removes rows whose maximum lifetime has
// elapsed. Consumed rows naturally remain only until their very short expiry.
func (s *SQLStore) DeleteExpiredFilterCapabilities(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("DELETE FROM filter_capabilities WHERE expires_at <= ?"),
		s.dialect.FormatTime(before.UTC()))
	if err != nil {
		return 0, fmt.Errorf("DeleteExpiredFilterCapabilities: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLStore) withLockedFilterCapability(ctx context.Context, rawToken string, fn func(*sql.Tx, *FilterCapability) error) (*FilterCapability, error) {
	if rawToken == "" {
		return nil, ErrInvalidFilterCapability
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("filter capability: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `SELECT kind, state, source_vault_id, source_session_hash,
		source_actor_id, source_actor_type, source_agent_id,
		target_vault_id, target_vault_name, target_vault_role,
		request_method, request_scheme, request_authority, request_path, request_query,
		snapshot_version, snapshot_json, expires_at, created_at, claimed_at, consumed_at
	 FROM filter_capabilities WHERE token_hash = ? ` + s.dialect.ForUpdateClause()
	capability, err := s.scanFilterCapability(tx.QueryRowContext(ctx, s.dialect.Rebind(query), hashToken(rawToken)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidFilterCapability
	}
	if err != nil {
		return nil, fmt.Errorf("filter capability: select: %w", err)
	}
	if err := fn(tx, capability); err != nil {
		// Commit intentional burn-on-mismatch state transitions. A rollback
		// would make a mistargeted continuation reusable.
		if capability.State == FilterCapabilityConsumed {
			if commitErr := tx.Commit(); commitErr != nil {
				return nil, fmt.Errorf("filter capability: commit burn: %w", commitErr)
			}
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("filter capability: commit: %w", err)
	}
	return capability, nil
}

func (s *SQLStore) scanFilterCapability(row rowScanner) (*FilterCapability, error) {
	var capability FilterCapability
	var sourceAgentID sql.NullString
	var method, scheme, authority, path, query sql.NullString
	var snapshotJSON string
	var expiresAt, createdAt, claimedAt, consumedAt interface{}
	if err := row.Scan(
		&capability.Kind, &capability.State,
		&capability.SourceVaultID, &capability.SourceSessionHash,
		&capability.SourceActorID, &capability.SourceActorType, &sourceAgentID,
		&capability.TargetVaultID, &capability.TargetVaultName, &capability.TargetVaultRole,
		&method, &scheme, &authority, &path, &query,
		&capability.SnapshotVersion, &snapshotJSON,
		&expiresAt, &createdAt, &claimedAt, &consumedAt,
	); err != nil {
		return nil, err
	}
	capability.SourceAgentID = sourceAgentID.String
	capability.Request = FilterRequestBinding{
		Method: method.String, Scheme: scheme.String, Authority: authority.String,
		Path: path.String, Query: query.String,
	}
	capability.SnapshotJSON = []byte(snapshotJSON)
	var err error
	if capability.ExpiresAt, err = s.dialect.ScanTime(expiresAt); err != nil {
		return nil, err
	}
	if capability.CreatedAt, err = s.dialect.ScanTime(createdAt); err != nil {
		return nil, err
	}
	if capability.ClaimedAt, err = s.dialect.ScanNullableTime(claimedAt); err != nil {
		return nil, err
	}
	if capability.ConsumedAt, err = s.dialect.ScanNullableTime(consumedAt); err != nil {
		return nil, err
	}
	return &capability, nil
}

// validateFilterCapabilitySourceTx checks the initiating session and its actor
// on every use. Session deletion is also protected by the schema FK cascade;
// these checks cover absolute/idle expiry, agent revocation, user deactivation,
// identity mismatch, and loss of source-vault authorization.
func (s *SQLStore) validateFilterCapabilitySourceTx(ctx context.Context, tx *sql.Tx, capability *FilterCapability, now time.Time) error {
	var userID, sessionVaultID, agentID, createdByActorID, createdByActorType sql.NullString
	var expiresAt, lastUsedAt interface{}
	var idleSeconds sql.NullInt64
	err := tx.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT user_id, vault_id, agent_id, expires_at, last_used_at, idle_ttl_seconds,
		        created_by_actor_id, created_by_actor_type
		 FROM sessions WHERE id = ?`), capability.SourceSessionHash,
	).Scan(&userID, &sessionVaultID, &agentID, &expiresAt, &lastUsedAt, &idleSeconds,
		&createdByActorID, &createdByActorType)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidFilterCapability
	}
	if err != nil {
		return fmt.Errorf("filter capability: validate source session: %w", err)
	}
	sessionExpiry, err := s.dialect.ScanNullableTime(expiresAt)
	if err != nil {
		return ErrInvalidFilterCapability
	}
	lastUsed, err := s.dialect.ScanNullableTime(lastUsedAt)
	if err != nil {
		return ErrInvalidFilterCapability
	}
	if sessionExpiry != nil && !now.Before(*sessionExpiry) {
		return ErrInvalidFilterCapability
	}
	if idleSeconds.Valid && idleSeconds.Int64 > 0 && lastUsed != nil && now.Sub(*lastUsed) > time.Duration(idleSeconds.Int64)*time.Second {
		return ErrInvalidFilterCapability
	}

	switch capability.SourceActorType {
	case "user":
		directUserSession := userID.Valid && userID.String == capability.SourceActorID && !agentID.Valid
		scopedSession := !userID.Valid && !agentID.Valid &&
			createdByActorID.String == capability.SourceActorID && createdByActorType.String == "user"
		if (!directUserSession && !scopedSession) || capability.SourceAgentID != "" {
			return ErrInvalidFilterCapability
		}
		var active interface{}
		if err := tx.QueryRowContext(ctx,
			s.dialect.Rebind("SELECT is_active FROM users WHERE id = ?"), capability.SourceActorID).Scan(&active); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidFilterCapability
			}
			return fmt.Errorf("filter capability: validate source user: %w", err)
		}
		isActive, err := s.dialect.ScanBool(active)
		if err != nil || !isActive {
			return ErrInvalidFilterCapability
		}
	case "agent":
		directAgentSession := agentID.Valid && agentID.String == capability.SourceActorID && !userID.Valid
		scopedSession := !userID.Valid && !agentID.Valid &&
			createdByActorID.String == capability.SourceActorID && createdByActorType.String == "agent"
		if (!directAgentSession && !scopedSession) || capability.SourceAgentID != capability.SourceActorID {
			return ErrInvalidFilterCapability
		}
		var status string
		if err := tx.QueryRowContext(ctx,
			s.dialect.Rebind("SELECT status FROM agents WHERE id = ?"), capability.SourceAgentID).Scan(&status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidFilterCapability
			}
			return fmt.Errorf("filter capability: validate source agent: %w", err)
		}
		if status != "active" {
			return ErrInvalidFilterCapability
		}
	default:
		return ErrInvalidFilterCapability
	}

	// A scoped session must be scoped to the same source vault. It does not,
	// however, preserve access after its creator loses the corresponding grant.
	if !userID.Valid && !agentID.Valid && (!sessionVaultID.Valid || sessionVaultID.String != capability.SourceVaultID) {
		return ErrInvalidFilterCapability
	}
	var one int
	if err := tx.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT 1 FROM vault_grants WHERE actor_id = ? AND vault_id = ? AND actor_type = ?"),
		capability.SourceActorID, capability.SourceVaultID, capability.SourceActorType).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidFilterCapability
		}
		return fmt.Errorf("filter capability: validate source vault access: %w", err)
	}
	return nil
}

func validateNewFilterCapability(capability *FilterCapability) error {
	if capability == nil {
		return fmt.Errorf("CreateFilterCapability: capability is required")
	}
	if capability.Kind != FilterCapabilityContinuation && capability.Kind != FilterCapabilityPolicy {
		return fmt.Errorf("CreateFilterCapability: unsupported kind %q", capability.Kind)
	}
	if capability.SourceVaultID == "" || capability.SourceActorID == "" || capability.TargetVaultID == "" ||
		capability.TargetVaultName == "" || capability.TargetVaultRole == "" {
		return fmt.Errorf("CreateFilterCapability: source and target scope are required")
	}
	if capability.SourceActorType != "user" && capability.SourceActorType != "agent" {
		return fmt.Errorf("CreateFilterCapability: unsupported source actor type %q", capability.SourceActorType)
	}
	if capability.SourceActorType == "agent" && capability.SourceAgentID != capability.SourceActorID {
		return fmt.Errorf("CreateFilterCapability: source agent identity mismatch")
	}
	if len(capability.SourceSessionHash) != hex.EncodedLen(32) {
		return fmt.Errorf("CreateFilterCapability: source session hash must be a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(capability.SourceSessionHash); err != nil {
		return fmt.Errorf("CreateFilterCapability: invalid source session hash")
	}
	if capability.ExpiresAt.IsZero() {
		return fmt.Errorf("CreateFilterCapability: expiry is required")
	}
	if capability.Kind == FilterCapabilityContinuation {
		if capability.SnapshotVersion <= 0 || len(capability.SnapshotJSON) == 0 || !json.Valid(capability.SnapshotJSON) {
			return fmt.Errorf("CreateFilterCapability: a versioned JSON snapshot is required for continuations")
		}
		r := capability.Request
		if strings.TrimSpace(r.Method) == "" || r.Scheme == "" || r.Authority == "" || r.Path == "" {
			return fmt.Errorf("CreateFilterCapability: continuation request binding is incomplete")
		}
	} else if capability.SnapshotVersion != 0 || len(capability.SnapshotJSON) != 0 {
		return fmt.Errorf("CreateFilterCapability: policy capabilities must not contain a match snapshot")
	}
	return nil
}

func nullableFilterRequestValue(kind, value string) interface{} {
	if kind == FilterCapabilityPolicy {
		return nil
	}
	return value
}
