package brokercore

import (
	"context"
	"database/sql"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// SQLCapabilities is the shared-store backend. Token material is stored
// only as a SHA-256 hash; consume is an atomic conditional update.
type SQLCapabilities struct {
	Store *store.SQLStore
	Check SourceChecker
	Now   func() time.Time
	TTL   time.Duration
}

func NewSQLCapabilities(s *store.SQLStore) *SQLCapabilities {
	return &SQLCapabilities{Store: s}
}

func (s *SQLCapabilities) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SQLCapabilities) ttl() time.Duration {
	if s != nil && s.TTL > 0 {
		return s.TTL
	}
	return capabilityTTL
}

func recToRow(rec Capability) store.FilterCapabilityRow {
	snap, _ := rec.Snapshot.Marshal()
	return store.FilterCapabilityRow{
		TokenHash:       rec.TokenHash,
		Kind:            string(rec.Kind),
		SourceVaultID:   rec.SourceVaultID,
		PolicyVaultID:   rec.PolicyVaultID,
		PolicyVaultName: rec.PolicyVaultName,
		ActorUserID:     rec.ActorUserID,
		ActorAgentID:    rec.ActorAgentID,
		SourceSessID:    rec.SourceSessID,
		VaultRole:       rec.VaultRole,
		VaultName:       rec.VaultName,
		Method:          rec.Method,
		Scheme:          rec.Scheme,
		Authority:       rec.Authority,
		EscapedPath:     rec.EscapedPath,
		Query:           rec.Query,
		SnapshotJSON:    snap,
		ExpiresAt:       rec.ExpiresAt,
		Consumed:        rec.Consumed,
	}
}

func rowToRec(row *store.FilterCapabilityRow) (*Capability, error) {
	if row == nil {
		return nil, ErrInvalidSession
	}
	snap, err := ParseMatchSnapshot(row.SnapshotJSON)
	if err != nil && len(row.SnapshotJSON) > 0 && string(row.SnapshotJSON) != "" && string(row.SnapshotJSON) != "{}" {
		// Policy rows may have an empty snapshot; continuation must parse.
		if row.Kind == string(CapContinuation) {
			return nil, ErrInvalidSession
		}
		snap = MatchSnapshot{Version: matchSnapshotVersion}
	}
	if row.Kind == string(CapContinuation) && snap.Version != matchSnapshotVersion {
		return nil, ErrInvalidSession
	}
	return &Capability{
		Kind:            CapabilityKind(row.Kind),
		SourceVaultID:   row.SourceVaultID,
		PolicyVaultID:   row.PolicyVaultID,
		PolicyVaultName: row.PolicyVaultName,
		ActorUserID:     row.ActorUserID,
		ActorAgentID:    row.ActorAgentID,
		SourceSessID:    row.SourceSessID,
		VaultRole:       row.VaultRole,
		VaultName:       row.VaultName,
		Method:          row.Method,
		Scheme:          row.Scheme,
		Authority:       row.Authority,
		EscapedPath:     row.EscapedPath,
		Query:           row.Query,
		Snapshot:        snap,
		TokenHash:       row.TokenHash,
		ExpiresAt:       row.ExpiresAt,
		Consumed:        row.Consumed,
	}, nil
}

func (s *SQLCapabilities) issue(ctx context.Context, kind CapabilityKind, prefix string, rec Capability) (string, error) {
	raw, err := randomToken(prefix)
	if err != nil {
		return "", err
	}
	rec.Kind = kind
	rec.TokenHash = hashToken(raw)
	rec.ExpiresAt = s.now().Add(s.ttl())
	rec.Consumed = false
	if rec.Snapshot.Version == 0 {
		rec.Snapshot.Version = matchSnapshotVersion
	}
	if err := s.Store.InsertFilterCapability(ctx, recToRow(rec)); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *SQLCapabilities) IssueContinuation(ctx context.Context, rec Capability) (string, error) {
	return s.issue(ctx, CapContinuation, ContinuationTokenPrefix, rec)
}

func (s *SQLCapabilities) IssuePolicy(ctx context.Context, rec Capability) (string, error) {
	return s.issue(ctx, CapPolicy, PolicyTokenPrefix, rec)
}

func (s *SQLCapabilities) lookup(ctx context.Context, rawToken string) (*Capability, error) {
	if rawToken == "" {
		return nil, ErrInvalidSession
	}
	row, err := s.Store.GetFilterCapability(ctx, hashToken(rawToken))
	if err != nil || row == nil {
		return nil, ErrInvalidSession
	}
	if s.now().After(row.ExpiresAt) {
		return nil, ErrInvalidSession
	}
	if row.Kind == string(CapContinuation) && row.Consumed {
		return nil, ErrInvalidSession
	}
	cp, err := rowToRec(row)
	if err != nil {
		return nil, ErrInvalidSession
	}
	if s.Check != nil {
		if err := s.Check(ctx, cp); err != nil {
			return nil, ErrInvalidSession
		}
	}
	return cp, nil
}

func (s *SQLCapabilities) Authenticate(ctx context.Context, rawToken string) (*Capability, error) {
	return s.lookup(ctx, rawToken)
}

func (s *SQLCapabilities) ConsumeContinuation(ctx context.Context, rawToken string) (*Capability, error) {
	if rawToken == "" {
		return nil, ErrInvalidSession
	}
	row, err := s.Store.ConsumeFilterContinuation(ctx, hashToken(rawToken), s.now())
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidSession
		}
		return nil, ErrInvalidSession
	}
	cp, err := rowToRec(row)
	if err != nil {
		return nil, ErrInvalidSession
	}
	if s.Check != nil {
		if err := s.Check(ctx, cp); err != nil {
			return nil, ErrInvalidSession
		}
	}
	if cp.Snapshot.Version != matchSnapshotVersion {
		return nil, ErrInvalidSession
	}
	return cp, nil
}
