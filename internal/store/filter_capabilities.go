package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// FilterCapabilityKind distinguishes the two capabilities a policy-filter
// hop can mint.
type FilterCapabilityKind string

const (
	// FilterCapContinuation is the single-use authority to complete the
	// exact request that entered the filter. Consuming it is what allows
	// the destination credential to be resolved at all.
	FilterCapContinuation FilterCapabilityKind = "continuation"

	// FilterCapPolicy is the optional, reusable-in-window authority to
	// call *unfiltered* services in the configured policy vault. It can
	// never spend the originating destination credential.
	FilterCapPolicy FilterCapabilityKind = "policy"
)

// FilterMatchSnapshotVersion is the format version written into new
// capability rows. Bump it whenever the serialized frozen match changes
// in a way that affects which credential gets attached; readers fail
// closed on any version they do not recognize, so a mixed-version
// deployment refuses the hop instead of silently resolving a different
// slot.
const FilterMatchSnapshotVersion = 1

// Sentinel errors from the capability path. Every one of them is a
// fail-closed outcome: none may result in a destination credential being
// resolved.
var (
	ErrFilterCapabilityNotFound = errors.New("store: filter capability not found")
	ErrFilterCapabilityExpired  = errors.New("store: filter capability expired")
	ErrFilterCapabilityConsumed = errors.New("store: filter capability already consumed")
	ErrFilterCapabilityBind     = errors.New("store: filter capability request bind mismatch")
	ErrFilterCapabilityKind     = errors.New("store: filter capability is of the wrong kind")
)

// FilterCapabilityBind is the exact request a continuation may complete.
// Path is the escaped path and Query the raw query, both taken verbatim
// from the request that entered the filter — comparing decoded forms
// would let two different wire requests claim the same capability.
type FilterCapabilityBind struct {
	Method    string
	Scheme    string
	Authority string
	Path      string
	Query     string
}

// FilterCapability is one short-lived capability row.
//
// It deliberately contains no credential value, no raw token, and
// nothing from which either can be recovered. MatchSnapshot is non-secret
// policy metadata (service identity and credential *key names*).
type FilterCapability struct {
	ID            string
	Kind          FilterCapabilityKind
	FormatVersion int

	// VaultID is the source vault the request matched in. PolicyVaultID
	// is set only for FilterCapPolicy rows.
	VaultID       string
	PolicyVaultID string

	// ActorID is the initiating actor, retained so audit and rate-limit
	// attribution stay with whoever made the original request rather
	// than drifting to the sidecar.
	ActorID string

	// SourceSessionHash is the sessions primary key — the SHA-256 of the
	// initiating raw session token, never the token. SourceAgentID is
	// set when the initiator was an agent. Both exist so revocation of
	// the source authority invalidates this capability immediately,
	// rather than leaving up to a full TTL of usable authority behind.
	SourceSessionHash string
	SourceAgentID     string

	ServiceName   string
	Bind          FilterCapabilityBind
	MatchSnapshot string

	IssuedAt   time.Time
	ExpiresAt  time.Time
	ClaimedAt  *time.Time
	ConsumedAt *time.Time
}

// IsExpired reports whether the capability is past its TTL. The TTL is a
// maximum lifetime, not a grant: callers must also re-check that the
// source session or agent is still live.
func (c *FilterCapability) IsExpired(now time.Time) bool {
	return !now.Before(c.ExpiresAt)
}

// CreateFilterCapabilityParams describes one capability to mint.
type CreateFilterCapabilityParams struct {
	Kind              FilterCapabilityKind
	VaultID           string
	PolicyVaultID     string
	ActorID           string
	SourceSessionHash string
	SourceAgentID     string
	ServiceName       string
	Bind              FilterCapabilityBind
	MatchSnapshot     string
	TTL               time.Duration
}

func newContinuationToken() string { return newPrefixedToken("av_cont_") }
func newPolicyToken() string       { return newPrefixedToken("av_pol_") }

// CreateFilterCapability mints one capability and returns the row
// alongside the raw token. The raw token is returned exactly once and is
// never persisted — only its hash is stored.
func (s *SQLStore) CreateFilterCapability(ctx context.Context, p CreateFilterCapabilityParams) (*FilterCapability, string, error) {
	switch p.Kind {
	case FilterCapContinuation, FilterCapPolicy:
	default:
		return nil, "", fmt.Errorf("store: unknown filter capability kind %q", p.Kind)
	}
	if p.VaultID == "" {
		return nil, "", fmt.Errorf("store: filter capability requires a source vault")
	}
	if p.SourceSessionHash == "" {
		return nil, "", fmt.Errorf("store: filter capability requires a source session identity")
	}
	if p.TTL <= 0 {
		return nil, "", fmt.Errorf("store: filter capability requires a positive TTL")
	}

	raw := newContinuationToken()
	if p.Kind == FilterCapPolicy {
		raw = newPolicyToken()
	}

	now := time.Now().UTC()
	fc := &FilterCapability{
		ID:                newUUID(),
		Kind:              p.Kind,
		FormatVersion:     FilterMatchSnapshotVersion,
		VaultID:           p.VaultID,
		PolicyVaultID:     p.PolicyVaultID,
		ActorID:           p.ActorID,
		SourceSessionHash: p.SourceSessionHash,
		SourceAgentID:     p.SourceAgentID,
		ServiceName:       p.ServiceName,
		Bind:              p.Bind,
		MatchSnapshot:     p.MatchSnapshot,
		IssuedAt:          now,
		ExpiresAt:         now.Add(p.TTL),
	}

	var policyVault interface{}
	if p.PolicyVaultID != "" {
		policyVault = p.PolicyVaultID
	}

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO filter_capabilities
			(id, kind, token_hash, format_version, vault_id, policy_vault_id, actor_id,
			 source_session_hash, source_agent_id, service_name,
			 bind_method, bind_scheme, bind_authority, bind_path, bind_query,
			 match_snapshot, issued_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		fc.ID, string(fc.Kind), hashToken(raw), fc.FormatVersion, fc.VaultID, policyVault, fc.ActorID,
		fc.SourceSessionHash, fc.SourceAgentID, fc.ServiceName,
		fc.Bind.Method, fc.Bind.Scheme, fc.Bind.Authority, fc.Bind.Path, fc.Bind.Query,
		fc.MatchSnapshot, s.dialect.FormatTime(fc.IssuedAt), s.dialect.FormatTime(fc.ExpiresAt),
	)
	if err != nil {
		return nil, "", fmt.Errorf("creating filter capability: %w", err)
	}
	return fc, raw, nil
}

const filterCapabilityColumns = `id, kind, format_version, vault_id, policy_vault_id, actor_id,
	source_session_hash, source_agent_id, service_name,
	bind_method, bind_scheme, bind_authority, bind_path, bind_query,
	match_snapshot, issued_at, expires_at, claimed_at, consumed_at`

func (s *SQLStore) scanFilterCapability(row interface{ Scan(...interface{}) error }) (*FilterCapability, error) {
	var (
		c           FilterCapability
		kind        string
		policyVault sql.NullString
		issuedAt    interface{}
		expiresAt   interface{}
		claimedAt   interface{}
		consumedAt  interface{}
	)
	if err := row.Scan(&c.ID, &kind, &c.FormatVersion, &c.VaultID, &policyVault, &c.ActorID,
		&c.SourceSessionHash, &c.SourceAgentID, &c.ServiceName,
		&c.Bind.Method, &c.Bind.Scheme, &c.Bind.Authority, &c.Bind.Path, &c.Bind.Query,
		&c.MatchSnapshot, &issuedAt, &expiresAt, &claimedAt, &consumedAt); err != nil {
		return nil, err
	}
	c.Kind = FilterCapabilityKind(kind)
	c.PolicyVaultID = policyVault.String

	var err error
	if c.IssuedAt, err = s.dialect.ScanTime(issuedAt); err != nil {
		return nil, fmt.Errorf("scanning issued_at: %w", err)
	}
	if c.ExpiresAt, err = s.dialect.ScanTime(expiresAt); err != nil {
		return nil, fmt.Errorf("scanning expires_at: %w", err)
	}
	if c.ClaimedAt, err = s.dialect.ScanNullableTime(claimedAt); err != nil {
		return nil, fmt.Errorf("scanning claimed_at: %w", err)
	}
	if c.ConsumedAt, err = s.dialect.ScanNullableTime(consumedAt); err != nil {
		return nil, fmt.Errorf("scanning consumed_at: %w", err)
	}
	return &c, nil
}

// GetFilterCapability looks a capability up by raw token.
//
// It deliberately does not judge expiry or consumption — callers need to
// tell those cases apart, and the policy kind is valid while unexpired
// regardless of how many times it has been used.
func (s *SQLStore) GetFilterCapability(ctx context.Context, rawToken string) (*FilterCapability, error) {
	if rawToken == "" {
		return nil, ErrFilterCapabilityNotFound
	}
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT `+filterCapabilityColumns+`
		 FROM filter_capabilities WHERE token_hash = ?`), hashToken(rawToken))
	c, err := s.scanFilterCapability(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrFilterCapabilityNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ConsumeFilterContinuation atomically claims and consumes a
// continuation for one exact request.
//
// The conditional UPDATE is the whole mechanism: only the first caller
// whose bind matches exactly, while the row is unconsumed and unexpired,
// affects a row. Every other caller — a replay, a mutated URL, a second
// replica racing the first — gets zero rows and a fail-closed error, and
// the destination credential is never resolved for them.
//
// claimed_at and consumed_at are stamped together: the 30s TTL is a
// deadline to claim, and claiming *is* consuming. Once this returns, the
// stream it authorizes runs under ordinary origin budgets, not the TTL.
func (s *SQLStore) ConsumeFilterContinuation(ctx context.Context, rawToken string, bind FilterCapabilityBind, now time.Time) (*FilterCapability, error) {
	if rawToken == "" {
		return nil, ErrFilterCapabilityNotFound
	}
	tokenHash := hashToken(rawToken)
	nowVal := s.dialect.FormatTime(now.UTC())

	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE filter_capabilities
		    SET claimed_at = ?, consumed_at = ?
		  WHERE token_hash = ?
		    AND kind = ?
		    AND consumed_at IS NULL
		    AND expires_at > ?
		    AND bind_method = ? AND bind_scheme = ? AND bind_authority = ?
		    AND bind_path = ? AND bind_query = ?`),
		nowVal, nowVal, tokenHash, string(FilterCapContinuation), nowVal,
		bind.Method, bind.Scheme, bind.Authority, bind.Path, bind.Query,
	)
	if err != nil {
		return nil, fmt.Errorf("consuming filter continuation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("consuming filter continuation: %w", err)
	}
	if n == 0 {
		// Nothing was consumed. Re-read only to report *why*; the
		// outcome is fail-closed either way.
		return nil, s.explainUnconsumed(ctx, tokenHash, bind, now)
	}

	// Safe to re-read: consumed_at is now set, so no other caller can
	// take this row out from under us.
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT `+filterCapabilityColumns+`
		 FROM filter_capabilities WHERE token_hash = ?`), tokenHash)
	c, err := s.scanFilterCapability(row)
	if err != nil {
		return nil, fmt.Errorf("reading consumed filter continuation: %w", err)
	}
	return c, nil
}

// explainUnconsumed classifies a zero-row consume so the proxy can emit
// a useful error. Ordering matters only for the message.
func (s *SQLStore) explainUnconsumed(ctx context.Context, tokenHash string, bind FilterCapabilityBind, now time.Time) error {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT `+filterCapabilityColumns+`
		 FROM filter_capabilities WHERE token_hash = ?`), tokenHash)
	c, err := s.scanFilterCapability(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFilterCapabilityNotFound
	}
	if err != nil {
		return err
	}
	switch {
	case c.Kind != FilterCapContinuation:
		return ErrFilterCapabilityKind
	case c.ConsumedAt != nil:
		return ErrFilterCapabilityConsumed
	case c.IsExpired(now):
		return ErrFilterCapabilityExpired
	case c.Bind != bind:
		return ErrFilterCapabilityBind
	default:
		// Lost a race that has since been resolved some other way.
		return ErrFilterCapabilityConsumed
	}
}

// DeleteFilterCapability removes one row by raw token. Used to drop a
// capability whose hop failed before it could ever be spent, so a
// stillborn continuation is not left sitting for its full TTL.
func (s *SQLStore) DeleteFilterCapability(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM filter_capabilities WHERE token_hash = ?`), hashToken(rawToken))
	return err
}

// DeleteExpiredFilterCapabilities sweeps rows past their TTL and returns
// how many went. Correctness never depends on the sweep — every read
// re-checks expiry — it just keeps a high-churn table from growing
// without bound.
func (s *SQLStore) DeleteExpiredFilterCapabilities(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM filter_capabilities WHERE expires_at <= ?`),
		s.dialect.FormatTime(cutoff.UTC()))
	if err != nil {
		return 0, fmt.Errorf("sweeping expired filter capabilities: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return n, nil
}

// HashSessionToken returns the sessions-table primary key for a raw
// session token.
//
// Exported so callers that must *record* a session identity — the filter
// capability rows, for revocation re-checks — can persist the hash
// without ever writing a usable bearer credential to disk. GetSession
// takes a raw token and returns it back as Session.ID, which makes the
// wrong thing look like the obvious thing; this is the right thing.
func HashSessionToken(rawToken string) string {
	return hashSessionToken(rawToken)
}

// GetSessionByHash looks a session up by its stored primary key rather
// than by the raw token, so a capability holder's source authority can be
// re-validated without the proxy ever holding that session's token.
//
// Returns sql.ErrNoRows when the session is gone — which is exactly what
// revoking an agent produces, since RevokeAgent cascades a delete over
// its sessions.
func (s *SQLStore) GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error) {
	if tokenHash == "" {
		return nil, sql.ErrNoRows
	}
	sess, err := s.scanSessionRow(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	// Session.ID normally carries the raw token back to the caller. There
	// is no raw token on this path, and handing back the hash would
	// invite it being used as one, so leave it empty.
	sess.ID = ""
	return sess, nil
}
