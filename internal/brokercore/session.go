package brokercore

import (
	"context"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// DefaultMaxRequestBytes is the default cap for request bodies forwarded
// on the MITM proxy ingress. Distinct from the generic 1 MB limitBody
// wrapper used on control-plane endpoints.
const DefaultMaxRequestBytes int64 = 1 << 30 // 1 GiB

// MaxMaterializeBytes caps request bodies that must be buffered in RAM
// for body-surface substitutions. Kept small because body substitutions
// target API payloads (JSON, form-encoded), not large file uploads.
const MaxMaterializeBytes int64 = 64 << 20 // 64 MiB

// ProxyScope is the resolved identity + vault context for a proxy request.
// It is produced once per CONNECT on the MITM ingress and carried through
// to credential injection.
type ProxyScope struct {
	AgentID   string // non-empty for agent tokens
	UserID    string // non-empty for user sessions
	VaultID   string
	VaultName string
	VaultRole string

	// SessionHash is the sessions-table primary key for the session that
	// authenticated this request: the SHA-256 of its bearer token, never
	// the token itself.
	//
	// Filter capabilities record it so revoking the session — or the
	// agent, which cascades a session delete — invalidates outstanding
	// capabilities immediately instead of leaving up to a full TTL of
	// usable authority behind. Anything persisting an identity from this
	// scope must use this field; store.Session.ID carries the raw token
	// back to its caller and is not safe to write down.
	SessionHash string
}

// ActorID returns the non-empty principal ID — UserID for user
// sessions, AgentID for agent tokens. Used as the actor dimension in
// per-scope rate-limit keys.
func (s *ProxyScope) ActorID() string {
	if s.UserID != "" {
		return s.UserID
	}
	return s.AgentID
}

// SessionResolver collapses bearer-token validation and vault selection
// into one call. The MITM ingress passes a vault hint parsed from
// Proxy-Authorization. An empty hint means "infer from session".
type SessionResolver interface {
	ResolveForProxy(ctx context.Context, token, vaultHint string) (*ProxyScope, error)
}

// SessionStore is the minimal store surface used by StoreSessionResolver.
// Kept narrow so tests can supply fakes without stubbing the full store.
type SessionStore interface {
	GetSession(ctx context.Context, rawToken string) (*store.Session, error)
	// GetSessionByHash re-reads a session from the identity a capability
	// recorded, without needing (or being given) the raw token.
	GetSessionByHash(ctx context.Context, tokenHash string) (*store.Session, error)
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultByID(ctx context.Context, id string) (*store.Vault, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	ListActorGrants(ctx context.Context, actorID string) ([]store.VaultGrant, error)
}

// StoreSessionResolver resolves sessions through a SessionStore. Now is
// injectable so tests can control expiry without wall-clock flake.
type StoreSessionResolver struct {
	Store SessionStore
	Now   func() time.Time
}

// NewStoreSessionResolver constructs a resolver backed by s. If s is nil
// the returned resolver will panic on use; the constructor is permissive
// to match existing server construction patterns.
func NewStoreSessionResolver(s SessionStore) *StoreSessionResolver {
	return &StoreSessionResolver{Store: s, Now: time.Now}
}

// ResolveForProxy validates token, applies the vault hint, and returns a
// ProxyScope. See the sentinel errors in errors.go for the full taxonomy.
func (r *StoreSessionResolver) ResolveForProxy(ctx context.Context, token, vaultHint string) (*ProxyScope, error) {
	if token == "" {
		return nil, ErrInvalidSession
	}
	sess, err := r.Store.GetSession(ctx, token)
	if err != nil || sess == nil {
		return nil, ErrInvalidSession
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	if sess.IsExpired(now()) {
		return nil, ErrInvalidSession
	}

	// Scoped session: vault is baked into the session. A hint must match
	// the session's vault name; never silently retarget.
	if sess.VaultID != "" {
		v, err := r.Store.GetVaultByID(ctx, sess.VaultID)
		if err != nil || v == nil {
			return nil, ErrVaultNotFound
		}
		if vaultHint != "" && vaultHint != v.Name {
			return nil, ErrVaultHintMismatch
		}
		return &ProxyScope{
			UserID:      sess.UserID,
			AgentID:     sess.AgentID,
			VaultID:     v.ID,
			VaultName:   v.Name,
			VaultRole:   sess.VaultRole,
			SessionHash: store.HashSessionToken(token),
		}, nil
	}

	// Instance-level agent token: resolve vault from hint, or from the
	// agent's unique grant if any.
	if sess.AgentID == "" {
		return nil, ErrNoVaultContext
	}

	if vaultHint != "" {
		v, err := r.Store.GetVault(ctx, vaultHint)
		if err != nil || v == nil {
			return nil, ErrVaultNotFound
		}
		role, err := r.Store.GetVaultRole(ctx, sess.AgentID, v.ID)
		if err != nil || role == "" {
			return nil, ErrVaultAccessDenied
		}
		return &ProxyScope{
			AgentID:     sess.AgentID,
			VaultID:     v.ID,
			VaultName:   v.Name,
			VaultRole:   role,
			SessionHash: store.HashSessionToken(token),
		}, nil
	}

	grants, err := r.Store.ListActorGrants(ctx, sess.AgentID)
	if err != nil {
		return nil, ErrNoVaultContext
	}
	switch len(grants) {
	case 0:
		return nil, ErrNoVaultContext
	case 1:
		g := grants[0]
		return &ProxyScope{
			AgentID:     sess.AgentID,
			VaultID:     g.VaultID,
			VaultName:   g.VaultName,
			VaultRole:   g.Role,
			SessionHash: store.HashSessionToken(token),
		}, nil
	default:
		return nil, ErrAgentVaultAmbiguous
	}
}

// SourceAuthority identifies the session a filter capability was minted
// from, so it can be re-validated later.
type SourceAuthority struct {
	// SessionHash is the sessions primary key. Required.
	SessionHash string
	// ActorID is the initiating principal, used for the vault-grant
	// check. AgentID is set when that principal was an agent.
	ActorID string
	AgentID string
	// VaultID is the source vault the capability must still be
	// authorized for.
	VaultID string
}

// SourceAuthorityChecker re-validates that a capability's originating
// authority is still live.
//
// Thirty seconds is a maximum capability lifetime, not a grace period
// after revocation: a capability whose source session or agent has been
// revoked, expired, or removed must fail closed even with TTL left.
type SourceAuthorityChecker interface {
	CheckSourceAuthority(ctx context.Context, a SourceAuthority) error
}

// CheckSourceAuthority reports whether the session behind a capability
// is still live and still granted on the source vault.
//
// One session read covers more than it looks like: revoking an agent
// cascades a delete over its sessions, and both agent tokens and user
// sessions share the same expiry rules, so a present, unexpired row plus
// a surviving vault grant is the whole check.
func (r *StoreSessionResolver) CheckSourceAuthority(ctx context.Context, a SourceAuthority) error {
	if a.SessionHash == "" {
		return ErrInvalidSession
	}
	sess, err := r.Store.GetSessionByHash(ctx, a.SessionHash)
	if err != nil || sess == nil {
		return ErrInvalidSession
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	if sess.IsExpired(now()) {
		return ErrInvalidSession
	}
	// The session must still belong to the principal the capability was
	// issued to; a reused hash pointing at someone else is not the same
	// authority.
	if a.AgentID != "" && sess.AgentID != a.AgentID {
		return ErrInvalidSession
	}

	// A vault-scoped session carries its grant inline. An instance-level
	// token is re-checked against the grants table so revoking the grant
	// alone is enough to kill the capability.
	if sess.VaultID != "" {
		if sess.VaultID != a.VaultID {
			return ErrVaultAccessDenied
		}
		return nil
	}
	actorID := a.ActorID
	if actorID == "" {
		actorID = sess.AgentID
	}
	if actorID == "" {
		return ErrInvalidSession
	}
	role, err := r.Store.GetVaultRole(ctx, actorID, a.VaultID)
	if err != nil || role == "" {
		return ErrVaultAccessDenied
	}
	return nil
}
