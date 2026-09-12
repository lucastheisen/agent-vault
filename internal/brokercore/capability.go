package brokercore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
)

const (
	ContinuationTokenPrefix = "av_cont_"
	PolicyTokenPrefix       = "av_pol_"
	capabilityTTL           = 30 * time.Second
	matchSnapshotVersion    = 1
)

// CapabilityKind is stored on the capability row.
type CapabilityKind string

const (
	CapContinuation CapabilityKind = "continuation"
	CapPolicy       CapabilityKind = "policy"
)

// MatchSnapshot is the versioned, non-secret frozen match persisted on
// a continuation row. Never contains credential values.
type MatchSnapshot struct {
	Version       int                   `json:"v"`
	ServiceName   string                `json:"name"`
	Host          string                `json:"host"`
	Path          string                `json:"path"`
	Port          *int                  `json:"port,omitempty"`
	Auth          broker.Auth           `json:"auth"`
	Substitutions []broker.Substitution `json:"substitutions,omitempty"`
}

// Capability is a looked-up row (no raw token).
type Capability struct {
	Kind            CapabilityKind
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
	Snapshot        MatchSnapshot
	TokenHash       string
	ExpiresAt       time.Time
	Consumed        bool
}

// RequestBind is the exact-URL binding for a continuation.
type RequestBind struct {
	Method      string
	Scheme      string
	Authority   string
	EscapedPath string
	Query       string
}

func BindFromURL(method string, u *url.URL) RequestBind {
	path := u.EscapedPath()
	if path == "" {
		path = u.Path
	}
	return RequestBind{
		Method:      method,
		Scheme:      strings.ToLower(u.Scheme),
		Authority:   strings.ToLower(u.Host),
		EscapedPath: path,
		Query:       u.RawQuery,
	}
}

func (c *Capability) BindMatches(method, host, path, rawQuery, scheme string) bool {
	if c == nil {
		return false
	}
	if !strings.EqualFold(c.Method, method) {
		return false
	}
	if !strings.EqualFold(c.Scheme, scheme) {
		return false
	}
	if !strings.EqualFold(c.Authority, host) {
		return false
	}
	if c.EscapedPath != path {
		return false
	}
	return c.Query == rawQuery
}

func (c *Capability) Scope() *ProxyScope {
	vaultID := c.SourceVaultID
	vaultName := c.VaultName
	if c.Kind == CapPolicy && c.PolicyVaultID != "" {
		vaultID = c.PolicyVaultID
		if c.PolicyVaultName != "" {
			vaultName = c.PolicyVaultName
		}
	}
	scope := &ProxyScope{
		UserID:        c.ActorUserID,
		AgentID:       c.ActorAgentID,
		VaultID:       vaultID,
		VaultName:     vaultName,
		VaultRole:     c.VaultRole,
		SkipFilter:    c.Kind == CapContinuation,
		IsPolicy:      c.Kind == CapPolicy,
		SourceSessID:  c.SourceSessID,
		SourceAgentID: c.ActorAgentID,
	}
	if c.Kind == CapContinuation {
		scope.Continuation = c
	}
	return scope
}

// SourceChecker re-validates the inbound session/agent and source-vault
// grant. Return an error to fail closed (revoked/expired/missing).
type SourceChecker func(ctx context.Context, c *Capability) error

// CapabilityStore issues and consumes filter capabilities.
type CapabilityStore interface {
	IssueContinuation(ctx context.Context, rec Capability) (rawToken string, err error)
	IssuePolicy(ctx context.Context, rec Capability) (rawToken string, err error)
	Authenticate(ctx context.Context, rawToken string) (*Capability, error)
	ConsumeContinuation(ctx context.Context, rawToken string) (*Capability, error)
}

// MemoryCapabilities is the single-instance / test backend. Semantics
// match the shared-store contract (hash, TTL, single-use consume).
type MemoryCapabilities struct {
	mu     sync.Mutex
	byHash map[string]*Capability
	Now    func() time.Time
	Check  SourceChecker
	TTL    time.Duration
}

func NewMemoryCapabilities() *MemoryCapabilities {
	return &MemoryCapabilities{byHash: make(map[string]*Capability)}
}

func (m *MemoryCapabilities) now() time.Time {
	if m != nil && m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *MemoryCapabilities) ttl() time.Duration {
	if m != nil && m.TTL > 0 {
		return m.TTL
	}
	return capabilityTTL
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken(prefix string) (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func (m *MemoryCapabilities) issue(kind CapabilityKind, prefix string, rec Capability) (string, error) {
	raw, err := randomToken(prefix)
	if err != nil {
		return "", err
	}
	rec.Kind = kind
	rec.TokenHash = hashToken(raw)
	rec.ExpiresAt = m.now().Add(m.ttl())
	rec.Consumed = false
	if rec.Snapshot.Version == 0 {
		rec.Snapshot.Version = matchSnapshotVersion
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byHash == nil {
		m.byHash = make(map[string]*Capability)
	}
	cp := rec
	m.byHash[rec.TokenHash] = &cp
	return raw, nil
}

func (m *MemoryCapabilities) IssueContinuation(_ context.Context, rec Capability) (string, error) {
	return m.issue(CapContinuation, ContinuationTokenPrefix, rec)
}

func (m *MemoryCapabilities) IssuePolicy(_ context.Context, rec Capability) (string, error) {
	return m.issue(CapPolicy, PolicyTokenPrefix, rec)
}

func (m *MemoryCapabilities) lookup(ctx context.Context, rawToken string, consume bool) (*Capability, error) {
	if rawToken == "" {
		return nil, ErrInvalidSession
	}
	h := hashToken(rawToken)
	m.mu.Lock()
	c, ok := m.byHash[h]
	if !ok {
		m.mu.Unlock()
		return nil, ErrInvalidSession
	}
	if m.now().After(c.ExpiresAt) {
		delete(m.byHash, h)
		m.mu.Unlock()
		return nil, ErrInvalidSession
	}
	if c.Kind == CapContinuation && c.Consumed {
		m.mu.Unlock()
		return nil, ErrInvalidSession
	}
	if consume {
		if c.Kind != CapContinuation {
			m.mu.Unlock()
			return nil, ErrInvalidSession
		}
		c.Consumed = true
	}
	cp := *c
	m.mu.Unlock()

	if m.Check != nil {
		if err := m.Check(ctx, &cp); err != nil {
			return nil, ErrInvalidSession
		}
	}
	if consume && cp.Snapshot.Version != matchSnapshotVersion {
		return nil, ErrInvalidSession
	}
	return &cp, nil
}

func (m *MemoryCapabilities) Authenticate(ctx context.Context, rawToken string) (*Capability, error) {
	return m.lookup(ctx, rawToken, false)
}

func (m *MemoryCapabilities) ConsumeContinuation(ctx context.Context, rawToken string) (*Capability, error) {
	return m.lookup(ctx, rawToken, true)
}

// SnapshotFromService builds a non-secret match snapshot (key names only).
func SnapshotFromService(svc *broker.Service) MatchSnapshot {
	if svc == nil {
		return MatchSnapshot{Version: matchSnapshotVersion}
	}
	auth := svc.Auth
	subs := append([]broker.Substitution(nil), svc.Substitutions...)
	return MatchSnapshot{
		Version:       matchSnapshotVersion,
		ServiceName:   svc.Name,
		Host:          svc.Host,
		Path:          svc.Path,
		Port:          svc.Port,
		Auth:          auth,
		Substitutions: subs,
	}
}

func (s MatchSnapshot) Service() broker.Service {
	return broker.Service{
		Name:          s.ServiceName,
		Host:          s.Host,
		Path:          s.Path,
		Port:          s.Port,
		Auth:          s.Auth,
		Substitutions: s.Substitutions,
	}
}

func (s MatchSnapshot) Marshal() ([]byte, error) { return json.Marshal(s) }

func ParseMatchSnapshot(raw []byte) (MatchSnapshot, error) {
	var s MatchSnapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return MatchSnapshot{}, err
	}
	if s.Version != matchSnapshotVersion {
		return MatchSnapshot{}, ErrInvalidSession
	}
	return s, nil
}

func IsCapabilityToken(token string) bool {
	return strings.HasPrefix(token, ContinuationTokenPrefix) || strings.HasPrefix(token, PolicyTokenPrefix)
}
