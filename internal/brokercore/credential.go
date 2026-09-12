package brokercore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

// UnmatchedHostPolicy controls what happens when a request's target host
// does not match any configured broker service. PolicyPassthrough is the
// system-wide default; PolicyDeny is the opt-in strict mode.
type UnmatchedHostPolicy string

const (
	PolicyPassthrough UnmatchedHostPolicy = "passthrough"
	PolicyDeny        UnmatchedHostPolicy = "deny"
)

func IsValidUnmatchedHostPolicy(p UnmatchedHostPolicy) bool {
	return p == PolicyPassthrough || p == PolicyDeny
}

// InjectResult is the outcome of matching (host, path) and resolving
// credentials to ready-to-attach HTTP headers.
type InjectResult struct {
	// Headers carries SECRET values — never log. Caller must Set (not
	// Add) so injected values win over client-supplied duplicates.
	// Nil for passthrough services.
	Headers map[string]string

	// MatchedName/Host/Path/Port describe the matched service. Safe to log.
	// Empty under unmatched-host passthrough.
	MatchedName string
	MatchedHost string
	MatchedPath string
	MatchedPort *int

	// CredentialKeys are the key names referenced by the matched
	// service. Populated before resolution so credential-missing
	// errors still carry diagnostic context. Safe to log.
	CredentialKeys []string

	// Substitutions are resolved placeholder rewrites; each entry
	// carries a SECRET Value — never log placeholder values.
	Substitutions []ResolvedSubstitution

	// Passthrough is set when no service matched but the unmatched-host
	// policy permitted forwarding.
	Passthrough bool
}

// CredentialMatch is the outcome of matching a request to a service
// *without* reading or decrypting the destination credential.
//
// It is the object a continuation capability freezes. Everything in it
// is non-secret — service identity plus credential key names — and it is
// what ResolveMatch works from, so an administrator editing the service
// during the 30-second continuation window cannot retarget which
// credential slot ends up attached.
type CredentialMatch struct {
	// Passthrough is set when no service matched but the vault's
	// unmatched-host policy permitted forwarding. Passthrough traffic is
	// never filtered and never frozen.
	Passthrough bool

	// Service is a copy of the matched service. Nil on passthrough. Held
	// by value so a later reload of the vault's service list cannot
	// alias its way into an in-flight match.
	Service *broker.Service
}

// HasFilter reports whether the matched service carries a policy hop.
func (m *CredentialMatch) HasFilter() bool {
	return m != nil && !m.Passthrough && m.Service.HasFilter()
}

// CredentialProvider resolves a service for (targetHost, targetPath) in
// vaultID and returns the headers to attach. targetPath must be the URL
// path only — no query, no fragment.
//
// Match and ResolveMatch are the two halves of Inject, split so the
// policy-filter hop can decide on a request before any destination
// secret is read. Inject remains the whole operation for the ordinary
// unfiltered path.
type CredentialProvider interface {
	Inject(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*InjectResult, error)

	// Match selects a service without touching credentials. A denied or
	// unreachable filter must leave the destination credential unread,
	// and that guarantee starts here.
	Match(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*CredentialMatch, error)

	// ResolveMatch decrypts and attaches credentials for an already
	// matched service. On the filtered path this runs only after a
	// continuation has been consumed.
	ResolveMatch(ctx context.Context, vaultID string, m *CredentialMatch) (*InjectResult, error)
}

// CredentialStore is the minimal store surface used by StoreCredentialProvider.
type CredentialStore interface {
	GetBrokerConfig(ctx context.Context, vaultID string) (*store.BrokerConfig, error)
	GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error)
	UnmatchedHostPolicy(ctx context.Context, vaultID string) (UnmatchedHostPolicy, error)
}

// OAuthStore is the store surface for OAuth token refresh.
// Passed separately to StoreCredentialProvider to keep CredentialStore minimal.
type OAuthStore interface {
	GetCredentialOAuth(ctx context.Context, vaultID, key string) (*store.CredentialOAuth, error)
	UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error
	UpdateCredentialOAuthError(ctx context.Context, vaultID, key string, errMsg string) error
}

// DynamicCredentialResolver resolves credential keys that are not stored
// statically — e.g. Infisical dynamic-secret leases minted on demand. ok=false
// means "not a dynamic credential" (the caller keeps its not-found error); a
// non-nil error is a real failure. Implemented outside brokercore (infisical)
// and injected, so brokercore takes no dependency on it.
type DynamicCredentialResolver interface {
	Resolve(ctx context.Context, vaultID, key string) (value string, ok bool, err error)
}

// StoreCredentialProvider injects credentials using a CredentialStore and a
// 32-byte AES-256-GCM key held in memory for the lifetime of the process.
type StoreCredentialProvider struct {
	Store      CredentialStore
	OAuthStore OAuthStore // nil = no OAuth refresh
	EncKey     []byte
	Refresher  *oauth.Refresher          // nil = no OAuth refresh
	Dynamic    DynamicCredentialResolver // nil = no dynamic-secret resolution
}

// NewStoreCredentialProvider constructs a provider. encKey must be 32 bytes.
func NewStoreCredentialProvider(s CredentialStore, encKey []byte) *StoreCredentialProvider {
	return &StoreCredentialProvider{Store: s, EncKey: encKey}
}

// Inject matches (targetHost, targetPath) and resolves the matched
// service's auth into HTTP headers. targetHost may include a port —
// stripped before matching. Pass "/" for targetPath when no path is
// meaningful.
//
// This is Match followed immediately by ResolveMatch: the unfiltered
// path, where there is nothing to decide before attaching credentials.
func (p *StoreCredentialProvider) Inject(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*InjectResult, error) {
	m, err := p.Match(ctx, vaultID, targetHost, targetPort, targetPath)
	if err != nil {
		return nil, err
	}
	return p.ResolveMatch(ctx, vaultID, m)
}

// Match selects the service for (targetHost, targetPath) and stops. No
// credential is read, no DEK is opened, nothing is decrypted.
func (p *StoreCredentialProvider) Match(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*CredentialMatch, error) {
	// A missing row is equivalent to an empty services list — fall
	// through to the unmatched-host policy. Any other error fails closed
	// so a transient store failure can't silently strip enforcement.
	cfg, err := p.Store.GetBrokerConfig(ctx, vaultID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrServiceNotFound
	}

	var services []broker.Service
	if cfg != nil && cfg.ServicesJSON != "" {
		if err := json.Unmarshal([]byte(cfg.ServicesJSON), &services); err != nil {
			return nil, fmt.Errorf("brokercore: parsing broker services: %w", err)
		}
	}
	// MarshalJSON persists Host in joined-inline form; the matcher
	// requires Host without "/", so split before matching.
	for i := range services {
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	// Heal legacy unnamed entries so MatchedName (which lands in the
	// request log and the X-Vault-Service header) is never blank for a
	// matched service — the documented `?service=<name>` log filter
	// depends on it.
	broker.AssignSlugNames(services)

	matchHost := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		matchHost = h
	}
	if targetPath == "" {
		targetPath = "/"
	}
	matched, score := broker.MatchService(matchHost, targetPort, targetPath, services)
	if matched == nil {
		// Fail closed on policy lookup errors so a transient store
		// failure can't silently strip enforcement.
		policy, err := p.Store.UnmatchedHostPolicy(ctx, vaultID)
		if err != nil || policy == PolicyDeny {
			return nil, ErrServiceNotFound
		}
		return &CredentialMatch{Passthrough: true}, nil
	}
	if !matched.IsEnabled() {
		return nil, ErrServiceDisabled
	}
	slog.Default().Debug("broker matched",
		slog.String("vault", vaultID),
		slog.String("service", matched.Name),
		slog.String("host", matched.Host),
		slog.String("path", matched.Path),
		slog.String("host_tier", score.HostTierName()),
		slog.Int("path_prefix_len", score.PathLiteralLen),
		slog.Int("decl_order", score.DeclOrder),
	)

	// Copy out of the slice: `services` is re-read from the store on
	// every call, and a match may outlive this one when it is frozen
	// into a continuation.
	svc := *matched
	return &CredentialMatch{Service: &svc}, nil
}

// ResolveMatch decrypts the matched service's credentials and builds the
// headers to attach. On the filtered path this is reached only after a
// continuation capability has been consumed, so a denied or unreachable
// filter performs zero credential reads.
//
// Credential *values* are deliberately not frozen: a rotation applied
// during the continuation window attaches the new secret for the same
// frozen key name.
func (p *StoreCredentialProvider) ResolveMatch(ctx context.Context, vaultID string, m *CredentialMatch) (*InjectResult, error) {
	if m == nil {
		return nil, ErrServiceNotFound
	}
	if m.Passthrough {
		return &InjectResult{Passthrough: true}, nil
	}
	if m.Service == nil {
		return nil, ErrServiceNotFound
	}
	matched := m.Service

	// Memoize per-key lookups so a credential shared by auth and a
	// substitution decrypts only once.
	cache := make(map[string]string)
	getCredential := func(key string) (string, error) {
		if v, ok := cache[key]; ok {
			return v, nil
		}
		cred, err := p.Store.GetCredential(ctx, vaultID, key)
		if err != nil || cred == nil {
			// No static credential: try resolving it as a dynamic-secret field.
			if p.Dynamic != nil {
				if val, ok, derr := p.Dynamic.Resolve(ctx, vaultID, key); derr != nil {
					return "", derr
				} else if ok {
					cache[key] = val
					return val, nil
				}
			}
			return "", fmt.Errorf("credential %q not found", key)
		}

		plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, p.EncKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt credential %q", key)
		}
		s := string(plaintext)

		if cred.Type == "oauth" && s == "" {
			return "", fmt.Errorf("%w: credential %q", ErrOAuthNotConnected, key)
		}

		if cred.Type == "oauth" && p.Refresher != nil && p.OAuthStore != nil {
			s, err = p.maybeRefreshOAuth(ctx, vaultID, key, s)
			if err != nil {
				return "", err
			}
		}

		cache[key] = s
		return s, nil
	}

	// Capture non-secret metadata up front so a downstream credential-missing
	// error still carries it for diagnostic logging.
	result := &InjectResult{
		MatchedName:    matched.Name,
		MatchedHost:    matched.Host,
		MatchedPath:    matched.Path,
		MatchedPort:    matched.Port,
		CredentialKeys: matched.CredentialKeys(),
	}

	// Resolve substitutions before auth so passthrough services (which
	// skip the auth branch) still surface ErrCredentialMissing here.
	// Hold locally and attach only on success — error returns must not
	// expose resolved secret values via result.
	var resolvedSubs []ResolvedSubstitution
	if len(matched.Substitutions) > 0 {
		resolvedSubs = make([]ResolvedSubstitution, 0, len(matched.Substitutions))
		for _, sub := range matched.Substitutions {
			val, err := getCredential(sub.Key)
			if err != nil {
				return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
			}
			resolvedSubs = append(resolvedSubs, ResolvedSubstitution{
				Placeholder: sub.Placeholder,
				Value:       val,
				In:          sub.NormalizedIn(),
			})
		}
	}

	if matched.Auth.Type == "passthrough" {
		result.Substitutions = resolvedSubs
		return result, nil
	}

	headers, err := matched.Auth.Resolve(getCredential)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
	}

	result.Headers = headers
	result.Substitutions = resolvedSubs
	return result, nil
}

const oauthRefreshBuffer = 5 * time.Minute

func (p *StoreCredentialProvider) maybeRefreshOAuth(ctx context.Context, vaultID, key, currentToken string) (string, error) {
	oauthCfg, err := p.OAuthStore.GetCredentialOAuth(ctx, vaultID, key)
	if err != nil {
		return currentToken, nil
	}

	if oauthCfg.TokenExpiresAt == nil {
		return currentToken, nil
	}
	if time.Until(*oauthCfg.TokenExpiresAt) > oauthRefreshBuffer {
		return currentToken, nil
	}

	if len(oauthCfg.RefreshTokenCT) == 0 {
		return currentToken, nil
	}

	sfKey := vaultID + "|" + key
	result := p.Refresher.Do(sfKey, func() oauth.RefreshResult {
		refreshToken, err := crypto.Decrypt(oauthCfg.RefreshTokenCT, oauthCfg.RefreshTokenNonce, p.EncKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: decrypt refresh token: %v", ErrOAuthRefreshFailed, err)}
		}

		var clientSecret string
		if len(oauthCfg.ClientSecretCT) > 0 {
			cs, err := crypto.Decrypt(oauthCfg.ClientSecretCT, oauthCfg.ClientSecretNonce, p.EncKey)
			if err != nil {
				return oauth.RefreshResult{Err: fmt.Errorf("%w: decrypt client secret: %v", ErrOAuthRefreshFailed, err)}
			}
			clientSecret = string(cs)
		}

		tok, err := oauth.Refresh(ctx, oauth.RefreshConfig{
			TokenURL:        oauthCfg.TokenURL,
			ClientID:        oauthCfg.ClientID,
			ClientSecret:    clientSecret,
			RefreshToken:    string(refreshToken),
			Scopes:          oauthCfg.Scopes,
			ScopeSeparator:  oauthCfg.ScopeSeparator,
			TokenAuthMethod: oauthCfg.TokenAuthMethod,
		})
		if err != nil {
			_ = p.OAuthStore.UpdateCredentialOAuthError(ctx, vaultID, key, err.Error())
			return oauth.RefreshResult{Err: fmt.Errorf("%w: %v", ErrOAuthRefreshFailed, err)}
		}

		accessCT, accessNonce, err := crypto.Encrypt([]byte(tok.AccessToken), p.EncKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: encrypt access token: %v", ErrOAuthRefreshFailed, err)}
		}

		var newRefreshCT, newRefreshNonce []byte
		if tok.RefreshToken != "" {
			newRefreshCT, newRefreshNonce, err = crypto.Encrypt([]byte(tok.RefreshToken), p.EncKey)
			if err != nil {
				return oauth.RefreshResult{Err: fmt.Errorf("%w: encrypt refresh token: %v", ErrOAuthRefreshFailed, err)}
			}
		}

		var expiresAt *time.Time
		if !tok.ExpiresAt.IsZero() {
			expiresAt = &tok.ExpiresAt
		}

		if err := p.OAuthStore.UpdateCredentialOAuthTokens(ctx, vaultID, key, accessCT, accessNonce, newRefreshCT, newRefreshNonce, expiresAt); err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: store tokens: %v", ErrOAuthRefreshFailed, err)}
		}

		return oauth.RefreshResult{AccessToken: tok.AccessToken, Refreshed: true}
	})

	if result.Err != nil {
		return "", result.Err
	}
	if result.Refreshed {
		return result.AccessToken, nil
	}
	return currentToken, nil
}
