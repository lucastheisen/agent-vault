package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type filterCapabilityFixture struct {
	store         *SQLStore
	vaultID       string
	sourceToken   string
	sourceHash    string
	sourceActorID string
	expiresAt     time.Time
}

func newFilterCapabilityFixture(t *testing.T) filterCapabilityFixture {
	t.Helper()
	s := openTestDB(t)
	ctx := context.Background()
	vault, err := s.GetVault(ctx, DefaultVault)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	actorID := "filter-user"
	if _, err := s.db.ExecContext(ctx, `INSERT INTO users
		(id, email, password_hash, password_salt, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'member', 1, ?, ?)`, actorID, "filter@example.test", []byte("hash"), []byte("salt"),
		now.Format(time.DateTime), now.Format(time.DateTime)); err != nil {
		t.Fatalf("insert source user: %v", err)
	}
	if err := s.GrantVaultRole(ctx, actorID, "user", vault.ID, "proxy"); err != nil {
		t.Fatalf("grant source vault: %v", err)
	}
	sourceToken := "av_sess_filter-source"
	sourceHash := hashSessionToken(sourceToken)
	sessionExpiry := now.Add(10 * time.Minute)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sessions
		(id, user_id, expires_at, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?)`, sourceHash, actorID, sessionExpiry.Format(time.DateTime),
		now.Format(time.DateTime), now.Format(time.DateTime)); err != nil {
		t.Fatalf("insert source session: %v", err)
	}
	return filterCapabilityFixture{
		store: s, vaultID: vault.ID, sourceToken: sourceToken, sourceHash: sourceHash,
		sourceActorID: actorID, expiresAt: now.Add(time.Minute),
	}
}

func (f filterCapabilityFixture) continuation() *FilterCapability {
	return &FilterCapability{
		Kind:          FilterCapabilityContinuation,
		SourceVaultID: f.vaultID, SourceSessionHash: f.sourceHash,
		SourceActorID: f.sourceActorID, SourceActorType: "user",
		TargetVaultID: f.vaultID, TargetVaultName: DefaultVault, TargetVaultRole: "proxy",
		Request: FilterRequestBinding{
			Method: "POST", Scheme: "https", Authority: "github.com:443",
			Path: "/acme/repo.git/git-receive-pack", Query: "service=git-receive-pack",
		},
		SnapshotVersion: 1,
		SnapshotJSON:    []byte(`{"service":{"name":"github-push"},"credential_keys":["GITHUB_TOKEN"]}`),
		ExpiresAt:       f.expiresAt,
	}
}

func (f filterCapabilityFixture) policy() *FilterCapability {
	return &FilterCapability{
		Kind:          FilterCapabilityPolicy,
		SourceVaultID: f.vaultID, SourceSessionHash: f.sourceHash,
		SourceActorID: f.sourceActorID, SourceActorType: "user",
		TargetVaultID: f.vaultID, TargetVaultName: DefaultVault, TargetVaultRole: "proxy",
		ExpiresAt: f.expiresAt,
	}
}

func TestFilterContinuationStoredHashedClaimedAndConsumedOnce(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	capability := f.continuation()
	rawToken, err := f.store.CreateFilterCapability(ctx, capability)
	if err != nil {
		t.Fatalf("CreateFilterCapability: %v", err)
	}
	if !strings.HasPrefix(rawToken, FilterCapabilityTokenPrefix) {
		t.Fatalf("token %q has no capability prefix", rawToken)
	}
	var storedHash string
	if err := f.store.db.QueryRow("SELECT token_hash FROM filter_capabilities").Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != hashToken(rawToken) || storedHash == rawToken {
		t.Fatalf("stored token identifier is not the expected one-way hash")
	}
	var rawCount int
	if err := f.store.db.QueryRow(`SELECT COUNT(*) FROM filter_capabilities
		WHERE snapshot_json LIKE ?`, "%"+rawToken+"%").Scan(&rawCount); err != nil {
		t.Fatal(err)
	}
	if rawCount != 0 {
		t.Fatal("raw capability token leaked into persisted payload")
	}

	now := time.Now().UTC()
	claimed, err := f.store.ResolveFilterCapability(ctx, rawToken, capability.Request.Authority, now)
	if err != nil {
		t.Fatalf("ResolveFilterCapability: %v", err)
	}
	if claimed.State != FilterCapabilityClaimed || claimed.ClaimedAt == nil {
		t.Fatalf("unexpected claimed record: %+v", claimed)
	}
	consumed, err := f.store.ConsumeFilterContinuation(ctx, rawToken, capability.Request, now.Add(time.Second))
	if err != nil {
		t.Fatalf("ConsumeFilterContinuation: %v", err)
	}
	if consumed.State != FilterCapabilityConsumed || consumed.ConsumedAt == nil || string(consumed.SnapshotJSON) != string(capability.SnapshotJSON) {
		t.Fatalf("unexpected consumed record: %+v", consumed)
	}
	if _, err := f.store.ConsumeFilterContinuation(ctx, rawToken, capability.Request, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("replay error = %v, want ErrInvalidFilterCapability", err)
	}
}

func TestFilterContinuationWrongRequestBurnsCapability(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	capability := f.continuation()
	rawToken, err := f.store.CreateFilterCapability(ctx, capability)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := f.store.ResolveFilterCapability(ctx, rawToken, capability.Request.Authority, now); err != nil {
		t.Fatal(err)
	}
	wrong := capability.Request
	wrong.Path = "/different"
	if _, err := f.store.ConsumeFilterContinuation(ctx, rawToken, wrong, now); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("wrong binding error = %v", err)
	}
	if _, err := f.store.ConsumeFilterContinuation(ctx, rawToken, capability.Request, now); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("correct retry after mismatch error = %v", err)
	}
}

func TestFilterContinuationWrongAuthorityBurnsCapability(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	capability := f.continuation()
	rawToken, err := f.store.CreateFilterCapability(ctx, capability)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := f.store.ResolveFilterCapability(ctx, rawToken, "evil.example:443", now); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("wrong authority error = %v", err)
	}
	if _, err := f.store.ResolveFilterCapability(ctx, rawToken, capability.Request.Authority, now); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("correct retry after authority mismatch error = %v", err)
	}
}

func TestFilterContinuationClaimIsAtomic(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	capability := f.continuation()
	rawToken, err := f.store.CreateFilterCapability(ctx, capability)
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := f.store.ResolveFilterCapability(ctx, rawToken, capability.Request.Authority, time.Now().UTC()); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if !errors.Is(err, ErrInvalidFilterCapability) {
				t.Errorf("unexpected claim error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful claims = %d, want 1", successes)
	}
}

func TestFilterPolicyReusableButSourceAuthorityIsRechecked(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	rawToken, err := f.store.CreateFilterCapability(ctx, f.policy())
	if err != nil {
		t.Fatalf("CreateFilterCapability(policy): %v", err)
	}
	for i := 0; i < 2; i++ {
		got, err := f.store.ValidateFilterPolicyCapability(ctx, rawToken, time.Now().UTC())
		if err != nil {
			t.Fatalf("policy validation %d: %v", i, err)
		}
		if got.Kind != FilterCapabilityPolicy || got.State != FilterCapabilityIssued {
			t.Fatalf("unexpected policy state: %+v", got)
		}
	}
	if err := f.store.RevokeVaultAccess(ctx, f.sourceActorID, f.vaultID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantVaultRole(ctx, f.sourceActorID, "user", f.vaultID, "proxy"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ValidateFilterPolicyCapability(ctx, rawToken, time.Now().UTC()); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("capability revived after revoke and immediate re-grant: %v", err)
	}
}

func TestFilterPolicyInvalidAfterAgentRevocation(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	agent, session, err := f.store.CreateAgentWithGrantsAndToken(ctx, "filter-agent", "owner", "member", []AgentVaultGrantSpec{{VaultID: f.vaultID, Role: "proxy"}}, nil)
	if err != nil {
		t.Fatalf("CreateAgentWithGrantsAndToken: %v", err)
	}
	capability := f.policy()
	capability.SourceSessionHash = hashSessionToken(session.ID)
	capability.SourceActorID = agent.ID
	capability.SourceActorType = "agent"
	capability.SourceAgentID = agent.ID
	rawToken, err := f.store.CreateFilterCapability(ctx, capability)
	if err != nil {
		t.Fatalf("CreateFilterCapability: %v", err)
	}
	if err := f.store.RevokeAgent(ctx, agent.ID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if _, err := f.store.ValidateFilterPolicyCapability(ctx, rawToken, time.Now().UTC()); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("validation after agent revocation = %v", err)
	}
}

func TestFilterContinuationInvalidAfterAgentRevocationBetweenClaimAndConsume(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	agent, session, err := f.store.CreateAgentWithGrantsAndToken(ctx, "continuation-agent", "owner", "member", []AgentVaultGrantSpec{{VaultID: f.vaultID, Role: "proxy"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	capability := f.continuation()
	capability.SourceSessionHash = hashSessionToken(session.ID)
	capability.SourceActorID = agent.ID
	capability.SourceActorType = "agent"
	capability.SourceAgentID = agent.ID
	rawToken, err := f.store.CreateFilterCapability(ctx, capability)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ResolveFilterCapability(ctx, rawToken, capability.Request.Authority, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeAgent(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ConsumeFilterContinuation(ctx, rawToken, capability.Request, time.Now().UTC()); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("consume after revoke error = %v", err)
	}
}

func TestFilterPolicySupportsScopedSessionCreatorAndRechecksGrant(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	session, err := f.store.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID: f.vaultID, VaultRole: "proxy", ExpiresAt: &f.expiresAt,
		CreatedByActorID: f.sourceActorID, CreatedByActorType: "user",
	})
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}
	capability := f.policy()
	capability.SourceSessionHash = hashSessionToken(session.ID)
	rawToken, err := f.store.CreateFilterCapability(ctx, capability)
	if err != nil {
		t.Fatalf("CreateFilterCapability: %v", err)
	}
	if _, err := f.store.ValidateFilterPolicyCapability(ctx, rawToken, time.Now().UTC()); err != nil {
		t.Fatalf("scoped policy validation: %v", err)
	}
	if err := f.store.RevokeVaultAccess(ctx, f.sourceActorID, f.vaultID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ValidateFilterPolicyCapability(ctx, rawToken, time.Now().UTC()); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("scoped policy after creator grant revocation = %v", err)
	}
}

func TestFilterCapabilitySourceSessionDeletionCascades(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	rawToken, err := f.store.CreateFilterCapability(ctx, f.policy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec("DELETE FROM sessions WHERE id = ?", f.sourceHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ValidateFilterPolicyCapability(ctx, rawToken, time.Now().UTC()); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("validation after session deletion = %v", err)
	}
	var count int
	if err := f.store.db.QueryRow("SELECT COUNT(*) FROM filter_capabilities").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("capability rows after session deletion = %d, want 0", count)
	}
}

func TestFilterCapabilityExpiryAndSweep(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	ctx := context.Background()
	rawToken, err := f.store.CreateFilterCapability(ctx, f.policy())
	if err != nil {
		t.Fatal(err)
	}
	afterExpiry := f.expiresAt.Add(time.Second)
	if _, err := f.store.ValidateFilterPolicyCapability(ctx, rawToken, afterExpiry); !errors.Is(err, ErrInvalidFilterCapability) {
		t.Fatalf("expired validation = %v", err)
	}
	n, err := f.store.DeleteExpiredFilterCapabilities(ctx, afterExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted rows = %d, want 1", n)
	}
}

func TestFilterCapabilityRejectsMissingContinuationSnapshot(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	capability := f.continuation()
	capability.SnapshotVersion = 0
	capability.SnapshotJSON = nil
	if _, err := f.store.CreateFilterCapability(context.Background(), capability); err == nil {
		t.Fatal("expected missing frozen snapshot to be rejected")
	}
}

func TestFilterCapabilityUnknownTokenUsesUniformError(t *testing.T) {
	f := newFilterCapabilityFixture(t)
	_, err := f.store.ValidateFilterPolicyCapability(context.Background(), "not-a-token", time.Now().UTC())
	if !errors.Is(err, ErrInvalidFilterCapability) || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("error = %v, want only ErrInvalidFilterCapability", err)
	}
}
