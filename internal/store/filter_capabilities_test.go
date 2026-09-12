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

func testBind() FilterCapabilityBind {
	return FilterCapabilityBind{
		Method:    "POST",
		Scheme:    "https",
		Authority: "github.com",
		Path:      "/acme/app.git/git-receive-pack",
		Query:     "",
	}
}

func mintContinuation(t *testing.T, s *SQLStore, vaultID string) (*FilterCapability, string) {
	t.Helper()
	fc, raw, err := s.CreateFilterCapability(context.Background(), CreateFilterCapabilityParams{
		Kind:              FilterCapContinuation,
		VaultID:           vaultID,
		ActorID:           "actor-1",
		SourceSessionHash: "sess-hash-1",
		SourceAgentID:     "agent-1",
		ServiceName:       "github-push",
		Bind:              testBind(),
		MatchSnapshot:     `{"version":1,"service":{"name":"github-push"}}`,
		TTL:               30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateFilterCapability: %v", err)
	}
	return fc, raw
}

func TestFilterCapabilityRoundTrip(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-roundtrip")

	fc, raw, err := s.CreateFilterCapability(ctx, CreateFilterCapabilityParams{
		Kind:              FilterCapPolicy,
		VaultID:           ns.ID,
		PolicyVaultID:     ns.ID,
		ActorID:           "actor-1",
		SourceSessionHash: "sess-hash-1",
		ServiceName:       "github-push",
		MatchSnapshot:     `{"version":1}`,
		TTL:               30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateFilterCapability: %v", err)
	}
	if fc.FormatVersion != FilterMatchSnapshotVersion {
		t.Errorf("FormatVersion = %d, want %d", fc.FormatVersion, FilterMatchSnapshotVersion)
	}
	if !strings.HasPrefix(raw, "av_pol_") {
		t.Errorf("policy token = %q, want an av_pol_ prefix", raw)
	}

	got, err := s.GetFilterCapability(ctx, raw)
	if err != nil {
		t.Fatalf("GetFilterCapability: %v", err)
	}
	if got.ID != fc.ID || got.Kind != FilterCapPolicy || got.PolicyVaultID != ns.ID {
		t.Errorf("round trip gave %+v", got)
	}
	if got.ConsumedAt != nil || got.ClaimedAt != nil {
		t.Error("a fresh capability must be unclaimed and unconsumed")
	}
	if got.ExpiresAt.Sub(got.IssuedAt) != 30*time.Second {
		t.Errorf("TTL = %v, want 30s", got.ExpiresAt.Sub(got.IssuedAt))
	}
}

// The row must never contain the token that opens it.
func TestFilterCapabilityStoresNoRawToken(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-no-raw-token")
	_, raw := mintContinuation(t, s, ns.ID)

	rows, err := s.db.Query(`SELECT id, kind, token_hash, vault_id, actor_id, source_session_hash,
		source_agent_id, service_name, bind_method, bind_scheme, bind_authority, bind_path,
		bind_query, match_snapshot FROM filter_capabilities`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		cols := make([]string, 14)
		ptrs := make([]interface{}, len(cols))
		for i := range cols {
			ptrs[i] = &cols[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, c := range cols {
			if c == raw || strings.Contains(c, raw) {
				t.Fatalf("column %d holds the raw capability token", i)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeFilterContinuationHappyPath(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-consume")
	fc, raw := mintContinuation(t, s, ns.ID)

	got, err := s.ConsumeFilterContinuation(ctx, raw, testBind(), time.Now())
	if err != nil {
		t.Fatalf("ConsumeFilterContinuation: %v", err)
	}
	if got.ID != fc.ID {
		t.Errorf("consumed %q, want %q", got.ID, fc.ID)
	}
	if got.ConsumedAt == nil || got.ClaimedAt == nil {
		t.Error("claimed_at and consumed_at must both be stamped")
	}
	if got.MatchSnapshot == "" {
		t.Error("the frozen match must come back with the consumed capability")
	}
}

func TestConsumeFilterContinuationIsSingleUse(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-single-use")
	_, raw := mintContinuation(t, s, ns.ID)

	if _, err := s.ConsumeFilterContinuation(ctx, raw, testBind(), time.Now()); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	_, err := s.ConsumeFilterContinuation(ctx, raw, testBind(), time.Now())
	if !errors.Is(err, ErrFilterCapabilityConsumed) {
		t.Fatalf("replay gave %v, want ErrFilterCapabilityConsumed", err)
	}
}

// Every field of the bind is load-bearing: changing any one of them must
// fail the consume rather than silently completing a different request.
func TestConsumeFilterContinuationRejectsMutatedBind(t *testing.T) {
	mutations := map[string]func(b *FilterCapabilityBind){
		"method":    func(b *FilterCapabilityBind) { b.Method = "GET" },
		"scheme":    func(b *FilterCapabilityBind) { b.Scheme = "http" },
		"authority": func(b *FilterCapabilityBind) { b.Authority = "evil.example.com" },
		"path":      func(b *FilterCapabilityBind) { b.Path = "/acme/other.git/git-receive-pack" },
		"query":     func(b *FilterCapabilityBind) { b.Query = "force=1" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := openTestDB(t)
			ctx := context.Background()
			ns, _ := s.CreateVault(ctx, "cap-bind-"+name)
			_, raw := mintContinuation(t, s, ns.ID)

			bad := testBind()
			mutate(&bad)
			if _, err := s.ConsumeFilterContinuation(ctx, raw, bad, time.Now()); !errors.Is(err, ErrFilterCapabilityBind) {
				t.Fatalf("consume with mutated %s gave %v, want ErrFilterCapabilityBind", name, err)
			}

			// And the capability is still spendable by the right request —
			// a rejected attempt must not burn it.
			if _, err := s.ConsumeFilterContinuation(ctx, raw, testBind(), time.Now()); err != nil {
				t.Fatalf("exact consume after a rejected attempt: %v", err)
			}
		})
	}
}

func TestConsumeFilterContinuationExpired(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-expired")
	_, raw, err := s.CreateFilterCapability(ctx, CreateFilterCapabilityParams{
		Kind:              FilterCapContinuation,
		VaultID:           ns.ID,
		ActorID:           "actor-1",
		SourceSessionHash: "sess-hash-1",
		Bind:              testBind(),
		TTL:               time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if _, err := s.ConsumeFilterContinuation(ctx, raw, testBind(), future); !errors.Is(err, ErrFilterCapabilityExpired) {
		t.Fatalf("expired consume gave %v, want ErrFilterCapabilityExpired", err)
	}
}

func TestConsumeFilterContinuationUnknownToken(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	if _, err := s.ConsumeFilterContinuation(ctx, "av_cont_nope", testBind(), time.Now()); !errors.Is(err, ErrFilterCapabilityNotFound) {
		t.Fatalf("unknown token gave %v, want ErrFilterCapabilityNotFound", err)
	}
	if _, err := s.GetFilterCapability(ctx, ""); !errors.Is(err, ErrFilterCapabilityNotFound) {
		t.Fatalf("empty token gave %v, want ErrFilterCapabilityNotFound", err)
	}
}

// A policy capability is not a continuation and must not be spendable as
// one, however exactly the request matches.
func TestConsumeRejectsPolicyCapability(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-wrong-kind")
	_, raw, err := s.CreateFilterCapability(ctx, CreateFilterCapabilityParams{
		Kind:              FilterCapPolicy,
		VaultID:           ns.ID,
		PolicyVaultID:     ns.ID,
		ActorID:           "actor-1",
		SourceSessionHash: "sess-hash-1",
		Bind:              testBind(),
		TTL:               30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeFilterContinuation(ctx, raw, testBind(), time.Now()); !errors.Is(err, ErrFilterCapabilityKind) {
		t.Fatalf("consuming a policy capability gave %v, want ErrFilterCapabilityKind", err)
	}
}

// Single-use has to survive concurrent callers, because in production
// they are different replicas racing on the same row.
func TestConsumeFilterContinuationConcurrent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-concurrent")
	_, raw := mintContinuation(t, s, ns.ID)

	const racers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		wins     int
		otherErr []error
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.ConsumeFilterContinuation(ctx, raw, testBind(), time.Now())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrFilterCapabilityConsumed):
			default:
				otherErr = append(otherErr, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d concurrent consumers succeeded, want exactly 1", wins)
	}
	if len(otherErr) > 0 {
		t.Fatalf("unexpected errors from losing racers: %v", otherErr)
	}
}

func TestDeleteFilterCapability(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-delete")
	_, raw := mintContinuation(t, s, ns.ID)

	if err := s.DeleteFilterCapability(ctx, raw); err != nil {
		t.Fatalf("DeleteFilterCapability: %v", err)
	}
	if _, err := s.GetFilterCapability(ctx, raw); !errors.Is(err, ErrFilterCapabilityNotFound) {
		t.Fatalf("after delete, Get gave %v", err)
	}
	// Deleting an unknown token is a no-op, not an error — the cleanup
	// path runs on failures where the mint may never have happened.
	if err := s.DeleteFilterCapability(ctx, ""); err != nil {
		t.Fatalf("DeleteFilterCapability(\"\") = %v", err)
	}
}

func TestDeleteExpiredFilterCapabilities(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-sweep")

	_, liveRaw := mintContinuation(t, s, ns.ID)
	_, deadRaw, err := s.CreateFilterCapability(ctx, CreateFilterCapabilityParams{
		Kind:              FilterCapContinuation,
		VaultID:           ns.ID,
		ActorID:           "actor-1",
		SourceSessionHash: "sess-hash-1",
		Bind:              testBind(),
		TTL:               time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteExpiredFilterCapabilities(ctx, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("DeleteExpiredFilterCapabilities: %v", err)
	}
	if n != 2 {
		// Both rows are past a one-minute-from-now cutoff.
		t.Fatalf("swept %d rows, want 2", n)
	}
	for _, raw := range []string{liveRaw, deadRaw} {
		if _, err := s.GetFilterCapability(ctx, raw); !errors.Is(err, ErrFilterCapabilityNotFound) {
			t.Errorf("row survived the sweep: %v", err)
		}
	}
}

func TestDeleteExpiredFilterCapabilitiesSparesLiveRows(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-sweep-live")
	_, raw := mintContinuation(t, s, ns.ID)

	if _, err := s.DeleteExpiredFilterCapabilities(ctx, time.Now()); err != nil {
		t.Fatalf("DeleteExpiredFilterCapabilities: %v", err)
	}
	if _, err := s.GetFilterCapability(ctx, raw); err != nil {
		t.Fatalf("sweep removed a live capability: %v", err)
	}
}

func TestCreateFilterCapabilityValidation(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-validate")

	base := CreateFilterCapabilityParams{
		Kind:              FilterCapContinuation,
		VaultID:           ns.ID,
		ActorID:           "actor-1",
		SourceSessionHash: "sess-hash-1",
		Bind:              testBind(),
		TTL:               30 * time.Second,
	}
	tests := map[string]func(p *CreateFilterCapabilityParams){
		"unknown kind":      func(p *CreateFilterCapabilityParams) { p.Kind = "nonsense" },
		"no vault":          func(p *CreateFilterCapabilityParams) { p.VaultID = "" },
		"no source session": func(p *CreateFilterCapabilityParams) { p.SourceSessionHash = "" },
		"non-positive TTL":  func(p *CreateFilterCapabilityParams) { p.TTL = 0 },
		"negative TTL":      func(p *CreateFilterCapabilityParams) { p.TTL = -time.Second },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if _, _, err := s.CreateFilterCapability(ctx, p); err == nil {
				t.Fatal("CreateFilterCapability succeeded, want an error")
			}
		})
	}
}

// Revocation re-checks read the session by its stored hash. The raw
// token must never be needed, and must never be handed back.
func TestGetSessionByHash(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.CreateVault(ctx, "cap-session-hash")

	agent, sess, err := s.CreateAgentWithGrantsAndToken(ctx, "filter-src", "creator", "member",
		[]AgentVaultGrantSpec{{VaultID: ns.ID, Role: "proxy"}}, nil)
	if err != nil {
		t.Fatalf("CreateAgentWithGrantsAndToken: %v", err)
	}
	rawToken := sess.ID
	hash := HashSessionToken(rawToken)

	got, err := s.GetSessionByHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if got.AgentID != agent.ID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, agent.ID)
	}
	if got.ID != "" {
		t.Errorf("Session.ID = %q, want empty — a hash must not be mistaken for a token", got.ID)
	}

	// Revoking the agent cascades a session delete, which is precisely
	// what makes the capability re-check fail closed.
	if err := s.RevokeAgent(ctx, agent.ID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if _, err := s.GetSessionByHash(ctx, hash); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("after revoke, GetSessionByHash = %v, want sql.ErrNoRows", err)
	}
	if _, err := s.GetSessionByHash(ctx, ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("empty hash = %v, want sql.ErrNoRows", err)
	}
}
