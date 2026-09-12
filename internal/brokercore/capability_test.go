package brokercore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestMemoryContinuationSingleUseAndBind(t *testing.T) {
	s := NewMemoryCapabilities()
	raw, err := s.IssueContinuation(context.Background(), Capability{
		SourceVaultID: "vid",
		VaultName:     "dev",
		ActorAgentID:  "ag",
		VaultRole:     "proxy",
		Method:        "POST",
		Scheme:        "https",
		Authority:     "github.com",
		EscapedPath:   "/acme/app.git/git-receive-pack",
		Snapshot:      SnapshotFromService(&broker.Service{Name: "push", Host: "github.com", Auth: broker.Auth{Type: "bearer", Token: "GH"}}),
	})
	if err != nil || !strings.HasPrefix(raw, ContinuationTokenPrefix) {
		t.Fatalf("issue: %q %v", raw, err)
	}
	got, err := s.Authenticate(context.Background(), raw)
	if err != nil || !got.BindMatches("POST", "github.com", "/acme/app.git/git-receive-pack", "", "https") {
		t.Fatalf("auth: %+v %v", got, err)
	}
	if got.BindMatches("GET", "github.com", "/acme/app.git/git-receive-pack", "", "https") {
		t.Fatal("method mismatch should fail bind")
	}
	if _, err := s.ConsumeContinuation(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeContinuation(context.Background(), raw); err == nil {
		t.Fatal("second consume must fail")
	}
	if _, err := s.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("consumed token must not authenticate")
	}
}

func TestMemoryPolicyReusableAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	s := NewMemoryCapabilities()
	s.Now = func() time.Time { return now }
	raw, err := s.IssuePolicy(context.Background(), Capability{
		SourceVaultID:   "vid",
		PolicyVaultID:   "vid",
		PolicyVaultName: "dev",
		VaultName:       "dev",
		ActorAgentID:    "ag",
	})
	if err != nil || !strings.HasPrefix(raw, PolicyTokenPrefix) {
		t.Fatalf("issue: %q %v", raw, err)
	}
	if _, err := s.Authenticate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(context.Background(), raw); err != nil {
		t.Fatal("policy must be reusable in window")
	}
	s.Now = func() time.Time { return now.Add(31 * time.Second) }
	if _, err := s.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("expired policy must fail")
	}
}

func TestMemoryUnknownSnapshotFailsClosed(t *testing.T) {
	s := NewMemoryCapabilities()
	raw, err := s.IssueContinuation(context.Background(), Capability{
		SourceVaultID: "vid",
		Method:        "GET",
		Scheme:        "https",
		Authority:     "h",
		EscapedPath:   "/",
		Snapshot:      MatchSnapshot{Version: 99, ServiceName: "x", Host: "h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeContinuation(context.Background(), raw); err == nil {
		t.Fatal("unknown snapshot version must fail closed")
	}
}

func TestResolveForProxyCapability(t *testing.T) {
	caps := NewMemoryCapabilities()
	raw, err := caps.IssueContinuation(context.Background(), Capability{
		SourceVaultID: "vid",
		VaultName:     "dev",
		ActorAgentID:  "ag",
		VaultRole:     "proxy",
		Method:        "GET",
		Scheme:        "https",
		Authority:     "h",
		EscapedPath:   "/p",
		Snapshot:      SnapshotFromService(&broker.Service{Name: "s", Host: "h"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &StoreSessionResolver{Caps: caps}
	scope, err := r.ResolveForProxy(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if !scope.SkipFilter || scope.VaultID != "vid" || scope.Continuation == nil {
		t.Fatalf("scope: %+v", scope)
	}
}
