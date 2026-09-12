package brokercore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func port(p int) *int { return &p }

func pushService() *broker.Service {
	return &broker.Service{
		Name: "github-push",
		Host: "github.com",
		Path: "/*/git-receive-pack",
		Port: port(8443),
		Auth: broker.Auth{Type: "basic", Username: "GITLAB_USER", Password: "GITLAB_PUSH_TOKEN"},
		Substitutions: []broker.Substitution{
			{Key: "PROJECT_ID", Placeholder: "__project__", In: []string{"path"}},
		},
		Filter: &broker.Filter{URL: "https://policy.example.com/hook", PolicyVault: "policy"},
	}
}

func TestFreezeThawRoundTrip(t *testing.T) {
	orig := &CredentialMatch{Service: pushService()}

	snapshot, err := FreezeMatch(orig)
	if err != nil {
		t.Fatalf("FreezeMatch: %v", err)
	}

	got, err := ThawMatch(snapshot)
	if err != nil {
		t.Fatalf("ThawMatch: %v", err)
	}
	svc := got.Service
	if svc.Name != "github-push" || svc.Host != "github.com" || svc.Path != "/*/git-receive-pack" {
		t.Errorf("matcher did not round-trip: name=%q host=%q path=%q", svc.Name, svc.Host, svc.Path)
	}
	if svc.Port == nil || *svc.Port != 8443 {
		t.Errorf("Port = %v, want 8443", svc.Port)
	}
	// The auth *shape* has to survive, not just the key names, or
	// ResolveMatch cannot rebuild the same headers.
	if svc.Auth.Type != "basic" || svc.Auth.Username != "GITLAB_USER" || svc.Auth.Password != "GITLAB_PUSH_TOKEN" {
		t.Errorf("auth did not round-trip: %+v", svc.Auth)
	}
	if len(svc.Substitutions) != 1 || svc.Substitutions[0].Placeholder != "__project__" {
		t.Errorf("substitutions did not round-trip: %+v", svc.Substitutions)
	}
}

// The snapshot is policy metadata, not a secret store. Assert the shape
// of that claim: it carries key *names*, and nothing that looks like a
// resolved value.
func TestFrozenMatchCarriesKeyNamesNotValues(t *testing.T) {
	snapshot, err := FreezeMatch(&CredentialMatch{Service: pushService()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snapshot, "GITLAB_PUSH_TOKEN") {
		t.Error("snapshot must carry the credential key name so Resolve can find the slot")
	}
	for _, secret := range []string{"glpat-", "ghp_", "hunter2"} {
		if strings.Contains(snapshot, secret) {
			t.Errorf("snapshot contains what looks like a credential value (%q)", secret)
		}
	}
}

func TestThawMatchFailsClosed(t *testing.T) {
	good, err := FreezeMatch(&CredentialMatch{Service: pushService()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		snapshot string
		wantErr  error
	}{
		{"empty", "", ErrFrozenMatchInvalid},
		{"not json", "{{{", ErrFrozenMatchInvalid},
		{"version zero", `{"service":{"name":"a","host":"b"}}`, ErrFrozenMatchVersion},
		{"future version", `{"version":9999,"service":{"name":"a","host":"b"}}`, ErrFrozenMatchVersion},
		{"no service", `{"version":1}`, ErrFrozenMatchInvalid},
		{"null service", `{"version":1,"service":null}`, ErrFrozenMatchInvalid},
		{"service without name", `{"version":1,"service":{"host":"github.com"}}`, ErrFrozenMatchInvalid},
		{"service without host", `{"version":1,"service":{"name":"github-push"}}`, ErrFrozenMatchInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ThawMatch(tc.snapshot)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ThawMatch(%q) = %v, want %v", tc.snapshot, err, tc.wantErr)
			}
		})
	}

	// Sanity: the good snapshot still thaws, so the table above is
	// testing rejection and not a broken codec.
	if _, err := ThawMatch(good); err != nil {
		t.Fatalf("valid snapshot failed to thaw: %v", err)
	}
}

func TestFreezeMatchRejectsUnfreezable(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *CredentialMatch
	}{
		{"nil match", nil},
		{"nil service", &CredentialMatch{}},
		{"passthrough", &CredentialMatch{Passthrough: true, Service: pushService()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := FreezeMatch(tc.m); !errors.Is(err, ErrFrozenMatchInvalid) {
				t.Fatalf("FreezeMatch = %v, want ErrFrozenMatchInvalid", err)
			}
		})
	}
}

// The no-read invariant, measured rather than asserted: Match must not
// call GetCredential even once.
func TestMatchPerformsNoCredentialRead(t *testing.T) {
	key32 := make32(0x31)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Name: "github-push",
		Host: "github.com",
		Path: "/*/git-receive-pack",
		Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
	}})
	f.setCred(t, key32, "v1", "GITHUB_TOKEN", "ghp_secret")
	p := NewStoreCredentialProvider(f, key32)

	m, err := p.Match(context.Background(), "v1", "github.com", 0, "/acme/app.git/git-receive-pack")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if f.getCredentialCalls != 0 {
		t.Fatalf("Match made %d credential reads, want 0", f.getCredentialCalls)
	}
	if m.Service == nil || m.Service.Name != "github-push" {
		t.Fatalf("Match returned %+v", m)
	}

	// Resolving the same match does read, so the counter is measuring
	// something real rather than a path that never runs.
	res, err := p.ResolveMatch(context.Background(), "v1", m)
	if err != nil {
		t.Fatalf("ResolveMatch: %v", err)
	}
	if f.getCredentialCalls == 0 {
		t.Error("ResolveMatch made no credential read")
	}
	if got := res.Headers["Authorization"]; got != "Bearer ghp_secret" {
		t.Errorf("Authorization = %q", got)
	}
}

// A rotation during the continuation window attaches the new value for
// the frozen key name — values are not frozen, key names are.
func TestResolveMatchUsesCurrentValueForFrozenKey(t *testing.T) {
	key32 := make32(0x32)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Name: "github-push",
		Host: "github.com",
		Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
	}})
	f.setCred(t, key32, "v1", "GITHUB_TOKEN", "old_value")
	p := NewStoreCredentialProvider(f, key32)

	m, err := p.Match(context.Background(), "v1", "github.com", 0, "/")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	snapshot, err := FreezeMatch(m)
	if err != nil {
		t.Fatalf("FreezeMatch: %v", err)
	}

	// Rotate, then resolve the frozen match.
	f.setCred(t, key32, "v1", "GITHUB_TOKEN", "rotated_value")
	thawed, err := ThawMatch(snapshot)
	if err != nil {
		t.Fatalf("ThawMatch: %v", err)
	}
	res, err := p.ResolveMatch(context.Background(), "v1", thawed)
	if err != nil {
		t.Fatalf("ResolveMatch: %v", err)
	}
	if got := res.Headers["Authorization"]; got != "Bearer rotated_value" {
		t.Errorf("Authorization = %q, want the rotated value", got)
	}
}

// Deleting the frozen key mid-window fails closed rather than falling
// back to some other slot.
func TestResolveMatchMissingKeyFailsClosed(t *testing.T) {
	key32 := make32(0x33)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Name: "github-push",
		Host: "github.com",
		Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
	}})
	p := NewStoreCredentialProvider(f, key32)

	m := &CredentialMatch{Service: &broker.Service{
		Name: "github-push",
		Host: "github.com",
		Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
	}}
	res, err := p.ResolveMatch(context.Background(), "v1", m)
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("ResolveMatch = %v, want ErrCredentialMissing", err)
	}
	if res != nil && res.Headers != nil {
		t.Error("a failed resolve must not return headers")
	}
}

func TestResolveMatchPassthroughAndNil(t *testing.T) {
	key32 := make32(0x34)
	p := NewStoreCredentialProvider(newFakeCredStore(), key32)
	ctx := context.Background()

	res, err := p.ResolveMatch(ctx, "v1", &CredentialMatch{Passthrough: true})
	if err != nil || !res.Passthrough {
		t.Fatalf("passthrough match resolved to %+v, %v", res, err)
	}
	if _, err := p.ResolveMatch(ctx, "v1", nil); !errors.Is(err, ErrServiceNotFound) {
		t.Errorf("nil match = %v, want ErrServiceNotFound", err)
	}
	if _, err := p.ResolveMatch(ctx, "v1", &CredentialMatch{}); !errors.Is(err, ErrServiceNotFound) {
		t.Errorf("empty match = %v, want ErrServiceNotFound", err)
	}
}

func TestCredentialMatchHasFilter(t *testing.T) {
	if (&CredentialMatch{Service: pushService()}).HasFilter() != true {
		t.Error("HasFilter() = false for a filtered service")
	}
	plain := pushService()
	plain.Filter = nil
	if (&CredentialMatch{Service: plain}).HasFilter() {
		t.Error("HasFilter() = true for an unfiltered service")
	}
	if (&CredentialMatch{Passthrough: true}).HasFilter() {
		t.Error("HasFilter() = true for passthrough")
	}
	if (*CredentialMatch)(nil).HasFilter() {
		t.Error("HasFilter() = true for a nil match")
	}
}
