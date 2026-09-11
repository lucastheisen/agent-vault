package brokercore

import (
	"context"
	"testing"
	"time"
)

func TestTicketMintParse(t *testing.T) {
	s := &TicketSigner{Key: []byte("0123456789abcdef0123456789abcdef"), Now: func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}}
	tok, err := s.Mint(ContinuationClaims{
		VaultID: "vid", VaultName: "dev", AgentID: "ag", VaultRole: "proxy",
		Method: "POST", Host: "github.com", Path: "/org/repo.git/git-receive-pack",
		FilterAgentID: "filter-ag",
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "github.com" || c.Method != "POST" || c.VaultID != "vid" {
		t.Fatalf("claims %+v", c)
	}
	if _, err := s.Parse("av_agt_notaticket"); err == nil {
		t.Fatal("expected reject of non-ticket")
	}
	bad := &TicketSigner{Key: []byte("ffffffffffffffffffffffffffffffff"), Now: s.Now}
	if _, err := bad.Parse(tok); err == nil {
		t.Fatal("expected reject of wrong key")
	}
}

func TestTicketExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &TicketSigner{Key: []byte("0123456789abcdef0123456789abcdef"), Now: func() time.Time { return now }}
	tok, err := s.Mint(ContinuationClaims{VaultID: "v", VaultName: "n", Method: "GET", Host: "h", Path: "/", Exp: now.Add(-time.Second).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Parse(tok); err == nil {
		t.Fatal("expected expired ticket rejected")
	}
}

func TestResolveForProxyContinuation(t *testing.T) {
	s := &TicketSigner{Key: []byte("0123456789abcdef0123456789abcdef")}
	tok, err := s.Mint(ContinuationClaims{
		VaultID: "vid", VaultName: "dev", AgentID: "ag", VaultRole: "proxy",
		Method: "POST", Host: "github.com", Path: "/x",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &StoreSessionResolver{Tickets: s}
	scope, err := r.ResolveForProxy(context.Background(), tok, "")
	if err != nil {
		t.Fatal(err)
	}
	if !scope.SkipFilter || scope.VaultID != "vid" || scope.Continuation == nil {
		t.Fatalf("scope %+v", scope)
	}
}
