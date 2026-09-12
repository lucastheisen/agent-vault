package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

func newCapabilityStore(st Store) brokercore.CapabilityStore {
	if sql, ok := st.(*store.SQLStore); ok {
		return brokercore.NewSQLCapabilities(sql)
	}
	return brokercore.NewMemoryCapabilities()
}

func (s *Server) wireCapabilityCheck() {
	switch c := s.caps.(type) {
	case *brokercore.MemoryCapabilities:
		c.Check = s.checkCapabilitySource
	case *brokercore.SQLCapabilities:
		c.Check = s.checkCapabilitySource
	}
}

func (s *Server) checkCapabilitySource(ctx context.Context, c *brokercore.Capability) error {
	if c == nil {
		return brokercore.ErrInvalidSession
	}
	if c.ActorAgentID != "" {
		ag, err := s.store.GetAgentByID(ctx, c.ActorAgentID)
		if err != nil || ag == nil || ag.Status != "active" {
			return brokercore.ErrInvalidSession
		}
	}
	if c.SourceSessID != "" {
		if lookup, ok := s.store.(interface {
			GetSessionByTokenHash(context.Context, string) (*store.Session, error)
		}); ok {
			sess, err := lookup.GetSessionByTokenHash(ctx, c.SourceSessID)
			if err != nil || sess == nil || sess.IsExpired(time.Now()) {
				return brokercore.ErrInvalidSession
			}
		}
	}
	actorID := c.ActorAgentID
	if actorID == "" {
		actorID = c.ActorUserID
	}
	if actorID != "" && c.SourceVaultID != "" {
		role, err := s.store.GetVaultRole(ctx, actorID, c.SourceVaultID)
		if err != nil || role == "" {
			return brokercore.ErrInvalidSession
		}
	}
	return nil
}

// validateFilterWrites checks filter URLs and dual-admin when policy_vault
// names a different vault than the source.
func (s *Server) validateFilterWrites(ctx context.Context, actorID string, source *store.Vault, services []broker.Service) error {
	for _, svc := range services {
		if !svc.HasActiveFilter() {
			continue
		}
		if err := broker.ValidateFilter(svc.Filter); err != nil {
			return err
		}
		pv := svc.Filter.PolicyVault
		if pv == "" || pv == source.Name {
			continue
		}
		other, err := s.store.GetVault(ctx, pv)
		if err != nil || other == nil {
			return fmt.Errorf("filter.policy_vault %q not found", pv)
		}
		role, err := s.store.GetVaultRole(ctx, actorID, other.ID)
		if err != nil || role != "admin" {
			return fmt.Errorf("filter.policy_vault %q requires admin on both vaults", pv)
		}
	}
	return nil
}
