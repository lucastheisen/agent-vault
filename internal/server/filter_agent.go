package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

const filterAgentTokenSettingPrefix = "filter-agent-token:"

func filterAgentTokenKey(agentID string) string {
	return filterAgentTokenSettingPrefix + agentID
}

type wrappedFilterToken struct {
	CT    string `json:"ct"`
	Nonce string `json:"nonce"`
}

// FilterAgentToken implements mitm.FilterTokenSource.
func (s *Server) FilterAgentToken(ctx context.Context, agentID string) (string, error) {
	ag, err := s.store.GetAgentByID(ctx, agentID)
	if err != nil || ag == nil || ag.Status != "active" {
		return "", fmt.Errorf("filter agent unavailable")
	}
	raw, err := s.store.GetSetting(ctx, filterAgentTokenKey(agentID))
	if err != nil {
		return "", err
	}
	var wrap wrappedFilterToken
	if err := json.Unmarshal([]byte(raw), &wrap); err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(wrap.CT)
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(wrap.Nonce)
	if err != nil {
		return "", err
	}
	pt, err := crypto.Decrypt(ct, nonce, s.encKey)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (s *Server) storeFilterAgentToken(ctx context.Context, agentID, rawToken string) error {
	ct, nonce, err := crypto.Encrypt([]byte(rawToken), s.encKey)
	if err != nil {
		return err
	}
	wrap, err := json.Marshal(wrappedFilterToken{
		CT:    base64.StdEncoding.EncodeToString(ct),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, filterAgentTokenKey(agentID), string(wrap))
}

// provisionFilters mints or reuses filter-agents for services that declare
// a filter. inboundVault is the vault the services belong to (name + id).
func (s *Server) provisionFilters(ctx context.Context, actorID string, inbound *store.Vault, services []broker.Service) error {
	for i := range services {
		f := services[i].Filter
		if f == nil || f.URL == "" {
			continue
		}
		vaultName := f.Vault
		if vaultName == "" {
			vaultName = inbound.Name
		}
		target, err := s.store.GetVault(ctx, vaultName)
		if err != nil || target == nil {
			return fmt.Errorf("filter.vault %q not found", vaultName)
		}
		name := broker.FilterAgentName(vaultName, f.URL)
		ag, err := s.store.GetAgentByName(ctx, name)
		if err != nil || ag == nil {
			created, sess, err := s.store.CreateAgentWithGrantsAndToken(ctx, name, actorID, "no-access",
				[]store.AgentVaultGrantSpec{{VaultID: target.ID, Role: "proxy"}}, nil)
			if err != nil {
				return fmt.Errorf("creating filter agent: %w", err)
			}
			if err := s.storeFilterAgentToken(ctx, created.ID, sess.ID); err != nil {
				return err
			}
			ag = created
		} else if ag.Status != "active" {
			// Name is unique even after revoke. Re-applying YAML remints
			// by rotating the existing row (reactivates + new token).
			sess, err := s.store.RotateAgentToken(ctx, ag.ID, nil)
			if err != nil {
				return fmt.Errorf("reminting filter agent: %w", err)
			}
			if err := s.storeFilterAgentToken(ctx, ag.ID, sess.ID); err != nil {
				return err
			}
			if err := s.store.GrantVaultRole(ctx, ag.ID, "agent", target.ID, "proxy"); err != nil {
				return err
			}
		} else {
			if err := s.store.GrantVaultRole(ctx, ag.ID, "agent", target.ID, "proxy"); err != nil {
				return err
			}
			if _, err := s.store.GetSetting(ctx, filterAgentTokenKey(ag.ID)); errors.Is(err, sql.ErrNoRows) {
				sess, err := s.store.CreateAgentToken(ctx, ag.ID, nil)
				if err != nil {
					return err
				}
				if err := s.storeFilterAgentToken(ctx, ag.ID, sess.ID); err != nil {
					return err
				}
			}
		}
		f.AgentID = ag.ID
		f.Vault = vaultName
		services[i].Filter = f
	}
	return nil
}

func (s *Server) releaseUnusedFilterAgents(ctx context.Context) {
	agents, err := s.store.ListAllAgents(ctx)
	if err != nil {
		return
	}
	inUse := map[string]bool{}
	vaults, err := s.store.ListVaults(ctx)
	if err != nil {
		return
	}
	for _, v := range vaults {
		svcs, err := s.loadServices(ctx, v.ID)
		if err != nil || svcs == nil {
			continue
		}
		for _, svc := range svcs {
			if svc.Filter != nil && svc.Filter.AgentID != "" {
				inUse[svc.Filter.AgentID] = true
			}
		}
	}
	for _, ag := range agents {
		if !broker.IsReservedFilterAgentName(ag.Name) || ag.Status != "active" {
			continue
		}
		if inUse[ag.ID] {
			continue
		}
		_ = s.store.RevokeAgent(ctx, ag.ID)
		_ = s.store.SetSetting(ctx, filterAgentTokenKey(ag.ID), "")
	}
}

func reservedFilterAgentNameError(name string) string {
	return fmt.Sprintf("agent name %q is reserved for service filters", name)
}

func newTicketSigner() *brokercore.TicketSigner {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("server: generating filter ticket key: " + err.Error())
	}
	return &brokercore.TicketSigner{Key: key}
}
