package brokercore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ContinuationTokenPrefix marks HMAC tickets the sidecar presents as
// Proxy-Authorization to send a *new* request through the inbound vault
// (skip filter, inject that vault's credentials). The ticket does not
// carry or resume the original body — that hop already streamed to the
// sidecar.
const ContinuationTokenPrefix = "av_cont_"

const continuationTTL = 10 * time.Minute

// ContinuationClaims authorize a later inbound request on the same
// route (method, host, path) and vault. Nothing about the original
// body, query, or headers is stored.
type ContinuationClaims struct {
	VaultID       string `json:"vault_id"`
	VaultName     string `json:"vault_name"`
	UserID        string `json:"user_id,omitempty"`
	AgentID       string `json:"agent_id,omitempty"`
	VaultRole     string `json:"vault_role"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	FilterAgentID string `json:"filter_agent_id"`
	Exp           int64  `json:"exp"`
}

// TicketSigner mints and verifies continuation tickets. Key is process-local.
type TicketSigner struct {
	Key []byte
	Now func() time.Time
}

func (s *TicketSigner) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Mint returns an av_cont_ token for the claims. Exp is set if zero.
func (s *TicketSigner) Mint(c ContinuationClaims) (string, error) {
	if s == nil || len(s.Key) == 0 {
		return "", fmt.Errorf("brokercore: continuation signer not configured")
	}
	if c.Exp == 0 {
		c.Exp = s.now().Add(continuationTTL).Unix()
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.Key)
	_, _ = mac.Write(payload)
	sig := mac.Sum(nil)
	return ContinuationTokenPrefix +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// Parse verifies an av_cont_ token. Returns ErrInvalidSession on failure.
func (s *TicketSigner) Parse(token string) (*ContinuationClaims, error) {
	if s == nil || len(s.Key) == 0 {
		return nil, ErrInvalidSession
	}
	rest, ok := strings.CutPrefix(token, ContinuationTokenPrefix)
	if !ok {
		return nil, ErrInvalidSession
	}
	payloadB64, sigB64, ok := strings.Cut(rest, ".")
	if !ok {
		return nil, ErrInvalidSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalidSession
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalidSession
	}
	mac := hmac.New(sha256.New, s.Key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, ErrInvalidSession
	}
	var c ContinuationClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrInvalidSession
	}
	if c.Exp < s.now().Unix() {
		return nil, ErrInvalidSession
	}
	return &c, nil
}

func (c *ContinuationClaims) Scope() *ProxyScope {
	return &ProxyScope{
		UserID:        c.UserID,
		AgentID:       c.AgentID,
		VaultID:       c.VaultID,
		VaultName:     c.VaultName,
		VaultRole:     c.VaultRole,
		SkipFilter:    true,
		Continuation:  c,
		FilterAgentID: c.FilterAgentID,
	}
}
