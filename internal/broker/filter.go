package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// FilterAgentNamePrefix is the reserved agent-name prefix for mint-at-config
// filter agents. Human `agent create` / rename must reject it.
const FilterAgentNamePrefix = "filter-"

// FilterOp records how an incoming JSON write treated the filter field.
// It is not persisted; UnmarshalJSON sets it so upsert can distinguish
// omit (preserve) from explicit null/empty (clear). YAML never sets this
// directly — the CLI converts YAML to JSON first.
type FilterOp int

const (
	FilterOpOmit FilterOp = iota
	FilterOpSet
	FilterOpClear
)

// Filter is an optional out-of-process sidecar hop on a matched service.
// After match and before credential inject, Agent Vault reverse-proxies
// the live request to URL.
type Filter struct {
	URL     string `json:"url" yaml:"url"`
	Vault   string `json:"vault,omitempty" yaml:"vault,omitempty"`
	AgentID string `json:"agent_id,omitempty" yaml:"-"`
}

// HasActiveFilter reports whether s declares a sidecar hop.
func (s *Service) HasActiveFilter() bool {
	return s != nil && s.Filter != nil && s.Filter.URL != ""
}

// FilterAgentName is the deterministic agent slug for a (filter.vault, url)
// pair so services share one agent. Truncates the vault portion so the
// result always passes ValidateSlug (≤64 chars).
func FilterAgentName(vaultName, filterURL string) string {
	sum := sha256.Sum256([]byte(filterURL))
	hash := hex.EncodeToString(sum[:])[:8]
	const prefix = FilterAgentNamePrefix
	// prefix + hash + two hyphens reserved; vault gets the remainder.
	budget := 64 - len(prefix) - 1 - len(hash)
	v := vaultName
	if len(v) > budget {
		v = v[:budget]
	}
	v = strings.Trim(v, "-")
	if v == "" {
		v = "v"
	}
	return prefix + v + "-" + hash
}

// IsReservedFilterAgentName reports whether name uses the minted-agent prefix.
func IsReservedFilterAgentName(name string) bool {
	return strings.HasPrefix(name, FilterAgentNamePrefix)
}

// ValidateFilter checks a set filter. Empty URL is treated as clear by
// callers; this function requires a usable http(s) URL.
func ValidateFilter(f *Filter) error {
	if f == nil || f.URL == "" {
		return nil
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return fmt.Errorf("filter.url is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("filter.url must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("filter.url must include a host")
	}
	if f.Vault != "" {
		if err := ValidateSlug(f.Vault); err != nil {
			return fmt.Errorf("filter.vault: %w", err)
		}
	}
	return nil
}

// ApplyFilterWrite copies incoming onto dst according to FilterOp.
// Omit keeps dst.Filter; Clear nils it; Set replaces it (AgentID is
// kept when the incoming URL+vault still match so minting can reuse).
func ApplyFilterWrite(dst *Service, incoming Service) {
	switch incoming.FilterOp {
	case FilterOpOmit:
		return
	case FilterOpClear:
		dst.Filter = nil
		dst.FilterOp = FilterOpClear
	case FilterOpSet:
		prev := dst.Filter
		next := incoming.Filter
		if next != nil && prev != nil && next.AgentID == "" &&
			next.URL == prev.URL && next.Vault == prev.Vault {
			cloned := *next
			cloned.AgentID = prev.AgentID
			next = &cloned
		}
		dst.Filter = next
		dst.FilterOp = FilterOpSet
	}
}

// UnmarshalJSON is the only omit/set/clear decoder for Filter. The HTTP
// API and on-disk broker config are JSON. CLI YAML is converted to JSON
// before it reaches this method (see cmd.loadServicesFromFile).
func (s *Service) UnmarshalJSON(data []byte) error {
	type wire struct {
		Name          string          `json:"name"`
		Host          string          `json:"host"`
		Path          string          `json:"path,omitempty"`
		Enabled       *bool           `json:"enabled,omitempty"`
		Auth          Auth            `json:"auth"`
		Substitutions []Substitution  `json:"substitutions,omitempty"`
		Filter        json.RawMessage `json:"filter"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	s.Name = w.Name
	s.Host = w.Host
	s.Path = w.Path
	s.Enabled = w.Enabled
	s.Auth = w.Auth
	s.Substitutions = w.Substitutions
	if len(w.Filter) == 0 {
		s.Filter = nil
		s.FilterOp = FilterOpOmit
		return nil
	}
	if string(w.Filter) == "null" {
		s.Filter = nil
		s.FilterOp = FilterOpClear
		return nil
	}
	var f Filter
	if err := json.Unmarshal(w.Filter, &f); err != nil {
		return fmt.Errorf("filter: %w", err)
	}
	if f.URL == "" && f.Vault == "" && f.AgentID == "" {
		s.Filter = nil
		s.FilterOp = FilterOpClear
		return nil
	}
	s.Filter = &f
	s.FilterOp = FilterOpSet
	return nil
}
