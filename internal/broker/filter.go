package broker

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

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
// After match and before destination credential resolve, Agent Vault
// reverse-proxies the live request to URL.
type Filter struct {
	URL                      string `json:"url" yaml:"url"`
	PolicyVault              string `json:"policy_vault,omitempty" yaml:"policy_vault,omitempty"`
	AllowInsecurePrivateHTTP bool   `json:"allow_insecure_private_http,omitempty" yaml:"allow_insecure_private_http,omitempty"`
}

// HasActiveFilter reports whether s declares a sidecar hop.
func (s *Service) HasActiveFilter() bool {
	return s != nil && s.Filter != nil && s.Filter.URL != ""
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
	if u.Scheme == "http" && !FilterHTTPHostAllowed(u.Hostname(), f.AllowInsecurePrivateHTTP) {
		return fmt.Errorf("filter.url http is only allowed for a literal loopback IP, or with allow_insecure_private_http for a private/loopback host")
	}
	if f.PolicyVault != "" {
		if err := ValidateSlug(f.PolicyVault); err != nil {
			return fmt.Errorf("filter.policy_vault: %w", err)
		}
	}
	return nil
}

// FilterHTTPHostAllowed reports whether an http filter.url host is
// permitted. Literal loopback IPs are always allowed. Other hosts
// require the insecure-private opt-in (resolved-address checks happen
// at dial time).
func FilterHTTPHostAllowed(hostname string, allowInsecurePrivate bool) bool {
	if ip := net.ParseIP(hostname); ip != nil && ip.IsLoopback() {
		return true
	}
	return allowInsecurePrivate
}

// ApplyFilterWrite copies incoming onto dst according to FilterOp.
// Omit keeps dst.Filter; Clear nils it; Set replaces it.
func ApplyFilterWrite(dst *Service, incoming Service) {
	switch incoming.FilterOp {
	case FilterOpOmit:
		return
	case FilterOpClear:
		dst.Filter = nil
		dst.FilterOp = FilterOpClear
	case FilterOpSet:
		dst.Filter = incoming.Filter
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
	if f.URL == "" && f.PolicyVault == "" && !f.AllowInsecurePrivateHTTP {
		s.Filter = nil
		s.FilterOp = FilterOpClear
		return nil
	}
	s.Filter = &f
	s.FilterOp = FilterOpSet
	return nil
}

// CredentialKeyNames returns the credential key names referenced by
// auth and substitutions — never values. Used in frozen-match snapshots.
func (s Service) CredentialKeyNames() []string {
	return s.CredentialKeys()
}

// IsLoopbackHost reports whether host is a literal loopback IP (no DNS).
func IsLoopbackHost(host string) bool {
	h := host
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
