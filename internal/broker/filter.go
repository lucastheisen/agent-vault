package broker

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Filter configures an out-of-process policy hop for a service.
//
// When a request matches a service carrying a Filter, Agent Vault
// reverse-proxies it to URL *without resolving the destination
// credential*. The sidecar there either short-circuits with any HTTP
// response, or continues the request back through Agent Vault using a
// single-use continuation capability — and only that continuation can
// cause the destination credential to be decrypted.
//
// Admin-only. Agent proposals can neither set nor clear this block, and
// it never appears on /discover. See ad_hoc/issue-407/service-filters.plan.md.
type Filter struct {
	// URL is the sidecar origin. https is the normal deployment and the
	// only form allowed to reach a public address. Cleartext http is
	// permitted to a literal loopback IP with no further ceremony; any
	// other http target requires AllowInsecurePrivateHTTP.
	URL string `yaml:"url" json:"url"`

	// PolicyVault names the vault a short-lived policy capability is
	// scoped to.
	//
	// Empty means NO policy capability is minted at all — the sidecar
	// decides from the intercepted request alone. Naming the *source*
	// vault is the explicit opt-in to Layout A ("logic in front of the
	// same credentials"); naming a different vault is Layout B and
	// requires the configuring actor to be a vault admin of both.
	PolicyVault string `yaml:"policy_vault,omitempty" json:"policy_vault,omitempty"`

	// AllowInsecurePrivateHTTP opts into cleartext http to a sidecar
	// that is not a literal loopback IP — the Compose / Kubernetes
	// `http://filter:12345` case.
	//
	// This is weaker than TLS, not equivalent to it: capabilities cross
	// a cleartext private network. With the flag set, every resolved
	// dial address must be loopback or RFC1918, redirects are disabled
	// on the filter hop, and public, link-local, and cloud-metadata
	// addresses stay blocked.
	AllowInsecurePrivateHTTP bool `yaml:"allow_insecure_private_http,omitempty" json:"allow_insecure_private_http,omitempty"`
}

// Validate checks a filter block for a well-formed URL and an
// acknowledged transport. A nil Filter is valid — it just means the
// service has no policy hop.
func (f *Filter) Validate() error {
	if f == nil {
		return nil
	}
	raw := strings.TrimSpace(f.URL)
	if raw == "" {
		return fmt.Errorf("filter: \"url\" is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("filter: url %q is not a valid URL", f.URL)
	}
	switch u.Scheme {
	case "http", "https":
	case "":
		return fmt.Errorf("filter: url %q must be absolute (include http:// or https://)", f.URL)
	default:
		return fmt.Errorf("filter: url %q must use http or https, not %q", f.URL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("filter: url %q must include a host", f.URL)
	}
	// Capabilities travel this hop as bearer *headers* precisely so they
	// stay out of request lines and access logs. A filter URL that
	// carries its own userinfo would put a credential straight back into
	// both, and into the service config besides.
	if u.User != nil {
		return fmt.Errorf("filter: url %q must not contain userinfo", f.URL)
	}
	if u.Scheme == "http" && !IsLoopbackURLHost(u.Host) && !f.AllowInsecurePrivateHTTP {
		return fmt.Errorf("filter: url %q is cleartext http to a non-loopback host — "+
			"use https, or set allow_insecure_private_http: true to acknowledge that "+
			"capabilities cross a cleartext private network", f.URL)
	}
	if f.PolicyVault != "" {
		if err := ValidateSlug(f.PolicyVault); err != nil {
			return fmt.Errorf("filter: invalid policy_vault: %w", err)
		}
	}
	return nil
}

// IsLoopbackURLHost reports whether a URL authority's host part is a
// literal loopback IP.
//
// A *name* that happens to resolve to loopback ("localhost") is
// deliberately not accepted here: resolution is not part of the config
// and can change under the operator's feet, so only an unambiguous
// literal earns the no-flag exemption. `http://localhost:12345` needs
// allow_insecure_private_http; `http://127.0.0.1:12345` does not.
func IsLoopbackURLHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// HasFilter reports whether the service carries a policy-filter hop.
// Callers on the hot path use this to decide between the plain Inject
// route and the filtered Match route.
func (s *Service) HasFilter() bool {
	return s != nil && s.Filter != nil
}

// FilterPolicyVault returns the vault a policy capability should be
// scoped to, or "" when the service mints no policy capability.
func (s *Service) FilterPolicyVault() string {
	if !s.HasFilter() {
		return ""
	}
	return s.Filter.PolicyVault
}
