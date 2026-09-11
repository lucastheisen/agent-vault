package mitm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

const (
	filterCapabilityTTL = 30 * time.Second

	filterContinuationProxyHeader = "X-Agent-Vault-Continuation-Proxy"
	filterCAHeader                = "X-Agent-Vault-CA"
	filterPolicyProxyHeader       = "X-Agent-Vault-Policy-Proxy"
	filterTargetURLHeader         = "X-Agent-Vault-Target-URL"
)

type filterCapabilityKind uint8

const (
	filterCapabilityContinuation filterCapabilityKind = iota + 1
	filterCapabilityPolicy
)

type filterCapabilityState uint8

const (
	filterCapabilityIssued filterCapabilityState = iota
	filterCapabilityClaimed
)

// PolicyVaultResolver resolves a configured policy-vault name into the
// non-secret proxy scope that a filter receives for its policy checks.
type PolicyVaultResolver func(context.Context, string, *brokercore.ProxyScope) (*brokercore.ProxyScope, error)

type filterCapabilities struct {
	capabilities map[string]filterCapability
	mu           sync.Mutex
}

type filterCapability struct {
	expiresAt time.Time
	kind      filterCapabilityKind
	match     *brokercore.CredentialMatch
	request   filterRequest
	scope     brokercore.ProxyScope
	state     filterCapabilityState
}

type filterRequest struct {
	method string
	path   string
	query  string
	scheme string
	target string
}

// ParseFilterProxyURL validates the proxy address advertised to policy
// filters. Plain HTTP is safe only on literal loopback; remote callbacks must
// be protected by HTTPS (typically via a TLS terminator in front of Agent
// Vault's HTTP forward-proxy listener).
func ParseFilterProxyURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, nil
	}
	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse filter proxy url: %w", err)
	}
	if !proxyURL.IsAbs() || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
		return nil, fmt.Errorf("filter proxy url scheme must be http or https")
	}
	if proxyURL.User != nil || proxyURL.Hostname() == "" {
		return nil, fmt.Errorf("filter proxy url must contain a host without userinfo")
	}
	if proxyURL.Path != "" || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return nil, fmt.Errorf("filter proxy url must not contain a path, query, or fragment")
	}
	if proxyURL.Scheme == "http" {
		ip := net.ParseIP(proxyURL.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("http filter proxy url host must be a loopback IP address")
		}
	}
	return proxyURL, nil
}

func newFilterCapabilities() *filterCapabilities {
	return &filterCapabilities{capabilities: make(map[string]filterCapability)}
}

func (c *filterCapabilities) consume(token string, request filterRequest) (*brokercore.CredentialMatch, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	capability, ok := c.capabilities[token]
	delete(c.capabilities, token)
	if !ok || !time.Now().Before(capability.expiresAt) {
		return nil, false
	}
	if capability.kind != filterCapabilityContinuation ||
		capability.state != filterCapabilityClaimed ||
		capability.request != request {
		return nil, false
	}
	return capability.match, capability.match != nil
}

func (c *filterCapabilities) issue(kind filterCapabilityKind, scope *brokercore.ProxyScope, request filterRequest, match *brokercore.CredentialMatch) (string, error) {
	if scope == nil {
		return "", fmt.Errorf("issue filter capability: proxy scope is required")
	}
	if kind == filterCapabilityContinuation && match == nil {
		return "", fmt.Errorf("issue filter continuation: credential match is required")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate filter capability: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(raw[:])
	copyScope := *scope
	if kind == filterCapabilityPolicy {
		copyScope.FilterPolicy = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.removeExpiredLocked(now)
	c.capabilities[token] = filterCapability{
		expiresAt: now.Add(filterCapabilityTTL),
		kind:      kind,
		match:     match,
		request:   request,
		scope:     copyScope,
		state:     filterCapabilityIssued,
	}
	return token, nil
}

func (c *filterCapabilities) removeExpiredLocked(now time.Time) {
	for token, capability := range c.capabilities {
		if !now.Before(capability.expiresAt) {
			delete(c.capabilities, token)
		}
	}
}

// resolve recognizes filter capabilities before the ordinary session
// resolver. Policy capabilities remain reusable for their short lifetime.
// Continuations are claimed once at proxy authentication, then consumed by
// the first exact matching HTTP request inside that connection or CONNECT.
func (c *filterCapabilities) resolve(token, target string) (*brokercore.ProxyScope, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	capability, ok := c.capabilities[token]
	if !ok {
		return nil, false, nil
	}
	if !time.Now().Before(capability.expiresAt) {
		delete(c.capabilities, token)
		return nil, true, brokercore.ErrInvalidSession
	}
	if capability.kind == filterCapabilityPolicy {
		scope := capability.scope
		scope.FilterPolicyExpiresAt = capability.expiresAt
		return &scope, true, nil
	}
	if capability.state != filterCapabilityIssued {
		return nil, true, brokercore.ErrInvalidSession
	}
	if capability.request.target != target {
		delete(c.capabilities, token)
		return nil, true, brokercore.ErrInvalidSession
	}

	capability.state = filterCapabilityClaimed
	capability.scope.FilterContinuation = token
	c.capabilities[token] = capability
	scope := capability.scope
	return &scope, true, nil
}

func (p *Proxy) consumeFilterContinuation(scope *brokercore.ProxyScope, request filterRequest) (*brokercore.CredentialMatch, bool) {
	if scope.FilterContinuation == "" {
		return nil, true
	}
	return p.filterCaps.consume(scope.FilterContinuation, request)
}

func (p *Proxy) filterProxyURL(token string) (string, error) {
	var proxyURL *url.URL
	if p.advertisedFilterProxyURL != nil {
		copyURL := *p.advertisedFilterProxyURL
		proxyURL = &copyURL
	} else {
		p.listenerMu.RLock()
		listenerAddr := p.listenerAddr
		p.listenerMu.RUnlock()
		if listenerAddr == "" {
			return "", fmt.Errorf("filter proxy is not listening")
		}
		_, port, err := net.SplitHostPort(listenerAddr)
		if err != nil {
			return "", fmt.Errorf("parse filter proxy address: %w", err)
		}
		proxyURL = &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", port)}
	}
	proxyURL.User = url.User(token)
	return proxyURL.String(), nil
}

func (p *Proxy) forwardToFilter(
	w http.ResponseWriter,
	r *http.Request,
	target, scheme string,
	scope *brokercore.ProxyScope,
	match *brokercore.CredentialMatch,
) (int, string) {
	filterURL, err := url.Parse(match.Filter.URL)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return http.StatusBadGateway, "filter_config_error"
	}
	if p.advertisedFilterProxyURL == nil && !isLoopbackURL(filterURL) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return http.StatusBadGateway, "filter_proxy_url_required"
	}

	original := filterRequest{
		method: r.Method,
		path:   r.URL.EscapedPath(),
		query:  r.URL.RawQuery,
		scheme: scheme,
		target: target,
	}
	continuationToken, err := p.filterCaps.issue(filterCapabilityContinuation, scope, original, match)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return http.StatusBadGateway, "filter_capability_error"
	}
	continuationProxy, err := p.filterProxyURL(continuationToken)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return http.StatusBadGateway, "filter_capability_error"
	}

	var policyProxy string
	if match.Filter.PolicyVault != "" {
		if p.policyVault == nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return http.StatusBadGateway, "filter_policy_unavailable"
		}
		policyScope, err := p.policyVault(r.Context(), match.Filter.PolicyVault, scope)
		if err != nil || policyScope == nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return http.StatusBadGateway, "filter_policy_unavailable"
		}
		policyToken, err := p.filterCaps.issue(filterCapabilityPolicy, policyScope, filterRequest{}, nil)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return http.StatusBadGateway, "filter_capability_error"
		}
		policyProxy, err = p.filterProxyURL(policyToken)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return http.StatusBadGateway, "filter_capability_error"
		}
	}

	filterReq, err := http.NewRequestWithContext(r.Context(), r.Method, filterURL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return http.StatusBadGateway, "filter_request_error"
	}
	filterReq.ContentLength = r.ContentLength
	brokercore.ApplyInjection(r.Header, filterReq.Header, &brokercore.InjectResult{})
	stripFilterInternalHeaders(filterReq.Header)
	filterReq.Header.Set(filterContinuationProxyHeader, continuationProxy)
	filterReq.Header.Set(filterCAHeader, base64.StdEncoding.EncodeToString(p.ca.RootPEM()))
	if policyProxy != "" {
		filterReq.Header.Set(filterPolicyProxyHeader, policyProxy)
	}
	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     target,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	filterReq.Header.Set(filterTargetURLHeader, targetURL.String())

	resp, err := p.filterUpstream.RoundTrip(filterReq)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return http.StatusBadGateway, "filter_unreachable"
	}
	defer func() { _ = resp.Body.Close() }()

	if p.maxResponseBytes > 0 && resp.ContentLength > p.maxResponseBytes {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return http.StatusBadGateway, "response_too_large"
	}
	for key, values := range resp.Header {
		if brokercore.ShouldStripResponseHeader(key) || isFilterInternalHeader(key) {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	var src io.Reader = resp.Body
	if p.maxResponseBytes > 0 {
		src = io.LimitReader(resp.Body, p.maxResponseBytes)
	}
	var dst io.Writer = w
	if flusher, ok := w.(http.Flusher); ok {
		dst = &flushingWriter{w: w, f: flusher}
	}
	n, _ := io.Copy(dst, src)
	if p.maxResponseBytes > 0 && n == p.maxResponseBytes {
		var probe [1]byte
		if extra, _ := resp.Body.Read(probe[:]); extra > 0 {
			panic(http.ErrAbortHandler)
		}
	}

	return resp.StatusCode, ""
}

func isLoopbackURL(target *url.URL) bool {
	ip := net.ParseIP(target.Hostname())
	return ip != nil && ip.IsLoopback()
}

func (p *Proxy) resolveScope(ctx context.Context, token, hint, target string) (*brokercore.ProxyScope, error) {
	if scope, recognized, err := p.filterCaps.resolve(token, target); recognized {
		return scope, err
	}
	return p.sessions.ResolveForProxy(ctx, token, hint)
}

func isFilterInternalHeader(name string) bool {
	return strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Agent-Vault-")
}

func stripFilterInternalHeaders(h http.Header) {
	for name := range h {
		if isFilterInternalHeader(name) {
			h.Del(name)
		}
	}
}
