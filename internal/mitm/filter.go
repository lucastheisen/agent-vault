package mitm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

const (
	filterCapabilityTTL = 30 * time.Second

	filterContinuationProxyHeader = brokercore.HeaderFilterContinuationProxy
	filterContinuationTokenHeader = brokercore.HeaderFilterContinuationToken
	filterCAHeader                = brokercore.HeaderFilterCA
	filterPolicyProxyHeader       = brokercore.HeaderFilterPolicyProxy
	filterPolicyTokenHeader       = brokercore.HeaderFilterPolicyToken
	filterTargetURLHeader         = brokercore.HeaderFilterOriginalURL
	filterServiceHeader           = brokercore.HeaderFilterService
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

// FilterCapabilityStore is the narrow shared-store surface required by the
// proxy. store.Store satisfies it. A nil store selects the test-only
// single-process backend below; production wiring always supplies the shared
// database store.
type FilterCapabilityStore interface {
	CreateFilterCapability(context.Context, *store.FilterCapability) (string, error)
	ResolveFilterCapability(context.Context, string, string, time.Time) (*store.FilterCapability, error)
	ConsumeFilterContinuation(context.Context, string, store.FilterRequestBinding, time.Time) (*store.FilterCapability, error)
	ValidateFilterPolicyCapability(context.Context, string, time.Time) (*store.FilterCapability, error)
}

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

func (p *Proxy) consumeFilterContinuation(ctx context.Context, scope *brokercore.ProxyScope, request filterRequest) (*brokercore.CredentialMatch, bool) {
	if scope.FilterContinuation == "" {
		return nil, true
	}
	if p.filterCapabilityStore != nil {
		capability, err := p.filterCapabilityStore.ConsumeFilterContinuation(ctx, scope.FilterContinuation, request.storeBinding(), time.Now())
		if err != nil || capability == nil || capability.SnapshotVersion != brokercore.CredentialMatchSnapshotVersion {
			return nil, false
		}
		match, err := brokercore.RestoreCredentialMatch(capability.SnapshotJSON)
		return match, err == nil
	}
	return p.filterCaps.consume(scope.FilterContinuation, request)
}

func (r filterRequest) storeBinding() store.FilterRequestBinding {
	return store.FilterRequestBinding{Method: r.method, Scheme: r.scheme, Authority: r.target, Path: r.path, Query: r.query}
}

func (p *Proxy) filterProxyURL() (string, error) {
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
	proxyURL.User = nil
	return proxyURL.String(), nil
}

func (p *Proxy) issueFilterCapability(
	ctx context.Context,
	kind filterCapabilityKind,
	source, target *brokercore.ProxyScope,
	request filterRequest,
	match *brokercore.CredentialMatch,
) (string, error) {
	if p.filterCapabilityStore == nil {
		return p.filterCaps.issue(kind, target, request, match)
	}
	if source == nil || target == nil || source.SourceSessionHash == "" {
		return "", fmt.Errorf("issue filter capability: source authority is incomplete")
	}
	actorType, actorID := actorFromScope(source)
	if actorType == "" || actorID == "" {
		return "", fmt.Errorf("issue filter capability: source actor is required")
	}
	record := &store.FilterCapability{
		Kind:              store.FilterCapabilityPolicy,
		SourceVaultID:     source.VaultID,
		SourceSessionHash: source.SourceSessionHash,
		SourceActorID:     actorID,
		SourceActorType:   actorType,
		SourceAgentID:     source.AgentID,
		TargetVaultID:     target.VaultID,
		TargetVaultName:   target.VaultName,
		TargetVaultRole:   target.VaultRole,
		ExpiresAt:         time.Now().Add(filterCapabilityTTL),
	}
	if kind == filterCapabilityContinuation {
		snapshot, err := match.Freeze()
		if err != nil {
			return "", fmt.Errorf("freeze credential match: %w", err)
		}
		record.Kind = store.FilterCapabilityContinuation
		record.Request = request.storeBinding()
		record.SnapshotVersion = brokercore.CredentialMatchSnapshotVersion
		record.SnapshotJSON = snapshot
	}
	return p.filterCapabilityStore.CreateFilterCapability(ctx, record)
}

func (p *Proxy) forwardToFilter(
	w http.ResponseWriter,
	r *http.Request,
	target, scheme string,
	scope *brokercore.ProxyScope,
	match *brokercore.CredentialMatch,
) (int, string) {
	if match.Filter == nil || match.Filter.Validate() != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "service filter configuration is invalid")
		return http.StatusBadGateway, "filter_misconfigured"
	}
	filterURL, err := url.Parse(match.Filter.URL)
	if err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "service filter configuration is invalid")
		return http.StatusBadGateway, "filter_misconfigured"
	}
	if p.advertisedFilterProxyURL == nil && !isLoopbackURL(filterURL) {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "AGENT_VAULT_FILTER_PROXY_URL is required for a remote filter")
		return http.StatusBadGateway, "filter_misconfigured"
	}

	original := filterRequest{
		method: r.Method,
		path:   r.URL.EscapedPath(),
		query:  r.URL.RawQuery,
		scheme: scheme,
		target: target,
	}
	continuationToken, err := p.issueFilterCapability(r.Context(), filterCapabilityContinuation, scope, scope, original, match)
	if err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "failed to create filter continuation")
		return http.StatusBadGateway, "filter_misconfigured"
	}
	continuationProxy, err := p.filterProxyURL()
	if err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "filter callback proxy is unavailable")
		return http.StatusBadGateway, "filter_misconfigured"
	}

	var policyToken string
	if match.Filter.PolicyVault != "" {
		if p.policyVault == nil {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "filter policy vault resolver is unavailable")
			return http.StatusBadGateway, "filter_misconfigured"
		}
		policyScope, err := p.policyVault(r.Context(), match.Filter.PolicyVault, scope)
		if err != nil || policyScope == nil {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "filter policy vault is unavailable")
			return http.StatusBadGateway, "filter_misconfigured"
		}
		policyToken, err = p.issueFilterCapability(r.Context(), filterCapabilityPolicy, scope, policyScope, filterRequest{}, nil)
		if err != nil {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "failed to create filter policy capability")
			return http.StatusBadGateway, "filter_misconfigured"
		}
	}

	filterTarget := *filterURL
	basePath := strings.TrimRight(filterTarget.Path, "/")
	if basePath == "" {
		filterTarget.Path = r.URL.Path
		filterTarget.RawPath = r.URL.RawPath
	} else {
		filterTarget.Path = basePath + r.URL.Path
		// Preserve the original escaped request path when the filter URL has a
		// base path. Clearing RawPath here would turn an encoded slash (%2F)
		// into a path separator before the sidecar sees it.
		filterTarget.RawPath = strings.TrimRight(filterURL.EscapedPath(), "/") + r.URL.EscapedPath()
	}
	filterTarget.RawQuery = r.URL.RawQuery
	filterReq, err := http.NewRequestWithContext(r.Context(), r.Method, filterTarget.String(), r.Body)
	if err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured", "failed to build filter request")
		return http.StatusBadGateway, "filter_misconfigured"
	}
	filterReq.ContentLength = r.ContentLength
	wsUpgrade := isWebSocketUpgrade(r)
	if wsUpgrade {
		copyWebSocketHandshakeHeaders(r.Header, filterReq.Header)
		brokercore.ApplyInjection(r.Header, filterReq.Header, &brokercore.InjectResult{}, websocketHandshakeHeaderNames...)
	} else {
		brokercore.ApplyInjection(r.Header, filterReq.Header, &brokercore.InjectResult{})
	}
	stripFilterInternalHeaders(filterReq.Header)
	filterReq.Host = hostHeaderForScheme(scheme, target)
	filterReq.Header.Set(filterContinuationProxyHeader, continuationProxy)
	filterReq.Header.Set(filterContinuationTokenHeader, continuationToken)
	filterReq.Header.Set(filterCAHeader, base64.StdEncoding.EncodeToString(p.ca.RootPEM()))
	if policyToken != "" {
		filterReq.Header.Set(filterPolicyProxyHeader, continuationProxy)
		filterReq.Header.Set(filterPolicyTokenHeader, policyToken)
	}
	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     target,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	filterReq.Header.Set(filterTargetURLHeader, targetURL.String())
	filterReq.Header.Set(filterServiceHeader, match.MatchedName)

	transport := p.filterUpstream
	if filterURL.Scheme == "http" {
		transport = p.filterPrivateUpstream
	}
	if wsUpgrade {
		status, code := http.StatusBadGateway, "filter_unreachable"
		p.forwardWebSocketVia(w, r, filterReq, nil, transport, true, func(s int, c string) {
			status, code = s, c
		})
		if code == "upstream_error" {
			code = "filter_unreachable"
		}
		return status, code
	}

	resp, err := transport.RoundTrip(filterReq)
	if err != nil {
		status, code := http.StatusBadGateway, "filter_unreachable"
		if isFilterTimeout(err) {
			status, code = http.StatusGatewayTimeout, "filter_timeout"
		}
		brokercore.WriteProxyError(w, status, code, "service filter is unreachable")
		return status, code
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

func isFilterTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isLoopbackURL(target *url.URL) bool {
	ip := net.ParseIP(target.Hostname())
	return ip != nil && ip.IsLoopback()
}

func (p *Proxy) resolveScope(ctx context.Context, token, hint, target string) (*brokercore.ProxyScope, error) {
	if p.filterCapabilityStore != nil && strings.HasPrefix(token, store.FilterCapabilityTokenPrefix) {
		capability, err := p.filterCapabilityStore.ResolveFilterCapability(ctx, token, target, time.Now())
		if err != nil || capability == nil {
			return nil, brokercore.ErrInvalidSession
		}
		scope := &brokercore.ProxyScope{
			VaultID: capability.TargetVaultID, VaultName: capability.TargetVaultName,
			VaultRole: capability.TargetVaultRole, SourceSessionHash: capability.SourceSessionHash,
		}
		if capability.SourceActorType == brokercore.ActorTypeUser {
			scope.UserID = capability.SourceActorID
		} else {
			scope.AgentID = capability.SourceActorID
		}
		switch capability.Kind {
		case store.FilterCapabilityPolicy:
			scope.FilterPolicy = true
			scope.FilterPolicyExpiresAt = capability.ExpiresAt
			scope.FilterPolicyCapability = token
		case store.FilterCapabilityContinuation:
			scope.FilterContinuation = token
		default:
			return nil, brokercore.ErrInvalidSession
		}
		return scope, nil
	}
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
