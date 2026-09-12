package mitm

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/store"
)

// Hop headers Agent Vault sets on the request to the sidecar.
//
// Proxy URLs and bearer tokens are deliberately separate headers: a
// capability embedded in a URL ends up in request lines and access logs,
// which is exactly where a 30-second bearer must not be.
const (
	HeaderOriginalURL       = "X-Agent-Vault-Original-URL"
	HeaderContinuationProxy = "X-Agent-Vault-Continuation-Proxy"
	HeaderContinuationToken = "X-Agent-Vault-Continuation-Token"
	HeaderPolicyProxy       = "X-Agent-Vault-Policy-Proxy"
	HeaderPolicyToken       = "X-Agent-Vault-Policy-Token"
	HeaderCA                = "X-Agent-Vault-CA"
	HeaderService           = "X-Agent-Vault-Service"

	// headerNamespace is stripped in both directions: off the request
	// before it reaches an origin, and off the sidecar's response before
	// it reaches the client. Namespace-wide rather than a fixed list, so
	// a policy API cannot spoof a control header we add later.
	headerNamespace = "X-Agent-Vault-"
)

// Capability token prefixes, following the existing av_* convention.
// They make the capability path dispatch deterministically instead of
// "try a session, fall back to a capability", and give log redaction
// something to match on.
const (
	continuationTokenPrefix = "av_cont_"
	policyTokenPrefix       = "av_pol_"
)

// DefaultFilterClaimTTL is how long a capability may be claimed for.
//
// It is a deadline to *claim*, not a budget for the work: once a
// continuation is consumed, the stream it authorizes runs under ordinary
// origin and WebSocket timeouts.
const DefaultFilterClaimTTL = 30 * time.Second

// Proxy-error codes on the filter hop.
const (
	errFilterUnreachable   = "filter_unreachable"
	errFilterTimeout       = "filter_timeout"
	errFilterMisconfigured = "filter_misconfigured"
)

// FilterCapabilityStore is the narrow store surface the filter hop uses.
type FilterCapabilityStore interface {
	CreateFilterCapability(ctx context.Context, p store.CreateFilterCapabilityParams) (*store.FilterCapability, string, error)
	GetFilterCapability(ctx context.Context, rawToken string) (*store.FilterCapability, error)
	ConsumeFilterContinuation(ctx context.Context, rawToken string, bind store.FilterCapabilityBind, now time.Time) (*store.FilterCapability, error)
	DeleteFilterCapability(ctx context.Context, rawToken string) error
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultByID(ctx context.Context, id string) (*store.Vault, error)
}

// FilterOptions configures the policy-filter hop. A nil FilterOptions on
// Proxy disables filtering entirely: services carrying a filter block
// then fail closed rather than quietly forwarding unfiltered.
type FilterOptions struct {
	// Store holds capability rows. Required.
	Store FilterCapabilityStore

	// Authority re-checks that a capability's originating session or
	// agent is still live. Required.
	Authority brokercore.SourceAuthorityChecker

	// ProxyBaseURL is the externally reachable forward-proxy URL a remote
	// sidecar should call back on (AGENT_VAULT_FILTER_PROXY_URL). Empty
	// means advertise the process's own loopback listener, which only
	// serves a sidecar on this host.
	ProxyBaseURL string

	// ClaimTTL overrides DefaultFilterClaimTTL.
	ClaimTTL time.Duration
}

// filterEngine carries the per-proxy state the hop needs.
type filterEngine struct {
	opts      FilterOptions
	tls       *http.Client // https sidecars
	cleartext *http.Client // http sidecars: loopback and private only
}

func newFilterEngine(opts FilterOptions) *filterEngine {
	// Two dedicated transports, neither of which consults
	// AGENT_VAULT_ALLOW_PRIVATE_RANGES: where an origin may live has no
	// bearing on where a policy sidecar may live.
	tlsTransport := &http.Transport{
		DialContext:           netguard.SafeDialContext(true),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: filterResponseHeaderTimeout,
	}
	cleartextTransport := &http.Transport{
		DialContext:           netguard.PrivateOnlyDialContext(),
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: filterResponseHeaderTimeout,
	}
	// Redirects are disabled on the filter hop in both directions: a
	// sidecar that answers 302 must not be able to walk the hop, and its
	// capability headers, somewhere else.
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &filterEngine{
		opts:      opts,
		tls:       &http.Client{Transport: tlsTransport, CheckRedirect: noRedirect},
		cleartext: &http.Client{Transport: cleartextTransport, CheckRedirect: noRedirect},
	}
}

// filterResponseHeaderTimeout bounds how long the sidecar has to start
// answering. Exceeding it is a 504; the body that follows streams under
// ordinary origin budgets.
const filterResponseHeaderTimeout = 30 * time.Second

func (e *filterEngine) claimTTL() time.Duration {
	if e.opts.ClaimTTL > 0 {
		return e.opts.ClaimTTL
	}
	return DefaultFilterClaimTTL
}

// client picks the transport for a filter URL. Validation has already
// established that cleartext is either literal loopback or explicitly
// acknowledged, so scheme alone decides here.
func (e *filterEngine) client(u *url.URL) *http.Client {
	if strings.EqualFold(u.Scheme, "http") {
		return e.cleartext
	}
	return e.tls
}

// capabilityKind classifies a Proxy-Authorization token by prefix.
// Returns "" for anything that is not a capability, which is the
// ordinary session path.
func capabilityKind(token string) store.FilterCapabilityKind {
	switch {
	case strings.HasPrefix(token, continuationTokenPrefix):
		return store.FilterCapContinuation
	case strings.HasPrefix(token, policyTokenPrefix):
		return store.FilterCapPolicy
	default:
		return ""
	}
}

// capabilityAuth is a request authenticated by a filter capability
// rather than by a session.
type capabilityAuth struct {
	kind     store.FilterCapabilityKind
	rawToken string
	record   *store.FilterCapability
}

// authenticateCapability validates a capability token and builds the
// proxy scope it acts under.
//
// The TTL is only half the check. The originating session or agent must
// still be live and still granted on the source vault, re-read here on
// every use — including every request inside a persistent CONNECT
// tunnel — so revocation takes effect now rather than in up to 30
// seconds.
func (e *filterEngine) authenticateCapability(ctx context.Context, rawToken string) (*brokercore.ProxyScope, *capabilityAuth, error) {
	kind := capabilityKind(rawToken)
	if kind == "" {
		return nil, nil, brokercore.ErrInvalidSession
	}
	rec, err := e.opts.Store.GetFilterCapability(ctx, rawToken)
	if err != nil {
		return nil, nil, brokercore.ErrInvalidSession
	}
	if rec.Kind != kind {
		return nil, nil, brokercore.ErrInvalidSession
	}
	if rec.IsExpired(time.Now()) {
		return nil, nil, brokercore.ErrInvalidSession
	}
	if rec.FormatVersion != store.FilterMatchSnapshotVersion {
		// A row written by a version we cannot read is not a row we may
		// resolve credentials from.
		return nil, nil, brokercore.ErrInvalidSession
	}

	if err := e.opts.Authority.CheckSourceAuthority(ctx, brokercore.SourceAuthority{
		SessionHash: rec.SourceSessionHash,
		ActorID:     rec.ActorID,
		AgentID:     rec.SourceAgentID,
		VaultID:     rec.VaultID,
	}); err != nil {
		return nil, nil, err
	}

	// A continuation acts in the source vault; a policy capability acts
	// in the vault it was scoped to.
	vaultID := rec.VaultID
	if kind == store.FilterCapPolicy {
		if rec.PolicyVaultID == "" {
			return nil, nil, brokercore.ErrInvalidSession
		}
		vaultID = rec.PolicyVaultID
	}
	v, err := e.opts.Store.GetVaultByID(ctx, vaultID)
	if err != nil || v == nil {
		return nil, nil, brokercore.ErrVaultNotFound
	}

	// Audit and rate-limit attribution stay with the actor that made the
	// original request, not with the sidecar.
	scope := &brokercore.ProxyScope{
		AgentID:     rec.SourceAgentID,
		VaultID:     v.ID,
		VaultName:   v.Name,
		VaultRole:   "proxy",
		SessionHash: rec.SourceSessionHash,
	}
	if rec.SourceAgentID == "" {
		scope.UserID = rec.ActorID
	}
	return scope, &capabilityAuth{kind: kind, rawToken: rawToken, record: rec}, nil
}

// bindFor builds the exact-request binding for a target.
//
// EscapedPath and RawQuery are taken verbatim rather than in decoded
// form: two different wire requests can decode to the same path, and
// only one of them is the request the filter actually saw.
func bindFor(method, scheme, authority string, u *url.URL) store.FilterCapabilityBind {
	return store.FilterCapabilityBind{
		Method:    method,
		Scheme:    scheme,
		Authority: authority,
		Path:      u.EscapedPath(),
		Query:     u.RawQuery,
	}
}

// mintCapabilities issues the continuation, and the policy capability
// when the service asks for one.
//
// An omitted policy_vault mints nothing: a filter that decides from the
// request alone is given no standing authority at all.
func (e *filterEngine) mintCapabilities(
	ctx context.Context,
	scope *brokercore.ProxyScope,
	match *brokercore.CredentialMatch,
	bind store.FilterCapabilityBind,
) (continuation string, policy string, err error) {
	snapshot, err := brokercore.FreezeMatch(match)
	if err != nil {
		return "", "", err
	}
	svc := match.Service

	base := store.CreateFilterCapabilityParams{
		VaultID:           scope.VaultID,
		ActorID:           scope.ActorID(),
		SourceSessionHash: scope.SessionHash,
		SourceAgentID:     scope.AgentID,
		ServiceName:       svc.Name,
		MatchSnapshot:     snapshot,
		TTL:               e.claimTTL(),
	}

	contParams := base
	contParams.Kind = store.FilterCapContinuation
	contParams.Bind = bind
	if _, continuation, err = e.opts.Store.CreateFilterCapability(ctx, contParams); err != nil {
		return "", "", err
	}

	policyVaultName := svc.FilterPolicyVault()
	if policyVaultName == "" {
		return continuation, "", nil
	}

	pv, gerr := e.opts.Store.GetVault(ctx, policyVaultName)
	if gerr != nil || pv == nil {
		// The configured policy vault has gone. Fail the hop rather than
		// silently downgrading to "no side channel" — the filter would
		// then deny every request for reasons the operator cannot see.
		_ = e.opts.Store.DeleteFilterCapability(ctx, continuation)
		return "", "", fmt.Errorf("filter: policy_vault %q not found", policyVaultName)
	}

	polParams := base
	polParams.Kind = store.FilterCapPolicy
	polParams.PolicyVaultID = pv.ID
	if _, policy, err = e.opts.Store.CreateFilterCapability(ctx, polParams); err != nil {
		_ = e.opts.Store.DeleteFilterCapability(ctx, continuation)
		return "", "", err
	}
	return continuation, policy, nil
}

// discard removes capabilities minted for a hop that then failed, so a
// stillborn continuation is not left spendable for its whole TTL.
func (e *filterEngine) discard(ctx context.Context, tokens ...string) {
	for _, t := range tokens {
		if t != "" {
			_ = e.opts.Store.DeleteFilterCapability(ctx, t)
		}
	}
}

// callbackURL is the proxy base URL advertised to the sidecar.
// A configured AGENT_VAULT_FILTER_PROXY_URL wins; otherwise the sidecar
// is assumed to be on this host and gets the local listener.
func (e *filterEngine) callbackURL(localAddr string) string {
	if e.opts.ProxyBaseURL != "" {
		return strings.TrimRight(e.opts.ProxyBaseURL, "/")
	}
	return "http://" + localAddr
}

// setHopHeaders overwrites the reserved namespace on the outbound
// request. Every value is *set*, never added, so a client cannot smuggle
// its own copy of a control header through to the sidecar.
func setHopHeaders(h http.Header, originalURL, serviceName, callback, continuation, policy string, caPEM []byte) {
	stripNamespace(h)
	h.Set(HeaderOriginalURL, originalURL)
	h.Set(HeaderService, serviceName)
	h.Set(HeaderContinuationProxy, callback)
	h.Set(HeaderContinuationToken, continuation)
	if policy != "" {
		h.Set(HeaderPolicyProxy, callback)
		h.Set(HeaderPolicyToken, policy)
	}
	if len(caPEM) > 0 {
		h.Set(HeaderCA, base64.StdEncoding.EncodeToString(caPEM))
	}
}

// stripNamespace removes every reserved header from h.
func stripNamespace(h http.Header) {
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), headerNamespace) {
			h.Del(name)
		}
	}
}

// filterErrorStatus maps a hop failure to its status and error code.
// Everything here happens before any credential is resolved.
func filterErrorStatus(err error) (int, string) {
	if err == nil {
		return http.StatusBadGateway, errFilterUnreachable
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout, errFilterTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, errFilterTimeout
	}
	return http.StatusBadGateway, errFilterUnreachable
}

// filterHopTarget builds the sidecar URL for an incoming request.
//
// The filter URL is treated as an *origin*: its own path is a prefix and
// the original path and query are preserved after it, so a sidecar can
// route on what the client actually asked for.
func filterHopTarget(filterURL string, orig *url.URL) (*url.URL, error) {
	base, err := url.Parse(filterURL)
	if err != nil {
		return nil, err
	}
	out := *base
	basePath := strings.TrimRight(base.EscapedPath(), "/")
	out.Path = ""
	out.RawPath = ""
	out.Opaque = ""
	joined := basePath + orig.EscapedPath()
	if joined == "" {
		joined = "/"
	}
	parsedPath, err := url.Parse(joined)
	if err != nil {
		return nil, err
	}
	out.Path = parsedPath.Path
	out.RawPath = parsedPath.RawPath
	out.RawQuery = orig.RawQuery
	return &out, nil
}

// policyCapabilityMayUse reports whether a policy capability is allowed
// to invoke the service it just matched.
//
// A policy capability may never invoke *any* filtered service, not just
// the one it came from. Allowing it would start a second filter hop and
// mint a second set of capabilities, and a stolen capability could walk
// the chain; a git sidecar calling a filtered OpenAI service fails here
// instead.
func policyCapabilityMayUse(match *brokercore.CredentialMatch) bool {
	return !match.HasFilter()
}

// filterURLFor returns the parsed sidecar URL for a matched service.
func filterURLFor(svc *broker.Service) (*url.URL, error) {
	if !svc.HasFilter() {
		return nil, errors.New("mitm: service has no filter")
	}
	return url.Parse(svc.Filter.URL)
}

// serveFilterHop reverse-proxies a matched request to its sidecar.
//
// The destination credential is still encrypted at every point in here.
// The sidecar's answer — whatever its status — is the client's answer,
// unless the sidecar instead calls back with the continuation, which is
// a separate request that arrives through the normal ingress.
func (p *Proxy) serveFilterHop(
	w http.ResponseWriter,
	r *http.Request,
	target, scheme string,
	outURL *url.URL,
	scope *brokercore.ProxyScope,
	match *brokercore.CredentialMatch,
	emit func(status int, errCode string),
) {
	ctx := r.Context()
	svc := match.Service

	filterURL, err := filterURLFor(svc)
	if err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, errFilterMisconfigured,
			"The policy filter for this service is not configured correctly.")
		emit(http.StatusBadGateway, errFilterMisconfigured)
		return
	}
	hopURL, err := filterHopTarget(svc.Filter.URL, outURL)
	if err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, errFilterMisconfigured,
			"The policy filter URL for this service could not be resolved.")
		emit(http.StatusBadGateway, errFilterMisconfigured)
		return
	}

	bind := bindFor(r.Method, scheme, target, outURL)
	continuation, policy, err := p.filter.mintCapabilities(ctx, scope, match, bind)
	if err != nil {
		// A capability that cannot be minted is a capability that cannot
		// be checked. Fail closed rather than hopping without one.
		p.logger.Warn("filter capability mint failed",
			slog.String("vault_id", scope.VaultID),
			slog.String("service", svc.Name),
			slog.String("error", err.Error()),
		)
		brokercore.WriteProxyError(w, http.StatusBadGateway, errFilterMisconfigured,
			"The policy filter could not be invoked for this request.")
		emit(http.StatusBadGateway, errFilterMisconfigured)
		return
	}

	callback := p.filter.callbackURL(p.listenAddr())
	originalURL := outURL.String()

	if isWebSocketUpgrade(r) {
		p.serveFilterWebSocket(w, r, hopURL, filterURL, svc, originalURL, callback, continuation, policy, emit)
		return
	}

	hopReq, err := http.NewRequestWithContext(ctx, r.Method, hopURL.String(), r.Body)
	if err != nil {
		p.filter.discard(ctx, continuation, policy)
		brokercore.WriteProxyError(w, http.StatusBadGateway, errFilterMisconfigured,
			"The policy filter request could not be constructed.")
		emit(http.StatusBadGateway, errFilterMisconfigured)
		return
	}
	hopReq.ContentLength = r.ContentLength

	// Client headers pass through minus hop-by-hop and broker-scoped
	// ones: the inbound agent session must not reach the sidecar, which
	// gets capabilities of its own instead.
	brokercore.ApplyInjection(r.Header, hopReq.Header, &brokercore.InjectResult{})
	// The sidecar routes on what the client actually asked for.
	hopReq.Host = hostHeaderForScheme(scheme, target)
	setHopHeaders(hopReq.Header, originalURL, svc.Name, callback, continuation, policy, p.ca.RootPEM())

	resp, err := p.filter.client(filterURL).Do(hopReq)
	if err != nil {
		p.filter.discard(ctx, continuation, policy)
		status, code := filterErrorStatus(err)
		p.logger.Warn("filter hop failed",
			slog.String("vault_id", scope.VaultID),
			slog.String("service", svc.Name),
			slog.String("filter_host", filterURL.Host),
			slog.String("error", err.Error()),
		)
		brokercore.WriteProxyError(w, status, code,
			"The policy filter for this service could not be reached.")
		emit(status, code)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// The sidecar's response is the client's response, at whatever status
	// it chose — Agent Vault does not translate a denial into a fixed
	// 403. The reserved namespace is stripped on the way back so a policy
	// API cannot spoof a control header at the agent.
	for k, vv := range resp.Header {
		ck := http.CanonicalHeaderKey(k)
		if brokercore.ShouldStripResponseHeader(ck) || strings.HasPrefix(ck, headerNamespace) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if _, err := io.Copy(newFlushingWriter(w), resp.Body); err != nil {
		p.logger.Debug("filter response copy failed",
			slog.String("service", svc.Name),
			slog.String("error", err.Error()),
		)
	}
	emit(resp.StatusCode, "")
}

// serveFilterWebSocket reverse-proxies an upgrade to the sidecar.
//
// The sidecar either answers the handshake with an ordinary rejection,
// or opens its own WebSocket through the continuation and bridges. Once
// an upgrade succeeds the existing 10-minute idle budget governs the
// stream; the capability TTL is a deadline to claim, not a cap on the
// conversation.
func (p *Proxy) serveFilterWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	hopURL, filterURL *url.URL,
	svc *broker.Service,
	originalURL, callback, continuation, policy string,
	emit func(status int, errCode string),
) {
	wsURL := *hopURL
	hopReq, err := http.NewRequestWithContext(r.Context(), r.Method, wsURL.String(), nil)
	if err != nil {
		p.filter.discard(r.Context(), continuation, policy)
		brokercore.WriteProxyError(w, http.StatusBadGateway, errFilterMisconfigured,
			"The policy filter request could not be constructed.")
		emit(http.StatusBadGateway, errFilterMisconfigured)
		return
	}
	brokercore.ApplyInjection(r.Header, hopReq.Header, &brokercore.InjectResult{}, websocketHandshakeHeaderNames...)
	copyWebSocketHandshakeHeaders(r.Header, hopReq.Header)
	hopReq.Host = wsURL.Host
	setHopHeaders(hopReq.Header, originalURL, svc.Name, callback, continuation, policy, p.ca.RootPEM())

	// No substitutions on this hop: nothing has been resolved yet, which
	// is the entire point of running the filter first.
	p.forwardWebSocket(w, r, hopReq, nil, emit, p.filter.dialer(filterURL), true)
}

// dialer exposes the transport a filter URL should travel on, for the
// WebSocket path which dials by hand rather than through http.Client.
func (e *filterEngine) dialer(u *url.URL) dialFunc {
	tr, _ := e.client(u).Transport.(*http.Transport)
	if tr == nil {
		return nil
	}
	return tr.DialContext
}

// newFlushingWriter wraps w so a streaming sidecar response reaches the
// client as it arrives rather than sitting in a buffer.
func newFlushingWriter(w http.ResponseWriter) io.Writer {
	if f, ok := w.(http.Flusher); ok {
		return &flushingWriter{w: w, f: f}
	}
	return w
}

// ValidateFilterProxyURL checks an AGENT_VAULT_FILTER_PROXY_URL value.
//
// This is the address a sidecar is told to send capabilities to, so the
// same transport rule as filter.url applies in reverse: TLS, unless it
// is unambiguously a literal loopback address and therefore never
// crosses a network at all.
func ValidateFilterProxyURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return fmt.Errorf("AGENT_VAULT_FILTER_PROXY_URL %q is not a valid URL", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("AGENT_VAULT_FILTER_PROXY_URL %q must include a host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("AGENT_VAULT_FILTER_PROXY_URL %q must not contain userinfo", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if broker.IsLoopbackURLHost(u.Host) {
			return nil
		}
		return fmt.Errorf("AGENT_VAULT_FILTER_PROXY_URL %q is cleartext http to a non-loopback host — "+
			"a sidecar sends capabilities to this address, so it must be https", raw)
	default:
		return fmt.Errorf("AGENT_VAULT_FILTER_PROXY_URL %q must use http or https", raw)
	}
}
