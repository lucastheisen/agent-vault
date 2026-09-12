// Package mitm implements an HTTP/1.1 forward-proxy ingress for agent
// traffic.
//
// A Proxy accepts two request shapes on the same listener:
//
//   - CONNECT host:port — for HTTPS upstreams. The proxy hijacks the
//     connection, terminates client-side TLS using a leaf minted on
//     demand by a ca.Provider, and forwards each tunnelled HTTP/1.1
//     request to the originally-requested upstream over a fresh TLS
//     connection with strict verification against the system trust
//     store.
//
//   - Absolute-form forward-proxy requests (e.g. POST http://host/path
//     HTTP/1.1, RFC 7230 §5.3.2) — for plain-HTTP upstreams. The proxy
//     authenticates the request inline (no hijack), forwards the body
//     to the upstream over plain HTTP, and applies the same credential
//     injection, host policy, and request logging as the CONNECT path.
//
// The listener is plain HTTP (standard forward-proxy convention).
// Clients use HTTPS_PROXY and HTTP_PROXY pointing at http://... and
// trust the CA that signs the per-host MITM leaves for upstream
// certificate verification.
//
// v1 scope: HTTP/1.1 only (ALPN pinned). HTTPS upstreams must use
// CONNECT — the forward-proxy path rejects https:// URLs to avoid
// silently TLS-stripping.
package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

// Proxy is a transparent MITM proxy. It is safe to start at most once;
// reuse across Shutdown is not supported.
type Proxy struct {
	ca                       ca.Provider
	sessions                 brokercore.SessionResolver
	creds                    brokercore.CredentialProvider
	httpServer               *http.Server
	upstream                 *http.Transport
	filterUpstream           *http.Transport
	filterPrivateUpstream    *http.Transport
	filterCaps               *filterCapabilities
	filterCapabilityStore    FilterCapabilityStore
	policyVault              PolicyVaultResolver
	advertisedFilterProxyURL *url.URL
	listenerMu               sync.RWMutex
	listenerAddr             string
	isListening              atomic.Bool
	baseURL                  string // externally-reachable control-plane URL for help links
	logger                   *slog.Logger
	rateLimit                *ratelimit.Registry // shared with the HTTP server; nil = no-op
	logSink                  requestlog.Sink     // never nil (Nop default); shared with the HTTP server
	maxResponseBytes         int64               // 0 = unlimited
	maxRequestBytes          int64
}

// Options carries the dependencies a Proxy needs. BaseURL is the
// externally-reachable control-plane URL used in help-link error
// responses. Logger must be non-nil; tests can pass
// slog.New(slog.DiscardHandler). RateLimit is shared with the HTTP
// server so proxy limits and control-plane limits live in one registry;
// nil disables rate limiting on the MITM path.
type Options struct {
	CA               ca.Provider
	Sessions         brokercore.SessionResolver
	Credentials      brokercore.CredentialProvider
	BaseURL          string
	Logger           *slog.Logger
	RateLimit        *ratelimit.Registry
	LogSink          requestlog.Sink // nil → Nop
	MaxResponseBytes int64           // 0 = unlimited (default); >0 = cap in bytes
	MaxRequestBytes  int64           // 0 → DefaultMaxRequestBytes (1 GiB)
	// PolicyVault resolves the vault whose credentials a filter may use
	// for its own policy checks. Nil disables policy-vault capabilities.
	PolicyVault PolicyVaultResolver
	// FilterProxyURL is the externally reachable forward-proxy URL supplied
	// to filters. Nil advertises this listener on 127.0.0.1, which is suitable
	// only for a filter running on the same host.
	FilterProxyURL *url.URL
	// FilterCapabilities enables the production shared capability backend.
	// Nil uses the single-process in-memory backend intended for tests/dev.
	FilterCapabilities FilterCapabilityStore
}

// New builds a Proxy bound to addr. The returned Proxy does not begin
// listening until ListenAndServe is called.
func New(addr string, opts Options) *Proxy {
	upstream := &http.Transport{
		DialContext:           netguard.SafeDialContext(netguard.AllowPrivateFromEnv()),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
	filterUpstream := newFilterTransport(false)
	filterPrivateUpstream := newFilterTransport(true)

	sink := opts.LogSink
	if sink == nil {
		sink = requestlog.Nop{}
	}

	maxReq := opts.MaxRequestBytes
	if maxReq <= 0 {
		maxReq = brokercore.DefaultMaxRequestBytes
	}

	p := &Proxy{
		ca:                       opts.CA,
		sessions:                 opts.Sessions,
		creds:                    opts.Credentials,
		upstream:                 upstream,
		filterUpstream:           filterUpstream,
		filterPrivateUpstream:    filterPrivateUpstream,
		filterCaps:               newFilterCapabilities(),
		filterCapabilityStore:    opts.FilterCapabilities,
		policyVault:              opts.PolicyVault,
		advertisedFilterProxyURL: opts.FilterProxyURL,
		baseURL:                  opts.BaseURL,
		logger:                   opts.Logger,
		rateLimit:                opts.RateLimit,
		logSink:                  sink,
		maxResponseBytes:         opts.MaxResponseBytes, // 0 = unlimited
		maxRequestBytes:          maxReq,
	}
	p.httpServer = &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(p.dispatch),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return p
}

// newFilterTransport builds the dedicated sidecar dial policy. HTTPS filters
// use privateOnly=false (public and private destinations are allowed, while
// link-local/unspecified addresses are always blocked). Cleartext HTTP uses
// privateOnly=true and can dial only loopback/RFC1918 addresses. Hostnames are
// resolved and every answer is checked on every connection.
func newFilterTransport(privateOnly bool) *http.Transport {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("filter dial address: %w", err)
			}
			var addresses []net.IPAddr
			if ip := net.ParseIP(host); ip != nil {
				addresses = []net.IPAddr{{IP: ip}}
			} else {
				addresses, err = net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
			}
			if len(addresses) == 0 {
				return nil, fmt.Errorf("filter host %q resolved to no addresses", host)
			}
			for _, resolved := range addresses {
				ip := resolved.IP
				if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
					(privateOnly && !ip.IsLoopback() && !isRFC1918Address(ip)) {
					return nil, fmt.Errorf("filter host %q resolves to blocked address %s", host, ip)
				}
			}
			var lastErr error
			for _, resolved := range addresses {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
}

func isRFC1918Address(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

// Addr returns the listener address the Proxy was configured with.
func (p *Proxy) Addr() string { return p.httpServer.Addr }

// RootPEM returns the root CA certificate in PEM form. Safe for public
// distribution — clients install this into trust stores to validate the
// leaves minted on demand during CONNECT.
func (p *Proxy) RootPEM() []byte { return p.ca.RootPEM() }

// IsListening reports whether the Proxy has successfully bound its
// listener and is accepting connections. Callers that gate operator-
// visible behavior (like advertising the root CA) on proxy reachability
// should check this rather than nil-checking the Proxy itself — a bind
// failure leaves the Proxy value alive but unreachable.
func (p *Proxy) IsListening() bool { return p.isListening.Load() }

// ListenAndServe starts accepting connections. It binds the listener
// eagerly so callers can detect bind failures; on success, IsListening
// reports true for the lifetime of the accept loop. Blocks until
// Shutdown, returning http.ErrServerClosed in that case.
func (p *Proxy) ListenAndServe() error {
	l, err := net.Listen("tcp", p.httpServer.Addr)
	if err != nil {
		return err
	}
	return p.Serve(l)
}

// Serve accepts connections on the provided listener. The listener
// itself is plain HTTP (standard forward-proxy convention); TLS is
// only used inside CONNECT tunnels where the MITM presents a leaf
// cert to the client. It blocks until Shutdown is called, returning
// http.ErrServerClosed in that case.
// Useful for tests that need to bind :0 and learn the resulting port.
func (p *Proxy) Serve(l net.Listener) error {
	p.isListening.Store(true)
	defer p.isListening.Store(false)
	p.listenerMu.Lock()
	p.listenerAddr = l.Addr().String()
	p.listenerMu.Unlock()
	return p.httpServer.Serve(l)
}

// Shutdown gracefully stops the listener. In-flight CONNECT tunnels are
// not tracked by http.Server's shutdown machinery (they detach from the
// handler on Hijack), so callers should allow the process to exit after
// Shutdown returns; the tunnels will die with it.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.upstream.CloseIdleConnections()
	p.filterUpstream.CloseIdleConnections()
	p.filterPrivateUpstream.CloseIdleConnections()
	return p.httpServer.Shutdown(ctx)
}

func (p *Proxy) dispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if isAbsoluteForwardProxyRequest(r) {
		p.handleForward(w, r)
		return
	}
	// Origin-form (no scheme/host), https://, ws://, file://, gopher://,
	// etc. all land here. The CONNECT-vs-forward split above already
	// covers every legitimate forward-proxy shape; anything else is a
	// malformed request, not a method-not-allowed.
	http.Error(w, "this endpoint is an HTTP forward proxy; non-CONNECT requests must use absolute-form URLs (http://host/path). Use CONNECT for https:// upstreams.", http.StatusBadRequest)
}
