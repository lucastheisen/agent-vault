package mitm

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

type matchingCredProvider struct {
	fakeCredProvider
	svc *broker.Service
}

func (m *matchingCredProvider) Match(_ context.Context, _, targetHost string, _ int, _ string) (*broker.Service, error) {
	host := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		host = h
	}
	if m.svc != nil && (m.svc.Host == host || m.svc.Host == "*") {
		return m.svc, nil
	}
	return nil, nil
}

func capResolver(caps brokercore.CapabilityStore, fallback *brokercore.ProxyScope) *fakeSessionResolver {
	return &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		if brokercore.IsCapabilityToken(token) {
			c, err := caps.Authenticate(context.Background(), token)
			if err != nil {
				return nil, err
			}
			scope := c.Scope()
			scope.RawToken = token
			return scope, nil
		}
		if fallback != nil {
			cp := *fallback
			cp.RawToken = token
			return &cp, nil
		}
		return nil, brokercore.ErrInvalidSession
	}}
}

func TestMITMFilterHopShortCircuit(t *testing.T) {
	var sawOrig, sawCont, sawProxy, sawSvc, sawAuth string
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawOrig = r.Header.Get(brokercore.HeaderOriginalURL)
		sawCont = r.Header.Get(brokercore.HeaderContinuationToken)
		sawProxy = r.Header.Get(brokercore.HeaderContinuationProxy)
		sawSvc = r.Header.Get(brokercore.HeaderService)
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"protected"}`)
	}))
	defer filter.Close()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be contacted when the filter short-circuits")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	caps := brokercore.NewMemoryCapabilities()
	sr := capResolver(caps, &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy", AgentID: "agent-1"})
	cp := &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			upstreamHost: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer secret"}}},
		}},
		svc: &broker.Service{
			Name: "github-push",
			Host: upstreamHost,
			Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
			Filter: &broker.Filter{
				URL:         filter.URL,
				PolicyVault: "default",
			},
		},
	}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.Capabilities = caps
	})
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	req, err := http.NewRequest("GET", upstream.URL+"/org/repo.git/git-receive-pack", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body %s", resp.StatusCode, body)
	}
	if !strings.HasPrefix(sawCont, brokercore.ContinuationTokenPrefix) {
		t.Fatalf("continuation = %q", sawCont)
	}
	if sawProxy == "" {
		t.Fatal("expected continuation proxy URL")
	}
	if sawSvc != "github-push" {
		t.Fatalf("service = %q", sawSvc)
	}
	if !strings.Contains(sawOrig, upstreamHost) {
		t.Fatalf("original url = %q", sawOrig)
	}
	if sawAuth != "" {
		t.Fatalf("origin credential leaked onto filter hop: %q", sawAuth)
	}
}

func TestMITMFilterHopOverwritesClientHopHeaders(t *testing.T) {
	var sawCont, sawVault, sawProxyAuth string
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCont = r.Header.Get(brokercore.HeaderContinuationToken)
		sawVault = r.Header.Get("X-Vault")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer filter.Close()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be contacted")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	caps := brokercore.NewMemoryCapabilities()
	sr := capResolver(caps, &brokercore.ProxyScope{VaultID: "v1", VaultName: "dev", VaultRole: "proxy", AgentID: "agent-1"})
	cp := filteredProvider(upstreamHost, filter.URL)
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.Capabilities = caps
	})
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	req, err := http.NewRequest("GET", upstream.URL+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(brokercore.HeaderContinuationToken, "forged")
	req.Header.Set("X-Vault", "attacker")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.HasPrefix(sawCont, brokercore.ContinuationTokenPrefix) || sawCont == "forged" {
		t.Fatalf("token = %q", sawCont)
	}
	if sawVault != "" {
		t.Fatalf("inbound X-Vault leaked to sidecar: %q", sawVault)
	}
	if sawProxyAuth != "" {
		t.Fatalf("Proxy-Authorization leaked to sidecar: %q", sawProxyAuth)
	}
}

func TestMITMFilterUnreachable(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be contacted when the filter is down")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	caps := brokercore.NewMemoryCapabilities()
	sr := capResolver(caps, &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy", AgentID: "agent-1"})
	cp := filteredProvider(upstreamHost, "http://127.0.0.1:1")
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.Capabilities = caps
	})
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get(brokercore.ProxyErrorHeader) != "true" {
		t.Fatal("expected X-Agent-Vault-Proxy-Error")
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "filter_unreachable" {
		t.Fatalf("error = %q", body["error"])
	}
}

func TestMITMFilterContinuationSkipsSidecar(t *testing.T) {
	filter := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("filter must not run for a valid continuation")
	}))
	defer filter.Close()

	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	caps := brokercore.NewMemoryCapabilities()
	u, _ := url.Parse(upstream.URL + "/org/repo.git/git-receive-pack")
	bind := brokercore.BindFromURL(http.MethodGet, u)
	raw, err := caps.IssueContinuation(context.Background(), brokercore.Capability{
		SourceVaultID: "v1", VaultName: "dev", ActorAgentID: "agent-1", VaultRole: "proxy",
		Method: bind.Method, Scheme: bind.Scheme, Authority: bind.Authority,
		EscapedPath: bind.EscapedPath, Query: bind.Query,
		Snapshot: brokercore.SnapshotFromService(&broker.Service{
			Name: "github-push", Host: upstreamHost,
			Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	sr := capResolver(caps, nil)
	cp := &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			upstreamHost: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer secret"}}},
		}},
		svc: &broker.Service{
			Name:   "github-push",
			Host:   upstreamHost,
			Filter: &broker.Filter{URL: filter.URL},
		},
	}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.Capabilities = caps
	})
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User(raw), clientRoots)
	resp, err := client.Get(upstream.URL + "/org/repo.git/git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if sawAuth != "Bearer secret" {
		t.Fatalf("origin auth = %q", sawAuth)
	}
}

func TestMITMFilterContinuationMismatch(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be contacted on ticket mismatch")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	caps := brokercore.NewMemoryCapabilities()
	raw, err := caps.IssueContinuation(context.Background(), brokercore.Capability{
		SourceVaultID: "v1", VaultName: "dev", Method: "GET", Scheme: "https",
		Authority: upstreamHost, EscapedPath: "/allowed", VaultRole: "proxy",
		Snapshot: brokercore.SnapshotFromService(&broker.Service{Name: "s", Host: upstreamHost}),
	})
	if err != nil {
		t.Fatal(err)
	}
	sr := capResolver(caps, nil)
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{Passthrough: true}},
	}}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) { o.Capabilities = caps })
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User(raw), clientRoots)
	resp, err := client.Get(upstream.URL + "/other")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestMITMFilterPolicyCannotInvokeFiltered(t *testing.T) {
	filter := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("policy cap must not start a nested filter hop")
	}))
	defer filter.Close()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be contacted")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	caps := brokercore.NewMemoryCapabilities()
	raw, err := caps.IssuePolicy(context.Background(), brokercore.Capability{
		SourceVaultID: "v1", PolicyVaultID: "v1", PolicyVaultName: "default",
		VaultName: "default", ActorAgentID: "agent-1", VaultRole: "proxy",
	})
	if err != nil {
		t.Fatal(err)
	}
	sr := capResolver(caps, nil)
	cp := filteredProvider(upstreamHost, filter.URL)
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) { o.Capabilities = caps })
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User(raw), clientRoots)
	resp, err := client.Get(upstream.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestMITMFilterWebSocketHopsToSidecar(t *testing.T) {
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected websocket", http.StatusBadRequest)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("sidecar hijack: %v", err)
			return
		}
		defer conn.Close()
		acc := websocketAccept(key)
		fmt.Fprintf(buf,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: %s\r\n\r\n",
			acc)
		_ = buf.Flush()
		frame, ferr := readWebSocketTextFrame(buf.Reader)
		if ferr != nil {
			return
		}
		_ = writeWebSocketTextFrame(conn, "echo:"+frame, false)
	}))
	defer filter.Close()

	caps := brokercore.NewMemoryCapabilities()
	sr := capResolver(caps, &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy", AgentID: "agent-1"})
	cp := &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{}},
		svc: &broker.Service{
			Name:   "ws",
			Host:   "*",
			Filter: &broker.Filter{URL: filter.URL},
		},
	}
	proxyURL, _, _ := setupProxy(t, sr, cp, func(o *Options) {
		o.Capabilities = caps
	})

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	keyBytes := make([]byte, 16)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	clientKey := base64.StdEncoding.EncodeToString(keyBytes)
	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_ok:"))
	fmt.Fprintf(conn,
		"GET http://example.test/ws HTTP/1.1\r\n"+
			"Host: example.test\r\n"+
			"Proxy-Authorization: Basic %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		auth, clientKey)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read switching response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if err := writeWebSocketTextFrame(conn, "hi", true); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got, err := readWebSocketTextFrame(reader)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got != "echo:hi" {
		t.Fatalf("frame = %q", got)
	}
}

func filteredProvider(host, filterURL string) *matchingCredProvider {
	return &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			host: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer secret"}}},
		}},
		svc: &broker.Service{
			Name:   "github-push",
			Host:   host,
			Filter: &broker.Filter{URL: filterURL},
		},
	}
}
