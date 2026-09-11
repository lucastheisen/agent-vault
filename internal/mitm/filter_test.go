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

type staticFilterTokens struct{ token string }

func (s staticFilterTokens) FilterAgentToken(_ context.Context, _ string) (string, error) {
	return s.token, nil
}

func TestMITMFilterHopShortCircuit(t *testing.T) {
	var sawOrig, sawToken, sawNonce, sawSvc string
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawOrig = r.Header.Get(brokercore.HeaderOriginalURL)
		sawToken = r.Header.Get(brokercore.HeaderFilterToken)
		sawNonce = r.Header.Get(brokercore.HeaderFilterNonce)
		sawSvc = r.Header.Get(brokercore.HeaderService)
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
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy", AgentID: "agent-1"})
	cp := &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			upstreamHost: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer secret"}}},
		}},
		svc: &broker.Service{
			Name: "github-push",
			Host: upstreamHost,
			Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
			Filter: &broker.Filter{
				URL:     filter.URL,
				Vault:   "policy",
				AgentID: "filter-agent-1",
			},
		},
	}
	signer := &brokercore.TicketSigner{Key: []byte("0123456789abcdef0123456789abcdef")}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.Tickets = signer
		o.FilterTokens = staticFilterTokens{token: "av_agt_filter"}
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
	if sawToken != "av_agt_filter" {
		t.Fatalf("filter token = %q", sawToken)
	}
	if sawNonce == "" || !strings.HasPrefix(sawNonce, brokercore.ContinuationTokenPrefix) {
		t.Fatalf("nonce = %q", sawNonce)
	}
	if sawSvc != "github-push" {
		t.Fatalf("service = %q", sawSvc)
	}
	if !strings.Contains(sawOrig, upstreamHost) {
		t.Fatalf("original url = %q", sawOrig)
	}
}

func TestMITMFilterHopOverwritesClientHopHeaders(t *testing.T) {
	var sawToken, sawVault, sawProxyAuth string
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawToken = r.Header.Get(brokercore.HeaderFilterToken)
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
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "dev", VaultRole: "proxy", AgentID: "agent-1"})
	cp := filteredProvider(upstreamHost, filter.URL, "filter-agent-1")
	signer := &brokercore.TicketSigner{Key: []byte("0123456789abcdef0123456789abcdef")}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.Tickets = signer
		o.FilterTokens = staticFilterTokens{token: "av_agt_filter"}
	})
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	req, err := http.NewRequest("GET", upstream.URL+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(brokercore.HeaderFilterToken, "forged")
	req.Header.Set("X-Vault", "attacker")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if sawToken != "av_agt_filter" {
		t.Fatalf("token = %q", sawToken)
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
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy", AgentID: "agent-1"})
	cp := filteredProvider(upstreamHost, "http://127.0.0.1:1", "filter-agent-1")
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.FilterTokens = staticFilterTokens{token: "av_agt_filter"}
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
		t.Error("filter must not run for a valid continuation ticket")
	}))
	defer filter.Close()

	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	signer := &brokercore.TicketSigner{Key: []byte("0123456789abcdef0123456789abcdef")}
	ticket, err := signer.Mint(brokercore.ContinuationClaims{
		VaultID: "v1", VaultName: "dev", AgentID: "agent-1", VaultRole: "proxy",
		Method: "GET", Host: upstreamHost, Path: "/org/repo.git/git-receive-pack",
		FilterAgentID: "filter-agent-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	sr := &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		if strings.HasPrefix(token, brokercore.ContinuationTokenPrefix) {
			c, err := signer.Parse(token)
			if err != nil {
				return nil, err
			}
			return c.Scope(), nil
		}
		return nil, brokercore.ErrInvalidSession
	}}
	cp := &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			upstreamHost: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer secret"}}},
		}},
		svc: &broker.Service{
			Name: "github-push",
			Host: upstreamHost,
			Filter: &broker.Filter{
				URL:     filter.URL,
				AgentID: "filter-agent-1",
			},
		},
	}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.Tickets = signer
		o.FilterTokens = staticFilterTokens{token: "av_agt_filter"}
	})
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User(ticket), clientRoots)
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
	signer := &brokercore.TicketSigner{Key: []byte("0123456789abcdef0123456789abcdef")}
	ticket, err := signer.Mint(brokercore.ContinuationClaims{
		VaultID: "v1", VaultName: "dev", Method: "GET", Host: upstreamHost, Path: "/allowed",
		VaultRole: "proxy",
	})
	if err != nil {
		t.Fatal(err)
	}
	sr := &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		c, err := signer.Parse(token)
		if err != nil {
			return nil, err
		}
		return c.Scope(), nil
	}}
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{Passthrough: true}},
	}}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) { o.Tickets = signer })
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User(ticket), clientRoots)
	resp, err := client.Get(upstream.URL + "/other")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
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

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy", AgentID: "agent-1"})
	cp := &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{}},
		svc: &broker.Service{
			Name: "ws",
			Host: "*",
			Filter: &broker.Filter{
				URL:     filter.URL,
				AgentID: "filter-agent-1",
			},
		},
	}
	proxyURL, _, _ := setupProxy(t, sr, cp, func(o *Options) {
		o.FilterTokens = staticFilterTokens{token: "av_agt_filter"}
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

func filteredProvider(host, filterURL, agentID string) *matchingCredProvider {
	return &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			host: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer secret"}}},
		}},
		svc: &broker.Service{
			Name: "github-push",
			Host: host,
			Filter: &broker.Filter{
				URL:     filterURL,
				Vault:   "policy",
				AgentID: agentID,
			},
		},
	}
}

func TestMITMFilterSkipForFilterAgent(t *testing.T) {
	filter := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("filter must not run for the minted filter-agent")
	}))
	defer filter.Close()

	var originHit bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	sr := validTokenResolver("av_agt_filter",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy", AgentID: "filter-agent-1"})
	cp := &matchingCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			upstreamHost: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer secret"}}},
		}},
		svc: &broker.Service{
			Name: "github-push",
			Host: upstreamHost,
			Filter: &broker.Filter{
				URL:     filter.URL,
				AgentID: "filter-agent-1",
			},
		},
	}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	p.upstream.TLSClientConfig.InsecureSkipVerify = true

	client := newTrustingClient(proxyURL, url.User("av_agt_filter"), clientRoots)
	resp, err := client.Get(upstream.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !originHit {
		t.Fatalf("status %d originHit %v", resp.StatusCode, originHit)
	}
}
