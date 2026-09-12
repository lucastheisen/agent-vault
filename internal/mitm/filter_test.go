package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestMITMFilterContinuationInjectsAfterFiltering(t *testing.T) {
	var filterAuth string
	var continuationProxy, continuationToken, policyToken, originalURL, serviceHeader, filterPath string
	var upstreamAuth string
	var mu sync.Mutex
	var upstreamRequests atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		mu.Lock()
		upstreamAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = io.WriteString(w, "upstream response")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		filterAuth = r.Header.Get("Authorization")
		continuationProxy = r.Header.Get(filterContinuationProxyHeader)
		continuationToken = r.Header.Get(filterContinuationTokenHeader)
		policyToken = r.Header.Get(filterPolicyTokenHeader)
		originalURL = r.Header.Get(filterTargetURLHeader)
		serviceHeader = r.Header.Get(filterServiceHeader)
		filterPath = r.URL.EscapedPath()
		mu.Unlock()
		forwardFilterRequest(t, w, r)
	}))
	defer filter.Close()

	sr := validTokenResolver("agent-session", &brokercore.ProxyScope{
		AgentID:   "agent-1",
		VaultID:   "agent-vault",
		VaultName: "agent-access",
		VaultRole: "proxy",
	})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamURL.Hostname(): {filter: &broker.Filter{URL: filter.URL + "/gitlab-push"}, result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer push-token"},
			MatchedName: "gitlab-push",
		}},
	}}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	proxyWithAuth := *proxyURL
	proxyWithAuth.User = url.User("agent-session")
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/repo%2Fname?service=push", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(filterTargetURLHeader, "https://attacker.invalid/")
	request.Header.Set(filterContinuationTokenHeader, "forged-continuation")
	request.Header.Set(filterPolicyTokenHeader, "forged-policy")
	response, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&proxyWithAuth)}}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "upstream response" {
		t.Fatalf("response = %d %q, want 200 upstream response", response.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if filterAuth != "" {
		t.Fatalf("filter received injected Authorization header %q", filterAuth)
	}
	parsedProxy, err := url.Parse(continuationProxy)
	if err != nil || parsedProxy.User != nil || continuationToken == "" {
		t.Fatalf("split continuation protocol proxy=%q token-present=%t err=%v", continuationProxy, continuationToken != "", err)
	}
	if continuationToken == "forged-continuation" || policyToken != "" {
		t.Fatalf("reserved headers were not overwritten/cleared: continuation=%q policy=%q", continuationToken, policyToken)
	}
	if originalURL != upstream.URL+"/repo%2Fname?service=push" || serviceHeader != "gitlab-push" || filterPath != "/gitlab-push/repo%2Fname" {
		t.Fatalf("filter metadata original=%q service=%q path=%q", originalURL, serviceHeader, filterPath)
	}
	if upstreamAuth != "Bearer push-token" {
		t.Fatalf("upstream Authorization = %q, want injected push credential", upstreamAuth)
	}
	if upstreamRequests.Load() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstreamRequests.Load())
	}
	if cp.MatchCalls() != 1 {
		t.Fatalf("service match count = %d, want original match reused by continuation", cp.MatchCalls())
	}
}

func TestMITMFilterDenyDoesNotReachUpstream(t *testing.T) {
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamRequests.Add(1)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(filterContinuationProxyHeader, "must-not-reach-agent")
		http.Error(w, "protected branch", http.StatusForbidden)
	}))
	defer filter.Close()

	sr := validTokenResolver("agent-session", &brokercore.ProxyScope{VaultID: "agent-vault", VaultName: "agent-access", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamURL.Hostname(): {filter: &broker.Filter{URL: filter.URL}, result: &brokercore.InjectResult{
			MatchedName: "gitlab-push",
		}},
	}}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	response := requestThroughProxy(t, proxyURL, "agent-session", upstream.URL)
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("response status = %d, want 403", response.StatusCode)
	}
	if response.Header.Get(filterContinuationProxyHeader) != "" {
		t.Fatal("filter-internal response header reached the agent")
	}
	if upstreamRequests.Load() != 0 {
		t.Fatalf("upstream request count = %d, want 0", upstreamRequests.Load())
	}
	if cp.ResolveCalls() != 0 {
		t.Fatalf("credential resolution count = %d, want 0 before continuation", cp.ResolveCalls())
	}
}

func TestMITMFilterUnreachableUsesProxyErrorEnvelope(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := "http://" + listener.Addr().String()
	_ = listener.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unreachable-filter request reached destination")
	}))
	defer upstream.Close()
	upstreamURL := mustParseURL(t, upstream.URL)
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamURL.Hostname(): {filter: &broker.Filter{URL: deadURL}, result: &brokercore.InjectResult{MatchedName: "filtered"}},
	}}
	proxyURL, _, _ := setupProxy(t,
		validTokenResolver("agent-session", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}), cp)
	resp := requestThroughProxy(t, proxyURL, "agent-session", upstream.URL)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(brokercore.ProxyErrorHeader) != "true" ||
		!strings.Contains(string(body), "filter_unreachable") {
		t.Fatalf("unreachable response status=%d header=%q body=%s", resp.StatusCode, resp.Header.Get(brokercore.ProxyErrorHeader), body)
	}
	if cp.ResolveCalls() != 0 {
		t.Fatalf("credential resolved %d times", cp.ResolveCalls())
	}
}

func TestMITMFilterContinuationInjectsAfterHTTPSConnect(t *testing.T) {
	var upstreamAuth string
	var mu sync.Mutex

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = io.WriteString(w, "upstream response")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	var filterRoots *x509.CertPool
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardFilterRequest(t, w, r, filterRoots)
	}))
	defer filter.Close()

	sr := validTokenResolver("agent-session", &brokercore.ProxyScope{VaultID: "agent-vault", VaultName: "agent-access", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamURL.Hostname(): {filter: &broker.Filter{URL: filter.URL}, result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer push-token"},
			MatchedName: "gitlab-push",
		}},
	}}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	filterRoots = clientRoots
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}

	response, err := newTrustingClient(proxyURL, url.User("agent-session"), clientRoots).Get(upstream.URL)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", response.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if upstreamAuth != "Bearer push-token" {
		t.Fatalf("upstream Authorization = %q, want injected push credential", upstreamAuth)
	}
}

func TestMITMFilterPolicyVaultUsesSeparateCredentialScope(t *testing.T) {
	var policyAuth string
	var mu sync.Mutex
	policyUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		policyAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set(filterContinuationProxyHeader, "forged-by-upstream")
		_, _ = io.WriteString(w, "protected branches")
	}))
	defer policyUpstream.Close()
	policyURL, err := url.Parse(policyUpstream.URL)
	if err != nil {
		t.Fatalf("parse policy URL: %v", err)
	}

	var pushRequests atomic.Int32
	pushUpstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		pushRequests.Add(1)
	}))
	defer pushUpstream.Close()
	pushURL, err := url.Parse(pushUpstream.URL)
	if err != nil {
		t.Fatalf("parse push URL: %v", err)
	}

	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyProxy := r.Header.Get(filterPolicyProxyHeader)
		policyToken := r.Header.Get(filterPolicyTokenHeader)
		if policyProxy == "" || policyToken == "" {
			http.Error(w, "missing policy proxy", http.StatusBadGateway)
			return
		}
		response := requestThroughProxy(t, mustParseURL(t, policyProxy), policyToken, policyUpstream.URL)
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			http.Error(w, "policy request failed", http.StatusBadGateway)
			return
		}
		if response.Header.Get(filterContinuationProxyHeader) != "" {
			http.Error(w, "policy response spoofed an internal header", http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "policy allowed request inspection")
	}))
	defer filter.Close()

	sr := validTokenResolver("agent-session", &brokercore.ProxyScope{VaultID: "agent-vault", VaultName: "agent-access", VaultRole: "proxy"})
	cp := &fakeCredProvider{byVaultHost: map[string]fakeInjectResult{
		"agent-vault|" + pushURL.Hostname(): {filter: &broker.Filter{URL: filter.URL, PolicyVault: "push-policy"}, result: &brokercore.InjectResult{
			MatchedName: "gitlab-push",
		}},
		"policy-vault|" + policyURL.Hostname(): {result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer maintainer-policy-token"},
			MatchedName: "gitlab-protected-branches",
		}},
	}}
	proxyURL, _, _ := setupProxy(t, sr, cp, func(opts *Options) {
		opts.PolicyVault = func(_ context.Context, name string, source *brokercore.ProxyScope) (*brokercore.ProxyScope, error) {
			if name != "push-policy" {
				return nil, fmt.Errorf("unexpected policy vault %q", name)
			}
			return &brokercore.ProxyScope{AgentID: source.AgentID, VaultID: "policy-vault", VaultName: name, VaultRole: "proxy", FilterPolicy: true}, nil
		}
	})

	response := requestThroughProxy(t, proxyURL, "agent-session", pushUpstream.URL)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", response.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if policyAuth != "Bearer maintainer-policy-token" {
		t.Fatalf("policy Authorization = %q, want policy-vault credential", policyAuth)
	}
	if pushRequests.Load() != 0 {
		t.Fatalf("push upstream request count = %d, want 0 before filter continuation", pushRequests.Load())
	}
}

func TestMITMFilterPolicyCapabilityCannotInvokeFilteredService(t *testing.T) {
	var nestedFilterHits atomic.Int32
	nestedFilter := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nestedFilterHits.Add(1)
	}))
	defer nestedFilter.Close()
	nestedTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer nestedTarget.Close()
	pushTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("push destination reached before continuation")
	}))
	defer pushTarget.Close()

	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := requestThroughProxy(t, mustParseURL(t, r.Header.Get(filterPolicyProxyHeader)), r.Header.Get(filterPolicyTokenHeader), nestedTarget.URL)
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer filter.Close()

	pushURL := mustParseURL(t, pushTarget.URL)
	nestedURL := mustParseURL(t, nestedTarget.URL)
	cp := &fakeCredProvider{byHostPort: map[string]fakeInjectResult{
		pushURL.Host:   {filter: &broker.Filter{URL: filter.URL, PolicyVault: "policy"}, result: &brokercore.InjectResult{MatchedName: "push"}},
		nestedURL.Host: {filter: &broker.Filter{URL: nestedFilter.URL}, result: &brokercore.InjectResult{MatchedName: "nested"}},
	}}
	source := &brokercore.ProxyScope{AgentID: "agent", VaultID: "source-id", VaultName: "source", VaultRole: "proxy"}
	proxyURL, _, _ := setupProxy(t, validTokenResolver("agent-session", source), cp, func(opts *Options) {
		opts.PolicyVault = func(context.Context, string, *brokercore.ProxyScope) (*brokercore.ProxyScope, error) {
			return &brokercore.ProxyScope{AgentID: "agent", VaultID: "policy-id", VaultName: "policy", VaultRole: "proxy", FilterPolicy: true}, nil
		}
	})
	resp := requestThroughProxy(t, proxyURL, "agent-session", pushTarget.URL)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("policy recursion status=%d body=%s", resp.StatusCode, body)
	}
	if nestedFilterHits.Load() != 0 || cp.ResolveCalls() != 0 {
		t.Fatalf("nested filter hits=%d resolve calls=%d", nestedFilterHits.Load(), cp.ResolveCalls())
	}
}

func TestMITMFilterContinuationRejectsChangedRequest(t *testing.T) {
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamRequests.Add(1)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		continuationProxy := mustParseURL(t, r.Header.Get(filterContinuationProxyHeader))
		response := requestThroughProxy(t, continuationProxy, r.Header.Get(filterContinuationTokenHeader), upstream.URL+"/different?allowed=true")
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	defer filter.Close()

	sr := validTokenResolver("agent-session", &brokercore.ProxyScope{VaultID: "agent-vault", VaultName: "agent-access", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamURL.Hostname(): {
			filter: &broker.Filter{URL: filter.URL},
			result: &brokercore.InjectResult{MatchedName: "gitlab-push"},
		},
	}}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	response := requestThroughProxy(t, proxyURL, "agent-session", upstream.URL+"/original?allowed=false")
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("response status = %d, want 403", response.StatusCode)
	}
	if upstreamRequests.Load() != 0 {
		t.Fatalf("upstream request count = %d, want 0", upstreamRequests.Load())
	}
	if cp.ResolveCalls() != 0 {
		t.Fatalf("credential resolution count = %d, want 0", cp.ResolveCalls())
	}
}

func TestMITMFilterSupportsHTTPS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer push-token" {
			http.Error(w, "missing credential", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "allowed")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	filter := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardFilterRequest(t, w, r)
	}))
	defer filter.Close()

	sr := validTokenResolver("agent-session", &brokercore.ProxyScope{
		VaultID: "agent-vault", VaultName: "agent-access", VaultRole: "proxy",
	})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamURL.Hostname(): {
			filter: &broker.Filter{URL: filter.URL},
			result: &brokercore.InjectResult{
				Headers:     map[string]string{"Authorization": "Bearer push-token"},
				MatchedName: "gitlab-push",
			},
		},
	}}
	proxyURL, _, proxy := setupProxy(t, sr, cp)
	filterRoots := x509.NewCertPool()
	filterRoots.AddCert(filter.Certificate())
	proxy.filterUpstream.TLSClientConfig.RootCAs = filterRoots

	response := requestThroughProxy(t, proxyURL, "agent-session", upstream.URL)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "allowed" {
		t.Fatalf("response = %d %q, want 200 allowed", response.StatusCode, body)
	}
}

func TestParseFilterProxyURL(t *testing.T) {
	tester := func(t *testing.T, rawURL, wantErr string) {
		t.Helper()
		proxyURL, err := ParseFilterProxyURL(rawURL)
		if wantErr == "" {
			if err != nil || proxyURL == nil {
				t.Fatalf("ParseFilterProxyURL(%q) = %v, %v", rawURL, proxyURL, err)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("ParseFilterProxyURL(%q) error = %v, want %q", rawURL, err, wantErr)
		}
	}

	t.Run("allows HTTPS", func(t *testing.T) {
		tester(t, "https://vault.example.com:14322", "")
	})
	t.Run("allows loopback HTTP", func(t *testing.T) {
		tester(t, "http://127.0.0.1:14322", "")
	})
	t.Run("rejects remote HTTP", func(t *testing.T) {
		tester(t, "http://vault.example.com:14322", "loopback")
	})
	t.Run("rejects userinfo", func(t *testing.T) {
		tester(t, "https://user:secret@vault.example.com:14322", "without userinfo")
	})
	t.Run("rejects paths", func(t *testing.T) {
		tester(t, "https://vault.example.com:14322/proxy", "must not contain")
	})
}

func TestFilterPrivateDialPolicy(t *testing.T) {
	for _, address := range []string{"8.8.8.8:80", "169.254.169.254:80", "[fd00::1]:80"} {
		if _, err := newFilterTransport(true).DialContext(context.Background(), "tcp", address); err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("private filter dial %s error = %v, want blocked", address, err)
		}
	}
	if _, err := newFilterTransport(false).DialContext(context.Background(), "tcp", "169.254.169.254:443"); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("secure filter link-local error = %v, want blocked", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := newFilterTransport(true).DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("loopback filter dial: %v", err)
	}
	_ = conn.Close()
}

func TestFilterContinuationCapabilityIsSingleUse(t *testing.T) {
	capabilities := newFilterCapabilities()
	scope := &brokercore.ProxyScope{VaultID: "agent-vault"}
	match := &brokercore.CredentialMatch{MatchedName: "gitlab-push"}
	request := filterRequest{
		method: http.MethodPost,
		path:   "/group/project.git/git-receive-pack",
		scheme: "https",
		target: "gitlab.example.com:443",
	}
	token, err := capabilities.issue(filterCapabilityContinuation, scope, request, match)
	if err != nil {
		t.Fatalf("issue() error: %v", err)
	}

	resolved, recognized, err := capabilities.resolve(token, request.target)
	if err != nil || !recognized || resolved.FilterContinuation != token {
		t.Fatalf("resolve() = %+v, %t, %v", resolved, recognized, err)
	}
	if _, recognized, err := capabilities.resolve(token, request.target); !recognized || !errors.Is(err, brokercore.ErrInvalidSession) {
		t.Fatalf("second resolve() recognized/error = %t/%v, want true/invalid session", recognized, err)
	}
	consumed, ok := capabilities.consume(token, request)
	if !ok || consumed != match {
		t.Fatalf("consume() = %+v, %t, want original match", consumed, ok)
	}
	if _, ok := capabilities.consume(token, request); ok {
		t.Fatal("second consume() succeeded")
	}
}

func forwardFilterRequest(t *testing.T, w http.ResponseWriter, r *http.Request, roots ...*x509.CertPool) {
	t.Helper()
	continuationProxy := r.Header.Get(filterContinuationProxyHeader)
	continuationToken := r.Header.Get(filterContinuationTokenHeader)
	if continuationProxy == "" || continuationToken == "" {
		http.Error(w, "missing continuation proxy", http.StatusBadGateway)
		return
	}
	targetURL, err := url.Parse(r.Header.Get(filterTargetURLHeader))
	if err != nil || !targetURL.IsAbs() {
		http.Error(w, "invalid target url", http.StatusBadGateway)
		return
	}
	proxyURL := mustParseURL(t, continuationProxy)
	proxyURL.User = url.User(continuationToken)
	request, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "build continuation request", http.StatusBadGateway)
		return
	}
	request.ContentLength = r.ContentLength
	for key, values := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(key), "X-Agent-Vault-") {
			continue
		}
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}

	rootPool := x509.NewCertPool()
	if len(roots) > 0 && roots[0] != nil {
		rootPool = roots[0]
	} else {
		caPEM, err := base64.StdEncoding.DecodeString(r.Header.Get(filterCAHeader))
		if err != nil || !rootPool.AppendCertsFromPEM(caPEM) {
			http.Error(w, "invalid agent vault ca", http.StatusBadGateway)
			return
		}
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootPool},
	}
	client := &http.Client{Transport: transport}
	response, err := client.Do(request)
	if err != nil {
		http.Error(w, "continue request", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return u
}

func requestThroughProxy(t *testing.T, proxyURL *url.URL, token, target string) *http.Response {
	t.Helper()
	proxyCopy := *proxyURL
	if token != "" {
		proxyCopy.User = url.User(token)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&proxyCopy)}}
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	return response
}
