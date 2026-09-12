package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

// --- fakes -----------------------------------------------------------

// fakeCapStore is an in-memory FilterCapabilityStore with the same
// semantics as the SQL one: single-use consume, exact bind, fail closed
// on expiry. Keyed by raw token purely for test convenience.
type fakeCapStore struct {
	mu     sync.Mutex
	rows   map[string]*store.FilterCapability
	vaults map[string]*store.Vault // by name
	byID   map[string]*store.Vault
	n      int

	// failCreate makes minting fail, exercising the fail-closed path when
	// a capability cannot be recorded.
	failCreate bool
}

func newFakeCapStore() *fakeCapStore {
	return &fakeCapStore{
		rows:   map[string]*store.FilterCapability{},
		vaults: map[string]*store.Vault{},
		byID:   map[string]*store.Vault{},
	}
}

func (f *fakeCapStore) addVault(id, name string) {
	v := &store.Vault{ID: id, Name: name}
	f.vaults[name] = v
	f.byID[id] = v
}

func (f *fakeCapStore) CreateFilterCapability(_ context.Context, p store.CreateFilterCapabilityParams) (*store.FilterCapability, string, error) {
	if f.failCreate {
		return nil, "", errors.New("capability store unavailable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	prefix := continuationTokenPrefix
	if p.Kind == store.FilterCapPolicy {
		prefix = policyTokenPrefix
	}
	raw := fmt.Sprintf("%s%d", prefix, f.n)
	now := time.Now().UTC()
	rec := &store.FilterCapability{
		ID:                fmt.Sprintf("cap-%d", f.n),
		Kind:              p.Kind,
		FormatVersion:     store.FilterMatchSnapshotVersion,
		VaultID:           p.VaultID,
		PolicyVaultID:     p.PolicyVaultID,
		ActorID:           p.ActorID,
		SourceSessionHash: p.SourceSessionHash,
		SourceAgentID:     p.SourceAgentID,
		ServiceName:       p.ServiceName,
		Bind:              p.Bind,
		MatchSnapshot:     p.MatchSnapshot,
		IssuedAt:          now,
		ExpiresAt:         now.Add(p.TTL),
	}
	f.rows[raw] = rec
	return rec, raw, nil
}

func (f *fakeCapStore) GetFilterCapability(_ context.Context, rawToken string) (*store.FilterCapability, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.rows[rawToken]
	if !ok {
		return nil, store.ErrFilterCapabilityNotFound
	}
	cp := *rec
	return &cp, nil
}

func (f *fakeCapStore) ConsumeFilterContinuation(_ context.Context, rawToken string, bind store.FilterCapabilityBind, now time.Time) (*store.FilterCapability, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.rows[rawToken]
	if !ok {
		return nil, store.ErrFilterCapabilityNotFound
	}
	switch {
	case rec.Kind != store.FilterCapContinuation:
		return nil, store.ErrFilterCapabilityKind
	case rec.ConsumedAt != nil:
		return nil, store.ErrFilterCapabilityConsumed
	case rec.IsExpired(now):
		return nil, store.ErrFilterCapabilityExpired
	case rec.Bind != bind:
		return nil, store.ErrFilterCapabilityBind
	}
	stamp := now.UTC()
	rec.ClaimedAt = &stamp
	rec.ConsumedAt = &stamp
	cp := *rec
	return &cp, nil
}

func (f *fakeCapStore) DeleteFilterCapability(_ context.Context, rawToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, rawToken)
	return nil
}

func (f *fakeCapStore) GetVault(_ context.Context, name string) (*store.Vault, error) {
	v, ok := f.vaults[name]
	if !ok {
		return nil, errors.New("vault not found")
	}
	return v, nil
}

func (f *fakeCapStore) GetVaultByID(_ context.Context, id string) (*store.Vault, error) {
	v, ok := f.byID[id]
	if !ok {
		return nil, errors.New("vault not found")
	}
	return v, nil
}

// fakeAuthority answers the revocation re-check from a closure, so a
// test can revoke mid-flight.
type fakeAuthority struct {
	check func(brokercore.SourceAuthority) error
}

func (f *fakeAuthority) CheckSourceAuthority(_ context.Context, a brokercore.SourceAuthority) error {
	if f.check == nil {
		return nil
	}
	return f.check(a)
}

// --- helpers ---------------------------------------------------------

const filterTestToken = "av_sess_filter"

func filterScope() *brokercore.ProxyScope {
	return &brokercore.ProxyScope{
		AgentID:     "agent-1",
		VaultID:     "vault-dev",
		VaultName:   "dev",
		VaultRole:   "proxy",
		SessionHash: "session-hash-1",
	}
}

// filteredSvc builds a service pointing its filter at sidecarURL.
func filteredSvc(name, host, sidecarURL, policyVault string) *broker.Service {
	return &broker.Service{
		Name: name,
		Host: host,
		Auth: broker.Auth{Type: "bearer", Token: "DEST_TOKEN"},
		Filter: &broker.Filter{
			URL:                      sidecarURL,
			PolicyVault:              policyVault,
			AllowInsecurePrivateHTTP: strings.HasPrefix(sidecarURL, "http://"),
		},
	}
}

// filterHarness wires a proxy, an origin, and a sidecar together.
type filterHarness struct {
	proxyURL    *url.URL
	clientRoots *x509.CertPool
	proxy       *Proxy
	caps        *fakeCapStore
	auth        *fakeAuthority
	creds       *fakeCredProvider
	originHost  string
	originAuth  string // host:port, the authority the client asked for
	originURL   string
	originHits  *atomic.Int32
	resolves    *atomic.Int32
}

// countingCredProvider wraps fakeCredProvider to count ResolveMatch
// calls — the direct measure of "was the destination credential read".
type countingCredProvider struct {
	*fakeCredProvider
	resolves *atomic.Int32
}

func (c *countingCredProvider) ResolveMatch(ctx context.Context, vaultID string, m *brokercore.CredentialMatch) (*brokercore.InjectResult, error) {
	if m != nil && !m.Passthrough {
		c.resolves.Add(1)
	}
	return c.fakeCredProvider.ResolveMatch(ctx, vaultID, m)
}

// newFilterOrigin starts a TLS origin that counts the requests it sees.
// The count is the direct measure of "did anything reach the
// destination", which most of these tests assert is zero.
func newFilterOrigin(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Origin-Auth", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "origin-body")
	}))
	t.Cleanup(origin.Close)
	return origin, hits
}

// newFilterHarness starts an origin plus a proxy whose only service is
// filtered at sidecarURL.
func newFilterHarness(t *testing.T, sidecarURL, policyVault string, extra ...func(*fakeCapStore, *fakeCredProvider)) *filterHarness {
	t.Helper()
	origin, hits := newFilterOrigin(t)
	return newFilterHarnessFor(t, origin, hits, sidecarURL, policyVault, extra...)
}

// newFilterHarnessFor wires a proxy around an origin the caller already
// started, for tests that need their own origin handler.
func newFilterHarnessFor(
	t *testing.T,
	origin *httptest.Server,
	originHits *atomic.Int32,
	sidecarURL, policyVault string,
	extra ...func(*fakeCapStore, *fakeCredProvider),
) *filterHarness {
	t.Helper()

	authority := strings.TrimPrefix(origin.URL, "https://")
	host, _, _ := net.SplitHostPort(authority)

	caps := newFakeCapStore()
	caps.addVault("vault-dev", "dev")
	caps.addVault("vault-policy", "policy")

	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {
			service: filteredSvc("github-push", host, sidecarURL, policyVault),
			result: &brokercore.InjectResult{
				MatchedName: "github-push",
				Headers:     map[string]string{"Authorization": "Bearer dest-secret"},
			},
		},
	}}
	auth := &fakeAuthority{}
	for _, e := range extra {
		e(caps, cp)
	}

	resolves := &atomic.Int32{}
	counting := &countingCredProvider{fakeCredProvider: cp, resolves: resolves}

	sr := validTokenResolver(filterTestToken, filterScope())
	proxyURL, clientRoots, p := setupProxy(t, sr, counting, func(o *Options) {
		o.Filter = &FilterOptions{Store: caps, Authority: auth}
	})

	originRoots := x509.NewCertPool()
	originRoots.AddCert(origin.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: originRoots}

	return &filterHarness{
		proxyURL: proxyURL, clientRoots: clientRoots, proxy: p,
		caps: caps, auth: auth, creds: cp,
		originHost: host, originAuth: authority, originURL: origin.URL,
		originHits: originHits, resolves: resolves,
	}
}

func (h *filterHarness) client() *http.Client {
	return newTrustingClient(h.proxyURL, url.User(filterTestToken), h.clientRoots)
}

// --- tests -----------------------------------------------------------

// The headline invariant: a sidecar that denies costs zero credential
// resolutions and never reaches the origin.
func TestFilterDenyResolvesNoCredential(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"branch is protected"}`)
	}))
	defer sidecar.Close()

	h := newFilterHarness(t, sidecar.URL, "")
	resp, err := h.client().Post(h.originURL+"/acme/app.git/git-receive-pack", "application/x-git", strings.NewReader("packfile"))
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 from the sidecar", resp.StatusCode)
	}
	if !strings.Contains(string(body), "branch is protected") {
		t.Errorf("body = %q, want the sidecar's own response", body)
	}
	if got := h.resolves.Load(); got != 0 {
		t.Errorf("ResolveMatch ran %d times on a denied request, want 0", got)
	}
	if got := h.originHits.Load(); got != 0 {
		t.Errorf("origin saw %d requests on a denied request, want 0", got)
	}
}

// The sidecar chooses the status; Agent Vault does not normalize a
// denial into a fixed 403.
func TestFilterPassesThroughAnyStatus(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusTeapot, http.StatusUnauthorized} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer sidecar.Close()
			h := newFilterHarness(t, sidecar.URL, "")
			resp, err := h.client().Get(h.originURL + "/x")
			if err != nil {
				t.Fatalf("client.Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != status {
				t.Errorf("status = %d, want %d", resp.StatusCode, status)
			}
		})
	}
}

// The hop headers the sidecar receives, and what it must not receive.
func TestFilterHopHeaders(t *testing.T) {
	var seen http.Header
	var seenURL, seenHost, seenMethod string
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seenURL = r.URL.String()
		seenHost = r.Host
		seenMethod = r.Method
		w.WriteHeader(http.StatusForbidden)
	}))
	defer sidecar.Close()

	h := newFilterHarness(t, sidecar.URL, "policy")
	req, _ := http.NewRequest("POST", h.originURL+"/acme/app.git/git-receive-pack?svc=push", strings.NewReader("body"))
	req.Header.Set("X-Client-Header", "kept")
	// A client must not be able to smuggle its own control headers.
	req.Header.Set(HeaderContinuationToken, "forged-continuation")
	req.Header.Set(HeaderPolicyToken, "forged-policy")
	req.Header.Set(HeaderService, "forged-service")

	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if seenMethod != "POST" {
		t.Errorf("method = %q, want POST", seenMethod)
	}
	if !strings.Contains(seenURL, "/acme/app.git/git-receive-pack") || !strings.Contains(seenURL, "svc=push") {
		t.Errorf("sidecar URL = %q, want the original path and query preserved", seenURL)
	}
	// The sidecar sees the authority the client actually asked for, not
	// the sidecar's own host — that is how it routes on the target.
	if seenHost != h.originAuth {
		t.Errorf("Host = %q, want the original %q", seenHost, h.originAuth)
	}
	if seen.Get("X-Client-Header") != "kept" {
		t.Error("ordinary client headers must reach the sidecar")
	}
	// The agent's own session must not leak to the sidecar.
	if seen.Get("Proxy-Authorization") != "" {
		t.Error("the inbound agent session reached the sidecar")
	}
	if got := seen.Get(HeaderOriginalURL); !strings.Contains(got, "/acme/app.git/git-receive-pack") {
		t.Errorf("%s = %q", HeaderOriginalURL, got)
	}
	if got := seen.Get(HeaderService); got != "github-push" {
		t.Errorf("%s = %q, want the real service name, not the client's forgery", HeaderService, got)
	}
	cont := seen.Get(HeaderContinuationToken)
	if cont == "forged-continuation" || !strings.HasPrefix(cont, continuationTokenPrefix) {
		t.Errorf("%s = %q, want a freshly minted continuation", HeaderContinuationToken, cont)
	}
	pol := seen.Get(HeaderPolicyToken)
	if pol == "forged-policy" || !strings.HasPrefix(pol, policyTokenPrefix) {
		t.Errorf("%s = %q, want a freshly minted policy capability", HeaderPolicyToken, pol)
	}
	// Bearer material is in headers, never in the advertised proxy URL.
	for _, hdr := range []string{HeaderContinuationProxy, HeaderPolicyProxy} {
		v := seen.Get(hdr)
		if v == "" {
			t.Errorf("%s is empty", hdr)
		}
		if strings.Contains(v, cont) || strings.Contains(v, pol) {
			t.Errorf("%s = %q leaks a capability into a URL", hdr, v)
		}
	}
	if seen.Get(HeaderCA) == "" {
		t.Errorf("%s is empty — a sidecar is not `vault run` and needs the root", HeaderCA)
	}
}

// Omitting policy_vault mints no policy capability at all.
func TestFilterWithoutPolicyVaultMintsNoPolicyCapability(t *testing.T) {
	var seen http.Header
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer sidecar.Close()

	h := newFilterHarness(t, sidecar.URL, "")
	resp, err := h.client().Get(h.originURL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if got := seen.Get(HeaderPolicyToken); got != "" {
		t.Errorf("%s = %q, want nothing when policy_vault is omitted", HeaderPolicyToken, got)
	}
	if got := seen.Get(HeaderPolicyProxy); got != "" {
		t.Errorf("%s = %q, want nothing when policy_vault is omitted", HeaderPolicyProxy, got)
	}
	if got := seen.Get(HeaderContinuationToken); got == "" {
		t.Error("a continuation is minted regardless of policy_vault")
	}
}

// The sidecar must not be able to spoof control headers back at the
// agent, and the namespace strip is what stops it.
func TestFilterStripsReservedHeadersFromSidecarResponse(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderContinuationToken, "leaked")
		w.Header().Set("X-Agent-Vault-Proxy-Error", "true")
		w.Header().Set("X-Sidecar-Header", "fine")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer sidecar.Close()

	h := newFilterHarness(t, sidecar.URL, "")
	resp, err := h.client().Get(h.originURL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	for _, name := range []string{HeaderContinuationToken, "X-Agent-Vault-Proxy-Error"} {
		if got := resp.Header.Get(name); got != "" {
			t.Errorf("%s = %q reached the client from the sidecar", name, got)
		}
	}
	if resp.Header.Get("X-Sidecar-Header") != "fine" {
		t.Error("ordinary sidecar response headers must reach the client")
	}
}

// A dead sidecar is a 502 with the broker's own envelope, and no
// credential is read.
func TestFilterUnreachableIs502(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := sidecar.URL
	sidecar.Close()

	h := newFilterHarness(t, deadURL, "")
	resp, err := h.client().Get(h.originURL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if resp.Header.Get(brokercore.ProxyErrorHeader) != "true" {
		t.Error("a broker-layer error must carry the proxy-error header")
	}
	if got := h.resolves.Load(); got != 0 {
		t.Errorf("ResolveMatch ran %d times against a dead sidecar, want 0", got)
	}
	if got := h.originHits.Load(); got != 0 {
		t.Errorf("origin saw %d requests, want 0", got)
	}
}

// A capability that cannot be recorded means a hop that cannot be
// checked: fail closed rather than calling the sidecar without one.
func TestFilterCapabilityMintFailureFailsClosed(t *testing.T) {
	var sidecarHits atomic.Int32
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sidecarHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()

	h := newFilterHarness(t, sidecar.URL, "", func(c *fakeCapStore, _ *fakeCredProvider) {
		c.failCreate = true
	})
	resp, err := h.client().Get(h.originURL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if got := sidecarHits.Load(); got != 0 {
		t.Errorf("sidecar saw %d requests without a capability, want 0", got)
	}
	if got := h.resolves.Load(); got != 0 {
		t.Errorf("ResolveMatch ran %d times, want 0", got)
	}
}

// A failed hop must not leave a spendable continuation behind.
func TestFilterDiscardsCapabilitiesOnHopFailure(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := sidecar.URL
	sidecar.Close()

	h := newFilterHarness(t, deadURL, "policy")
	resp, err := h.client().Get(h.originURL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	h.caps.mu.Lock()
	remaining := len(h.caps.rows)
	h.caps.mu.Unlock()
	if remaining != 0 {
		t.Errorf("%d capabilities survived a failed hop, want 0", remaining)
	}
}

// A service with a filter on a proxy that has no filter engine must
// fail closed, never forward unfiltered.
func TestFilteredServiceWithoutEngineFailsClosed(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {
			service: filteredSvc("github-push", host, "https://policy.example.com", ""),
			result:  &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer dest"}},
		},
	}}
	sr := validTokenResolver(filterTestToken, filterScope())
	// No Filter option: the engine is absent.
	proxyURL, roots, p := setupProxy(t, sr, cp)
	originRoots := x509.NewCertPool()
	originRoots.AddCert(origin.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: originRoots}

	resp, err := newTrustingClient(proxyURL, url.User(filterTestToken), roots).Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 — filtering unavailable is not filtering skipped", resp.StatusCode)
	}
}

func TestValidateFilterProxyURL(t *testing.T) {
	tests := []struct {
		raw     string
		wantErr string // substring; "" means valid
	}{
		{"", ""},
		{"https://agent-vault.example.com:14322", ""},
		{"https://agent-vault.example.com:14322/", ""},
		{"http://127.0.0.1:14322", ""},
		{"http://[::1]:14322", ""},
		// A sidecar sends capabilities here, so cleartext off-host is out.
		{"http://agent-vault.example.com:14322", "must be https"},
		{"http://localhost:14322", "must be https"},
		{"http://10.0.0.5:14322", "must be https"},
		{"https://user:pass@av.example.com", "must not contain userinfo"},
		{"ftp://av.example.com", "must use http or https"},
		{"not-a-url", "must include a host"},
	}
	for _, tc := range tests {
		err := ValidateFilterProxyURL(tc.raw)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("ValidateFilterProxyURL(%q) = %v, want nil", tc.raw, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("ValidateFilterProxyURL(%q) = nil, want an error containing %q", tc.raw, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("ValidateFilterProxyURL(%q) = %q, want it to contain %q", tc.raw, err, tc.wantErr)
		}
	}
}

// With a callback configured, that is what the sidecar is told; without
// one, the sidecar gets this process's real bound address.
func TestFilterCallbackURL(t *testing.T) {
	configured := newFilterEngine(FilterOptions{ProxyBaseURL: "https://av.example.com:14322/"})
	if got := configured.callbackURL("127.0.0.1:9999"); got != "https://av.example.com:14322" {
		t.Errorf("callbackURL = %q, want the configured value with the trailing slash trimmed", got)
	}
	local := newFilterEngine(FilterOptions{})
	if got := local.callbackURL("127.0.0.1:9999"); got != "http://127.0.0.1:9999" {
		t.Errorf("callbackURL = %q, want the local listener", got)
	}
}

// A sidecar that never starts answering is a 504, distinct from a
// sidecar that cannot be reached at all, and still costs nothing.
func TestFilterTimeoutIs504(t *testing.T) {
	release := make(chan struct{})
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(release)
		sidecar.Close()
	}()

	h := newFilterHarness(t, sidecar.URL, "")
	// Shrink the response-header budget so the test does not wait out
	// the production one.
	h.proxy.filter.tls.Transport.(*http.Transport).ResponseHeaderTimeout = 150 * time.Millisecond
	h.proxy.filter.cleartext.Transport.(*http.Transport).ResponseHeaderTimeout = 150 * time.Millisecond

	resp, err := h.client().Get(h.originURL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "filter_timeout") {
		t.Errorf("body = %q, want the filter_timeout code", body)
	}
	if got := h.resolves.Load(); got != 0 {
		t.Errorf("ResolveMatch ran %d times on a filter timeout, want 0", got)
	}
	if got := h.originHits.Load(); got != 0 {
		t.Errorf("origin saw %d requests, want 0", got)
	}
}

// Editing the service while a continuation is outstanding must not
// retarget it. This is observable because the continuation path does
// not consult the matcher at all: the service is removed from the
// matcher entirely mid-flight, and the continuation still completes
// from the snapshot it was issued against.
func TestContinuationIgnoresServiceEditMidWindow(t *testing.T) {
	origin, originHits := newFilterOrigin(t)

	var liveMatchAfterEdit atomic.Int32
	sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
		h := harnessRef.Load().(*filterHarness)

		// The admin rewrites the vault mid-window: this service no longer
		// matches anything. A live match would now 403.
		h.creds.byHost = map[string]fakeInjectResult{}

		// Prove that claim rather than assuming it — a fresh session
		// request for the same URL is now unmatched.
		if probe, err := h.client().Get(r.Header.Get(HeaderOriginalURL)); err == nil {
			liveMatchAfterEdit.Store(int32(probe.StatusCode))
			_ = probe.Body.Close()
		}

		client := capHTTPClient(t, s.callback(), s.continuation(), h.clientRoots)
		resp, err := client.Get(r.Header.Get(HeaderOriginalURL))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("X-Origin-Auth", resp.Header.Get("X-Origin-Auth"))
		w.WriteHeader(resp.StatusCode)
	})

	h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "")
	// Resolution is keyed by service name, so it survives the matcher
	// being emptied — exactly as the real provider resolves the frozen
	// service's credential keys.
	h.creds.byName = map[string]fakeInjectResult{
		"github-push": {result: &brokercore.InjectResult{
			MatchedName: "github-push",
			Headers:     map[string]string{"Authorization": "Bearer dest-secret"},
		}},
	}
	harnessRef.Store(h)

	resp, err := h.client().Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if got := liveMatchAfterEdit.Load(); got != http.StatusForbidden {
		t.Fatalf("a live match after the edit returned %d, want 403 — the edit did not take", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: the continuation must survive the edit", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin-Auth"); got != "Bearer dest-secret" {
		t.Errorf("origin Authorization = %q, want the frozen service's credential", got)
	}
	if got := originHits.Load(); got != 1 {
		t.Errorf("origin saw %d requests, want 1", got)
	}
}

// harnessRef carries the harness into a sidecar closure that has to be
// built before the harness exists.
var harnessRef atomic.Value
