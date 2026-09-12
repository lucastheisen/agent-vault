package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

// continuingSidecar answers by calling back through the advertised
// proxy with the continuation capability, which is the allow path.
// It records what it was handed so tests can reuse the token.
type continuingSidecar struct {
	server *httptest.Server
	// lastContinuation and lastPolicy are what the most recent hop
	// advertised.
	lastContinuation atomic.Value
	lastPolicy       atomic.Value
	lastCallback     atomic.Value
}

func (s *continuingSidecar) continuation() string {
	v, _ := s.lastContinuation.Load().(string)
	return v
}

func (s *continuingSidecar) policy() string {
	v, _ := s.lastPolicy.Load().(string)
	return v
}

func (s *continuingSidecar) callback() string {
	v, _ := s.lastCallback.Load().(string)
	return v
}

// newRecordingSidecar records the hop headers and then runs handle.
func newRecordingSidecar(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, s *continuingSidecar)) *continuingSidecar {
	t.Helper()
	s := &continuingSidecar{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lastContinuation.Store(r.Header.Get(HeaderContinuationToken))
		s.lastPolicy.Store(r.Header.Get(HeaderPolicyToken))
		s.lastCallback.Store(r.Header.Get(HeaderContinuationProxy))
		handle(w, r, s)
	}))
	t.Cleanup(s.server.Close)
	return s
}

// capHTTPClient builds a client that proxies through the advertised
// callback URL using capToken.
func capHTTPClient(t *testing.T, callback, capToken string, roots *x509.CertPool) *http.Client {
	t.Helper()
	u, err := url.Parse(callback)
	if err != nil {
		t.Fatalf("parse callback %q: %v", callback, err)
	}
	u.User = url.User(capToken)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
	}
}

// The allow path end to end: sidecar continues, credentials are
// resolved from the frozen match, origin is reached.
func TestContinuationCompletesTheRequest(t *testing.T) {
	origin, originHits := newFilterOrigin(t)

	var roots *x509.CertPool
	sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
		client := capHTTPClient(t, s.callback(), s.continuation(), roots)
		resp, err := client.Post(origin.URL+"/acme/app.git/git-receive-pack", "application/x-git", strings.NewReader("pack"))
		if err != nil {
			http.Error(w, "continuation failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		// Pass the origin's echo back so the test can see which
		// credential was attached on the continuation hop.
		w.Header().Set("X-Origin-Auth", resp.Header.Get("X-Origin-Auth"))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "")
	roots = h.clientRoots

	resp, err := h.client().Post(origin.URL+"/acme/app.git/git-receive-pack", "application/x-git", strings.NewReader("pack"))
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	if string(body) != "origin-body" {
		t.Errorf("body = %q, want the origin's", body)
	}
	if got := resp.Header.Get("X-Origin-Auth"); got != "Bearer dest-secret" {
		t.Errorf("origin Authorization = %q, want the injected destination credential", got)
	}
	if got := h.originHits.Load(); got != 1 {
		t.Errorf("origin saw %d requests, want 1", got)
	}
}

// A continuation is spent once. The replay is refused and never reaches
// the origin.
func TestContinuationIsSingleUse(t *testing.T) {
	origin, originHits := newFilterOrigin(t)

	var roots *x509.CertPool
	var secondStatus atomic.Int32
	sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
		client := capHTTPClient(t, s.callback(), s.continuation(), roots)
		first, err := client.Get(origin.URL + "/x")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = first.Body.Close()

		// Same capability, same exact request, a second time.
		second, err := client.Get(origin.URL + "/x")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer second.Body.Close()
		secondStatus.Store(int32(second.StatusCode))
		w.WriteHeader(first.StatusCode)
	})

	h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "")
	roots = h.clientRoots

	resp, err := h.client().Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if got := secondStatus.Load(); got != http.StatusForbidden {
		t.Errorf("replayed continuation got %d, want 403", got)
	}
	if got := h.originHits.Load(); got != 1 {
		t.Errorf("origin saw %d requests, want exactly 1", got)
	}
}

// Changing any part of the bound request invalidates the continuation.
func TestContinuationRejectsMutatedRequest(t *testing.T) {
	mutations := map[string]func(base string) (method, target string){
		"different path":   func(b string) (string, string) { return "GET", b + "/other" },
		"different query":  func(b string) (string, string) { return "GET", b + "/x?force=1" },
		"different method": func(b string) (string, string) { return "DELETE", b + "/x" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			origin, originHits := newFilterOrigin(t)

			var roots *x509.CertPool
			var mutatedStatus atomic.Int32
			sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
				client := capHTTPClient(t, s.callback(), s.continuation(), roots)
				method, target := mutate(origin.URL)
				req, _ := http.NewRequest(method, target, nil)
				resp, err := client.Do(req)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				mutatedStatus.Store(int32(resp.StatusCode))
				w.WriteHeader(http.StatusOK)
			})

			h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "")
			roots = h.clientRoots

			resp, err := h.client().Get(origin.URL + "/x")
			if err != nil {
				t.Fatalf("client.Do: %v", err)
			}
			defer resp.Body.Close()

			if got := mutatedStatus.Load(); got != http.StatusForbidden {
				t.Errorf("mutated continuation got %d, want 403", got)
			}
			if got := h.originHits.Load(); got != 0 {
				t.Errorf("origin saw %d requests, want 0", got)
			}
		})
	}
}

// A policy capability may not invoke any filtered service — including
// the one it was minted for. That is what stops a nested hop.
func TestPolicyCapabilityCannotInvokeFilteredService(t *testing.T) {
	origin, originHits := newFilterOrigin(t)

	var roots *x509.CertPool
	var policyStatus atomic.Int32
	sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
		client := capHTTPClient(t, s.callback(), s.policy(), roots)
		resp, err := client.Get(origin.URL + "/x")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		policyStatus.Store(int32(resp.StatusCode))
		w.WriteHeader(http.StatusForbidden)
	})

	// policy_vault names the source vault: Layout A, the most permissive
	// configuration, and even there the filtered service is off limits.
	h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "dev")
	roots = h.clientRoots

	resp, err := h.client().Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if got := policyStatus.Load(); got != http.StatusForbidden {
		t.Errorf("policy capability against a filtered service got %d, want 403", got)
	}
	if got := h.originHits.Load(); got != 0 {
		t.Errorf("origin saw %d requests, want 0", got)
	}
	if got := h.resolves.Load(); got != 0 {
		t.Errorf("ResolveMatch ran %d times, want 0", got)
	}
}

// Revoking the originating session kills outstanding capabilities
// immediately, with TTL still on the clock.
func TestRevokedSourceAuthorityRejectsCapabilities(t *testing.T) {
	for _, kind := range []string{"continuation", "policy"} {
		t.Run(kind, func(t *testing.T) {
			origin, originHits := newFilterOrigin(t)

			var roots *x509.CertPool
			var revoked atomic.Bool
			var capStatus atomic.Int32
			var transportErr atomic.Value

			sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
				token := s.continuation()
				if kind == "policy" {
					token = s.policy()
				}
				// The source agent is revoked after the hop starts but
				// before the capability is spent.
				revoked.Store(true)
				client := capHTTPClient(t, s.callback(), token, roots)
				resp, err := client.Get(origin.URL + "/x")
				if err != nil {
					transportErr.Store(err.Error())
					w.WriteHeader(http.StatusForbidden)
					return
				}
				defer resp.Body.Close()
				capStatus.Store(int32(resp.StatusCode))
				w.WriteHeader(http.StatusForbidden)
			})

			h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "dev")
			roots = h.clientRoots
			h.auth.check = func(brokercore.SourceAuthority) error {
				if revoked.Load() {
					return brokercore.ErrInvalidSession
				}
				return nil
			}

			resp, err := h.client().Get(origin.URL + "/x")
			if err != nil {
				t.Fatalf("client.Do: %v", err)
			}
			defer resp.Body.Close()

			// Either a 407 (rejected at the proxy) or a transport error
			// from the CONNECT being refused — both are fail-closed.
			if got := capStatus.Load(); got == http.StatusOK {
				t.Error("a revoked capability completed a request")
			}
			if got := h.originHits.Load(); got != 0 {
				t.Errorf("origin saw %d requests after revocation, want 0", got)
			}
			if got := h.resolves.Load(); got != 0 {
				t.Errorf("ResolveMatch ran %d times after revocation, want 0", got)
			}
		})
	}
}

// A continuation may only open a CONNECT tunnel to the authority it was
// bound to. Otherwise a stolen token gets a leaf minted for any host.
func TestContinuationCannotConnectToAnotherAuthority(t *testing.T) {
	origin, originHits := newFilterOrigin(t)

	// A second origin the capability was never bound to.
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "elsewhere")
	}))
	defer elsewhere.Close()

	var roots *x509.CertPool
	var elsewhereErr atomic.Value
	var elsewhereStatus atomic.Int32
	sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
		client := capHTTPClient(t, s.callback(), s.continuation(), roots)
		resp, err := client.Get(elsewhere.URL + "/x")
		if err != nil {
			elsewhereErr.Store(err.Error())
		} else {
			elsewhereStatus.Store(int32(resp.StatusCode))
			_ = resp.Body.Close()
		}
		w.WriteHeader(http.StatusForbidden)
	})

	h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "")
	roots = h.clientRoots

	resp, err := h.client().Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	// The CONNECT is refused outright, so the client sees a transport
	// error rather than any response from the other origin.
	if _, ok := elsewhereErr.Load().(string); !ok {
		t.Errorf("CONNECT to an unbound authority succeeded with status %d, want refusal",
			elsewhereStatus.Load())
	}
}

func TestCapabilityTokenPrefixesAreDistinct(t *testing.T) {
	if capabilityKind("av_cont_abc") != store.FilterCapContinuation {
		t.Error("continuation prefix not recognized")
	}
	if capabilityKind("av_pol_abc") != store.FilterCapPolicy {
		t.Error("policy prefix not recognized")
	}
	for _, tok := range []string{"av_sess_abc", "av_agt_abc", "", "random"} {
		if got := capabilityKind(tok); got != "" {
			t.Errorf("capabilityKind(%q) = %q, want a session token", tok, got)
		}
	}
}

// An unknown snapshot version must not resolve to anything.
func TestThawRejectsUnknownSnapshotVersion(t *testing.T) {
	_, err := brokercore.ThawMatch(`{"version":999,"service":{"name":"a","host":"b"}}`)
	if !errors.Is(err, brokercore.ErrFrozenMatchVersion) {
		t.Fatalf("ThawMatch = %v, want ErrFrozenMatchVersion", err)
	}
}

// filterHopTarget preserves the original path and query after the
// sidecar's own base path.
func TestFilterHopTarget(t *testing.T) {
	tests := []struct {
		filterURL string
		orig      string
		want      string
	}{
		{"https://p.example.com", "https://github.com/a/b.git/git-receive-pack", "https://p.example.com/a/b.git/git-receive-pack"},
		{"https://p.example.com/hook", "https://github.com/a/b", "https://p.example.com/hook/a/b"},
		{"https://p.example.com/hook/", "https://github.com/a/b", "https://p.example.com/hook/a/b"},
		{"http://127.0.0.1:12345", "https://github.com/x?y=1", "http://127.0.0.1:12345/x?y=1"},
		{"https://p.example.com", "https://github.com", "https://p.example.com/"},
	}
	for _, tc := range tests {
		orig, err := url.Parse(tc.orig)
		if err != nil {
			t.Fatal(err)
		}
		got, err := filterHopTarget(tc.filterURL, orig)
		if err != nil {
			t.Fatalf("filterHopTarget(%q, %q): %v", tc.filterURL, tc.orig, err)
		}
		if got.String() != tc.want {
			t.Errorf("filterHopTarget(%q, %q) = %q, want %q", tc.filterURL, tc.orig, got, tc.want)
		}
	}
}

func TestPolicyCapabilityMayUse(t *testing.T) {
	plain := &brokercore.CredentialMatch{Service: &broker.Service{Name: "api", Host: "api.github.com"}}
	if !policyCapabilityMayUse(plain) {
		t.Error("policy capability must be able to use an unfiltered service")
	}
	filtered := &brokercore.CredentialMatch{Service: filteredSvc("push", "github.com", "https://p.example.com", "")}
	if policyCapabilityMayUse(filtered) {
		t.Error("policy capability must not be able to use a filtered service")
	}
}

// Decision 9 both ways: the reserved namespace never reaches an origin
// either, which matters most on the continuation path because that
// request was assembled by a sidecar holding capability headers.
func TestReservedHeadersNeverReachTheOrigin(t *testing.T) {
	var sawReserved atomic.Value
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var found []string
		for name := range r.Header {
			if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Agent-Vault-") {
				found = append(found, name)
			}
		}
		sawReserved.Store(strings.Join(found, ","))
		_, _ = io.WriteString(w, "origin-body")
	}))
	defer origin.Close()
	originHits := &atomic.Int32{}

	var roots *x509.CertPool
	sidecar := newRecordingSidecar(t, func(w http.ResponseWriter, r *http.Request, s *continuingSidecar) {
		client := capHTTPClient(t, s.callback(), s.continuation(), roots)
		req, _ := http.NewRequest("GET", origin.URL+"/x", nil)
		// A sidecar echoing its own capability headers onward must not
		// leak them to the destination.
		req.Header.Set(HeaderContinuationToken, s.continuation())
		req.Header.Set(HeaderService, "github-push")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
	})

	h := newFilterHarnessFor(t, origin, originHits, sidecar.server.URL, "")
	roots = h.clientRoots

	req, _ := http.NewRequest("GET", origin.URL+"/x", nil)
	req.Header.Set(HeaderOriginalURL, "https://client-forgery.example.com")
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if got, _ := sawReserved.Load().(string); got != "" {
		t.Errorf("origin received reserved headers: %s", got)
	}
}
