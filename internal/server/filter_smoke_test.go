//go:build smoke

// Layout A policy filter, end to end on the final protocol.
//
//	go test -tags smoke -count=1 ./internal/server/ -run '^TestSmoke_' -timeout 60s
//	make test-smoke
//
// Deliberately out of `go test ./...`: this stands up a real SQLite
// store, a real software CA, a real MITM listener, a real sidecar, and
// two real origins, and drives an actual agent through all of them.
// Nothing here is stubbed except the internet.
//
// What it pins is the shape of Layout A from the design:
//
//	agent -> Agent Vault (match, no decrypt) -> sidecar
//	     sidecar -> Agent Vault (policy capability) -> unfiltered protection API
//	     sidecar -> Agent Vault (continuation)      -> filtered push, credential attached
//
// and, on the deny path, that none of the last step happens.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/store"
)

const (
	smokePAT       = "ghp_smoke_write_token"
	smokeReadToken = "ghp_smoke_read_token"
	protectedRef   = "refs/heads/main"
	openRef        = "refs/heads/feature"
)

// smokeEnv is everything the Layout A story needs, wired together.
type smokeEnv struct {
	t *testing.T

	proxyURL *url.URL
	roots    *x509.CertPool

	agentToken string

	pushURL  string // the filtered receive-pack endpoint
	apiURL   string // the unfiltered protection API
	pushHits *atomic.Int32
	apiHits  *atomic.Int32

	// pushSawAuth records the credential the push origin actually
	// received, so "was the destination secret attached" is observed
	// rather than inferred.
	pushSawAuth *atomic.Value
	apiSawAuth  *atomic.Value
}

func newSmokeEnv(t *testing.T, sidecarURL string) *smokeEnv {
	t.Helper()
	ctx := context.Background()

	// Every moving part here lives on loopback. The origin transport is
	// built inside mitm.New, so this has to be set before that call.
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")

	// --- origins -----------------------------------------------------
	pushHits, apiHits := &atomic.Int32{}, &atomic.Int32{}
	pushSawAuth, apiSawAuth := &atomic.Value{}, &atomic.Value{}

	pushOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushHits.Add(1)
		pushSawAuth.Store(r.Header.Get("Authorization"))
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "pushed %d bytes", len(body))
	}))
	t.Cleanup(pushOrigin.Close)

	apiOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		apiSawAuth.Store(r.Header.Get("Authorization"))
		// The protection API: main is protected, everything else is not.
		protected := strings.Contains(r.URL.Query().Get("ref"), "main")
		_ = json.NewEncoder(w).Encode(map[string]bool{"protected": protected})
	}))
	t.Cleanup(apiOrigin.Close)

	pushHost, pushPortStr, _ := net.SplitHostPort(strings.TrimPrefix(pushOrigin.URL, "http://"))
	apiHost, apiPortStr, _ := net.SplitHostPort(strings.TrimPrefix(apiOrigin.URL, "http://"))
	pushPort, _ := strconv.Atoi(pushPortStr)
	apiPort, _ := strconv.Atoi(apiPortStr)

	// --- real SQLite store -------------------------------------------
	db, err := store.Open(filepath.Join(t.TempDir(), "smoke.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	vault, err := db.CreateVault(ctx, "dev")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	encKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i + 1)
	}
	putCredential := func(key, value string) {
		ct, nonce, err := vaultcrypto.Encrypt([]byte(value), encKey)
		if err != nil {
			t.Fatalf("encrypt %s: %v", key, err)
		}
		if _, err := db.SetCredential(ctx, vault.ID, key, ct, nonce); err != nil {
			t.Fatalf("SetCredential %s: %v", key, err)
		}
	}
	putCredential("GITHUB_TOKEN", smokePAT)
	putCredential("GITHUB_READ_TOKEN", smokeReadToken)

	// Layout A: one vault. The protection API is a separate, *unfiltered*
	// service; the push is filtered and names its own vault as the policy
	// vault, which is the explicit opt-in.
	services := []broker.Service{
		{
			Name: "github-api",
			Host: apiHost,
			Port: &apiPort,
			Auth: broker.Auth{Type: "bearer", Token: "GITHUB_READ_TOKEN"},
		},
		{
			Name: "github-push",
			Host: pushHost,
			Port: &pushPort,
			Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
			Filter: &broker.Filter{
				URL:                      sidecarURL,
				PolicyVault:              "dev",
				AllowInsecurePrivateHTTP: strings.HasPrefix(sidecarURL, "http://"),
			},
		},
	}
	servicesJSON, err := json.Marshal(services)
	if err != nil {
		t.Fatalf("marshal services: %v", err)
	}
	if _, err := db.SetBrokerConfig(ctx, vault.ID, string(servicesJSON)); err != nil {
		t.Fatalf("SetBrokerConfig: %v", err)
	}

	agent, agentSession, err := db.CreateAgentWithGrantsAndToken(ctx, "coder", "smoke", "member",
		[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "proxy"}}, nil)
	if err != nil {
		t.Fatalf("CreateAgentWithGrantsAndToken: %v", err)
	}
	_ = agent

	// --- server + proxy ----------------------------------------------
	srv := New("127.0.0.1:0", db, encKey, nil, true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(200 - i)
	}
	caProv, err := ca.New(masterKey, ca.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	proxy := mitm.New("127.0.0.1:0", mitm.Options{
		CA:          caProv,
		Sessions:    srv.SessionResolver(),
		Credentials: srv.CredentialProvider(),
		BaseURL:     srv.BaseURL(),
		Logger:      srv.Logger(),
		RateLimit:   srv.RateLimit(),
		Filter: &mitm.FilterOptions{
			Store:     db,
			Authority: srv.SourceAuthorityChecker(),
		},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = proxy.Serve(ln) }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(proxy.RootPEM()) {
		t.Fatal("could not trust the MITM root")
	}

	return &smokeEnv{
		t:           t,
		proxyURL:    proxyURL,
		roots:       roots,
		agentToken:  agentSession.ID,
		pushURL:     pushOrigin.URL + "/acme/app.git/git-receive-pack",
		apiURL:      apiOrigin.URL + "/repos/acme/app/protection",
		pushHits:    pushHits,
		apiHits:     apiHits,
		pushSawAuth: pushSawAuth,
		apiSawAuth:  apiSawAuth,
	}
}

// clientFor builds an HTTP client proxying through Agent Vault with the
// given bearer, exactly as `HTTPS_PROXY=http://<token>@host:port` would.
func (e *smokeEnv) clientFor(token string) *http.Client {
	u := *e.proxyURL
	u.User = url.User(token)
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&u),
			TLSClientConfig: &tls.Config{RootCAs: e.roots, MinVersion: tls.VersionTLS12},
		},
	}
}

// newSmokeSidecar is the policy sidecar: it reads the ref out of the
// push body, asks the protection API about it using the policy
// capability, and either denies or completes the push through the
// continuation.
func newSmokeSidecar(t *testing.T, env **smokeEnv) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := *env
		if e == nil {
			http.Error(w, "harness not ready", http.StatusInternalServerError)
			return
		}

		continuation := r.Header.Get(mitm.HeaderContinuationToken)
		policy := r.Header.Get(mitm.HeaderPolicyToken)
		targetURL := r.Header.Get(mitm.HeaderOriginalURL)
		caPEM := r.Header.Get(mitm.HeaderCA)

		if continuation == "" || policy == "" || targetURL == "" || caPEM == "" {
			http.Error(w, "incomplete filter hop", http.StatusInternalServerError)
			return
		}
		// A sidecar is not `vault run`: it gets the root on the hop and
		// has to use it. Prove the advertised PEM is usable.
		pem, err := base64.StdEncoding.DecodeString(caPEM)
		if err != nil {
			http.Error(w, "bad CA header", http.StatusInternalServerError)
			return
		}
		sidecarRoots := x509.NewCertPool()
		if !sidecarRoots.AppendCertsFromPEM(pem) {
			http.Error(w, "unusable CA header", http.StatusInternalServerError)
			return
		}
		proxyFor := func(base, token string) *http.Client {
			u, _ := url.Parse(base)
			u.User = url.User(token)
			return &http.Client{
				Timeout: 15 * time.Second,
				Transport: &http.Transport{
					Proxy:           http.ProxyURL(u),
					TLSClientConfig: &tls.Config{RootCAs: sidecarRoots, MinVersion: tls.VersionTLS12},
				},
			}
		}

		body, _ := io.ReadAll(r.Body)
		ref := string(body)

		// Side channel: the unfiltered protection API, reached with the
		// policy capability. The sidecar never sees a credential.
		policyClient := proxyFor(r.Header.Get(mitm.HeaderPolicyProxy), policy)
		apiResp, err := policyClient.Get(e.apiURL + "?ref=" + url.QueryEscape(ref))
		if err != nil {
			http.Error(w, "protection lookup failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer apiResp.Body.Close()
		var verdict struct {
			Protected bool `json:"protected"`
		}
		if err := json.NewDecoder(apiResp.Body).Decode(&verdict); err != nil {
			http.Error(w, "bad protection response", http.StatusBadGateway)
			return
		}

		if verdict.Protected {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "protected_branch",
				"message": "pushes to " + ref + " are not permitted",
			})
			return
		}

		// Allowed: complete the exact original request through the
		// continuation. Only this attaches the destination credential.
		contClient := proxyFor(r.Header.Get(mitm.HeaderContinuationProxy), continuation)
		req, err := http.NewRequest(r.Method, targetURL, strings.NewReader(ref))
		if err != nil {
			http.Error(w, "bad continuation request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		contResp, err := contClient.Do(req)
		if err != nil {
			http.Error(w, "continuation failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer contResp.Body.Close()
		out, _ := io.ReadAll(contResp.Body)
		w.WriteHeader(contResp.StatusCode)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestSmoke_FilterLayoutA drives both halves of the straw man on the
// real stack.
func TestSmoke_FilterLayoutA(t *testing.T) {
	var env *smokeEnv
	sidecar := newSmokeSidecar(t, &env)
	env = newSmokeEnv(t, sidecar.URL)

	t.Run("protected branch is denied and no credential is spent", func(t *testing.T) {
		resp, err := env.clientFor(env.agentToken).Post(env.pushURL, "application/x-git-receive-pack-request",
			strings.NewReader(protectedRef))
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %q)", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "protected_branch") {
			t.Errorf("body = %q, want the sidecar's own verdict", body)
		}
		// The side channel ran...
		if n := env.apiHits.Load(); n != 1 {
			t.Errorf("protection API saw %d requests, want 1", n)
		}
		if got, _ := env.apiSawAuth.Load().(string); got != "Bearer "+smokeReadToken {
			t.Errorf("protection API Authorization = %q, want the read token", got)
		}
		// ...and the push origin never did.
		if n := env.pushHits.Load(); n != 0 {
			t.Errorf("push origin saw %d requests on a denial, want 0", n)
		}
		if v := env.pushSawAuth.Load(); v != nil {
			t.Errorf("the write PAT was attached on a denied push: %v", v)
		}
	})

	t.Run("open branch completes through the continuation", func(t *testing.T) {
		resp, err := env.clientFor(env.agentToken).Post(env.pushURL, "application/x-git-receive-pack-request",
			strings.NewReader(openRef))
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %q)", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "pushed") {
			t.Errorf("body = %q, want the origin's response relayed back", body)
		}
		if n := env.pushHits.Load(); n != 1 {
			t.Errorf("push origin saw %d requests, want exactly 1", n)
		}
		if got, _ := env.pushSawAuth.Load().(string); got != "Bearer "+smokePAT {
			t.Errorf("push origin Authorization = %q, want the write PAT", got)
		}
		// The agent never held either credential; it only ever spoke to
		// the proxy.
		if strings.Contains(string(body), smokePAT) {
			t.Error("the destination credential leaked into the client's response")
		}
	})

}

// TestSmoke_FilterLayoutA_UnreachableSidecar pins the fail-closed
// direction on the real stack: a sidecar that is not listening produces
// a 502 and no credential use at all.
func TestSmoke_FilterLayoutA_UnreachableSidecar(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	env := newSmokeEnv(t, deadURL)
	resp, err := env.clientFor(env.agentToken).Post(env.pushURL, "application/x-git-receive-pack-request",
		strings.NewReader(openRef))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if resp.Header.Get(brokercore.ProxyErrorHeader) != "true" {
		t.Error("a broker-layer failure must be distinguishable from an upstream 502")
	}
	if n := env.pushHits.Load(); n != 0 {
		t.Errorf("push origin saw %d requests, want 0", n)
	}
	if v := env.pushSawAuth.Load(); v != nil {
		t.Errorf("a credential was attached despite an unreachable filter: %v", v)
	}
}
