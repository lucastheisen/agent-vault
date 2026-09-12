//go:build smoke

// Layout A filter hop: sidecar in front of the same vault's credentials.
//
//	go test -tags smoke -count=1 ./internal/server/ -run '^TestSmoke_' -timeout 60s
//	make test-smoke
//
// Not part of `go test ./...` / `make test` — real MITM + sidecar + origin.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

const smokePAT = "ghp_smoke"

var (
	smokeRefRE  = regexp.MustCompile(`refs/heads/([A-Za-z0-9._/-]+)`)
	smokePackRE = regexp.MustCompile(`^https?://[^/]+/([^/]+)/([^/]+)\.git/git-receive-pack$`)
)

type smokeHit struct {
	Method, Path, Authorization, Body string
}

// TestSmoke_FilterLayoutA exercises the straw-man git-push / protected-branch
// flow over HTTP. Both the receive-pack service and protection API live in the
// same vault, while the filter itself has no agent or long-lived credential.
// A real temporary SQLite store backs both the server and the short-lived
// filter capabilities.
func TestSmoke_FilterLayoutA(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	t.Setenv("AGENT_VAULT_DEV_MODE", "true")
	t.Setenv("AGENT_VAULT_TELEMETRY", "false")

	var hitsMu sync.Mutex
	var hits []smokeHit
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hitsMu.Lock()
		hits = append(hits, smokeHit{
			Method: r.Method, Path: r.URL.Path,
			Authorization: r.Header.Get("Authorization"), Body: string(body),
		})
		hitsMu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/protection"):
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/branches/main/") {
				_, _ = io.WriteString(w, `{"protected":true}`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"protected":false}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-receive-pack"):
			if r.Header.Get("Authorization") != "Bearer "+smokePAT {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
			_, _ = io.WriteString(w, "unpack ok\n")
		default:
			http.NotFound(w, r)
		}
	}))
	originListener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback required for smoke origin: %v", err)
	}
	origin.Listener = originListener
	origin.Start()
	t.Cleanup(origin.Close)

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	originPort, err := strconv.Atoi(originURL.Port())
	if err != nil {
		t.Fatalf("origin port %q: %v", originURL.Host, err)
	}
	// Broker service hosts are DNS names, so address the loopback test server
	// through the standard localhost.localdomain alias rather than persisting
	// its literal listener IP.
	originURL.Host = net.JoinHostPort("localhost.localdomain", strconv.Itoa(originPort))
	pushURL := fmt.Sprintf("%s/acme/app.git/git-receive-pack", originURL.String())

	var mitmURL atomic.Pointer[url.URL]
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mitmURL.Load() == nil {
			http.Error(w, "mitm not ready", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		originalURL := r.Header.Get(brokercore.HeaderFilterOriginalURL)
		continuationProxy := r.Header.Get(brokercore.HeaderFilterContinuationProxy)
		continuationToken := r.Header.Get(brokercore.HeaderFilterContinuationToken)
		policyProxy := r.Header.Get(brokercore.HeaderFilterPolicyProxy)
		policyToken := r.Header.Get(brokercore.HeaderFilterPolicyToken)
		if r.Header.Get("Authorization") != "" {
			writeSmokeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential_leaked_to_filter"})
			return
		}
		if originalURL != pushURL || continuationProxy == "" || continuationToken == "" ||
			policyProxy == "" || policyToken == "" || continuationToken == policyToken ||
			!strings.HasPrefix(continuationToken, "av_fcap_") || !strings.HasPrefix(policyToken, "av_fcap_") {
			writeSmokeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_filter_protocol"})
			return
		}
		ref := smokeRefRE.FindStringSubmatch(string(body))
		repo := smokePackRE.FindStringSubmatch(originalURL)
		if len(ref) < 2 || len(repo) < 3 {
			writeSmokeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_filter_input"})
			return
		}
		u, err := url.Parse(originalURL)
		if err != nil {
			writeSmokeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_original_url"})
			return
		}
		protection := *u
		protection.Path = "/repos/" + repo[1] + "/" + repo[2] + "/branches/" + ref[1] + "/protection"
		protection.RawQuery = ""

		status, _, err := smokeProxyDo(policyProxy, policyToken, http.MethodGet, protection.String(), nil)
		if err != nil {
			writeSmokeJSON(w, http.StatusBadGateway, map[string]string{"error": "protection_lookup_failed"})
			return
		}
		switch status {
		case http.StatusOK:
			writeSmokeJSON(w, http.StatusForbidden, map[string]string{
				"error": "protected_branch", "message": "refuses push to protected branch " + ref[1],
			})
			return
		case http.StatusNotFound:
			// Unprotected: continue the exact original request.
		default:
			writeSmokeJSON(w, http.StatusBadGateway, map[string]string{"error": "protection_lookup_failed"})
			return
		}

		status, out, err := smokeProxyDo(continuationProxy, continuationToken, http.MethodPost, originalURL, body)
		if err != nil {
			writeSmokeJSON(w, http.StatusBadGateway, map[string]string{"error": "continuation_failed"})
			return
		}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		w.WriteHeader(status)
		_, _ = w.Write(out)
	}))
	t.Cleanup(sidecar.Close)

	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "smoke.db"))
	if err != nil {
		t.Fatalf("open smoke store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		t.Fatalf("get default vault: %v", err)
	}
	owner, err := db.RegisterFirstUser(ctx, "smoke-owner@example.com", []byte("hash"), []byte("salt"), vault.ID, 1, 8, 1)
	if err != nil {
		t.Fatalf("create smoke owner: %v", err)
	}

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := vaultcrypto.Encrypt([]byte(smokePAT), encKey)
	if err != nil {
		t.Fatalf("encrypt smoke credential: %v", err)
	}
	if _, err := db.SetCredential(ctx, vault.ID, "GITHUB_TOKEN", ciphertext, nonce); err != nil {
		t.Fatalf("set smoke credential: %v", err)
	}

	services := []broker.Service{
		{
			Name: "git-api", Host: originURL.Hostname(), Path: "/repos/*", Port: &originPort,
			Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
		},
		{
			Name: "git-push", Host: originURL.Hostname(), Path: "/*/git-receive-pack", Port: &originPort,
			Auth:   broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
			Filter: &broker.Filter{URL: sidecar.URL, PolicyVault: "default"},
		},
	}
	if err := broker.Validate(&broker.Config{Vault: vault.Name, Services: services}); err != nil {
		t.Fatalf("validate smoke services: %v", err)
	}
	rawServices, err := json.Marshal(services)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetBrokerConfig(ctx, vault.ID, string(rawServices)); err != nil {
		t.Fatalf("set smoke broker config: %v", err)
	}

	_, smoker, err := db.CreateAgentWithGrantsAndToken(ctx, "smoker", owner.ID, "no-access",
		[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "proxy"}}, nil)
	if err != nil {
		t.Fatalf("create smoke agent: %v", err)
	}

	srv := newTestServer(withStore(db), withEncKey(encKey))
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	caProvider, err := ca.New(masterKey, ca.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p := mitm.New("127.0.0.1:0", mitm.Options{
		CA: caProvider, Sessions: srv.SessionResolver(), Credentials: srv.CredentialProvider(),
		PolicyVault: srv.ResolvePolicyVault, FilterCapabilities: db,
		BaseURL: srv.BaseURL(), Logger: srv.Logger(), RateLimit: srv.RateLimit(),
	})
	srv.AttachMITM(p)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = p.Serve(listener)
	}()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(shutdownCtx)
		wg.Wait()
	})
	waitForListening(t, p)

	proxyURL := &url.URL{Scheme: "http", Host: listener.Addr().String()}
	mitmURL.Store(proxyURL)
	client := smokeProxyClient(proxyURL, url.UserPassword(smoker.ID, "default"))

	deny := smokeMustDo(t, client, http.MethodPost, pushURL, []byte("refs/heads/main"))
	denyBody, _ := io.ReadAll(deny.Body)
	_ = deny.Body.Close()
	if deny.StatusCode != http.StatusForbidden || !strings.Contains(string(denyBody), "protected_branch") {
		t.Fatalf("protected push status=%d body=%s", deny.StatusCode, denyBody)
	}
	if strings.Contains(string(denyBody), smokePAT) {
		t.Fatal("credential leaked in denied response")
	}

	hitsMu.Lock()
	afterDeny := append([]smokeHit(nil), hits...)
	hitsMu.Unlock()
	if smokeHitsContain(afterDeny, "git-receive-pack") {
		t.Fatalf("origin saw receive-pack on denied push: %+v", afterDeny)
	}
	if !smokeHitsMatch(afterDeny, "/protection", "Bearer "+smokePAT, "") {
		t.Fatalf("protection lookup missing injected credential: %+v", afterDeny)
	}

	allow := smokeMustDo(t, client, http.MethodPost, pushURL, []byte("refs/heads/feature"))
	allowBody, _ := io.ReadAll(allow.Body)
	_ = allow.Body.Close()
	if allow.StatusCode != http.StatusOK || !strings.Contains(string(allowBody), "unpack ok") {
		t.Fatalf("allowed push status=%d body=%s", allow.StatusCode, allowBody)
	}

	hitsMu.Lock()
	afterAllow := append([]smokeHit(nil), hits...)
	hitsMu.Unlock()
	if !smokeHitsMatch(afterAllow, "git-receive-pack", "Bearer "+smokePAT, "refs/heads/feature") {
		t.Fatalf("continued receive-pack missing credential or original body: %+v", afterAllow)
	}
}

func writeSmokeJSON(w http.ResponseWriter, status int, value any) {
	raw, _ := json.Marshal(value)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func smokeProxyClient(proxy *url.URL, user *url.Userinfo) *http.Client {
	u := *proxy
	u.User = user
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(&u)}}
}

func smokeProxyDo(proxyAddress, token, method, destination string, body []byte) (int, []byte, error) {
	proxy, err := url.Parse(proxyAddress)
	if err != nil || proxy.User != nil {
		return 0, nil, fmt.Errorf("invalid credential-free filter proxy URL %q", proxyAddress)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, destination, reader)
	if err != nil {
		return 0, nil, err
	}
	resp, err := smokeProxyClient(proxy, url.User(token)).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
}

func smokeMustDo(t *testing.T, client *http.Client, method, destination string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, destination, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func smokeHitsContain(hits []smokeHit, pathSubstring string) bool {
	for _, hit := range hits {
		if strings.Contains(hit.Path, pathSubstring) {
			return true
		}
	}
	return false
}

func smokeHitsMatch(hits []smokeHit, pathSubstring, authorization, bodySubstring string) bool {
	for _, hit := range hits {
		if strings.Contains(hit.Path, pathSubstring) && hit.Authorization == authorization &&
			(bodySubstring == "" || strings.Contains(hit.Body, bodySubstring)) {
			return true
		}
	}
	return false
}
