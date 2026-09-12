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

// TestSmoke_FilterLayoutA is the straw-man git-push / protected-branch case
// over HTTP: a filter on receive-pack, a second unfiltered service for the
// protection API, both in vault `default`.
func TestSmoke_FilterLayoutA(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	t.Setenv("AGENT_VAULT_TELEMETRY", "false")

	var hitsMu sync.Mutex
	var hits []smokeHit
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hitsMu.Lock()
		hits = append(hits, smokeHit{
			Method: r.Method, Path: r.URL.Path,
			Authorization: r.Header.Get("Authorization"), Body: string(body),
		})
		hitsMu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/protection"):
			if strings.Contains(r.URL.Path, "/branches/main/") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"protected":true}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
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
	t.Cleanup(origin.Close)

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	originHost := originURL.Hostname()
	originPortInt, err := strconv.Atoi(originURL.Port())
	if err != nil {
		t.Fatalf("origin port %q: %v", originURL.Host, err)
	}

	var mitmURL atomic.Pointer[url.URL]
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy := mitmURL.Load()
		if proxy == nil {
			http.Error(w, "mitm not ready", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		orig := r.Header.Get(brokercore.HeaderOriginalURL)
		polToken := r.Header.Get(brokercore.HeaderPolicyToken)
		contToken := r.Header.Get(brokercore.HeaderContinuationToken)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("origin credential leaked onto filter hop: %q", r.Header.Get("Authorization"))
		}
		ref := smokeRefRE.FindStringSubmatch(string(body))
		repo := smokePackRE.FindStringSubmatch(orig)
		if len(ref) < 2 || len(repo) < 3 || polToken == "" || contToken == "" {
			writeSmokeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_filter_input"})
			return
		}
		u, err := url.Parse(orig)
		if err != nil {
			writeSmokeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_original_url"})
			return
		}
		prot := *u
		prot.Path = "/repos/" + repo[1] + "/" + repo[2] + "/branches/" + ref[1] + "/protection"
		prot.RawQuery = ""

		st, _, err := smokeProxyDo(proxy, polToken, http.MethodGet, prot.String(), nil)
		if err != nil {
			writeSmokeJSON(w, http.StatusBadGateway, map[string]string{"error": "protection_lookup_failed"})
			return
		}
		switch st {
		case http.StatusOK:
			writeSmokeJSON(w, http.StatusForbidden, map[string]string{
				"error":   "protected_branch",
				"message": "refuses push to protected branch " + ref[1],
			})
			return
		case http.StatusNotFound:
			// unprotected
		default:
			writeSmokeJSON(w, http.StatusBadGateway, map[string]string{"error": "protection_lookup_failed"})
			return
		}

		st, out, err := smokeProxyDo(proxy, contToken, http.MethodPost, orig, body)
		if err != nil {
			writeSmokeJSON(w, http.StatusBadGateway, map[string]string{"error": "continuation_failed"})
			return
		}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		w.WriteHeader(st)
		_, _ = w.Write(out)
	}))
	t.Cleanup(sidecar.Close)

	ms, adminToken := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	credBody := `{"vault":"default","credentials":{"GITHUB_TOKEN":"` + smokePAT + `"}}`
	credReq := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer "+adminToken)
	credRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(credRec, credReq)
	if credRec.Code != http.StatusOK {
		t.Fatalf("set credential: %d %s", credRec.Code, credRec.Body.String())
	}

	ctx := context.Background()
	vault, err := ms.GetVault(ctx, "default")
	if err != nil || vault == nil {
		t.Fatal("default vault")
	}
	svcs := []broker.Service{
		{
			Name: "git-api",
			Host: originHost,
			Path: "/repos/*",
			Port: &originPortInt,
			Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
		},
		{
			Name:     "git-push",
			Host:     originHost,
			Path:     "/*/git-receive-pack",
			Port:     &originPortInt,
			Auth:     broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
			Filter:   &broker.Filter{URL: sidecar.URL, PolicyVault: "default"},
			FilterOp: broker.FilterOpSet,
		},
	}
	raw, err := json.Marshal(svcs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.SetBrokerConfig(ctx, vault.ID, string(raw)); err != nil {
		t.Fatal(err)
	}

	_, smoker, err := ms.CreateAgentWithGrantsAndToken(ctx, "smoker", "owner-user-id", "no-access",
		[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "proxy"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	caProv, err := ca.New(masterKey, ca.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p := mitm.New("127.0.0.1:0", mitm.Options{
		CA:           caProv,
		Sessions:     srv.SessionResolver(),
		Credentials:  srv.CredentialProvider(),
		Capabilities: srv.Capabilities(),
		BaseURL:      srv.BaseURL(),
		Logger:       srv.Logger(),
		RateLimit:    srv.RateLimit(),
	})
	srv.AttachMITM(p)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = p.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
		wg.Wait()
	})
	waitForListening(t, p)

	u := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	mitmURL.Store(u)

	client := smokeProxyClient(u, url.UserPassword(smoker.ID, "default"))
	pushURL := fmt.Sprintf("%s/acme/app.git/git-receive-pack", origin.URL)

	deny := smokeMustDo(t, client, http.MethodPost, pushURL, []byte("refs/heads/main"))
	defer deny.Body.Close()
	denyBody, _ := io.ReadAll(deny.Body)
	if deny.StatusCode != http.StatusForbidden {
		t.Fatalf("protected push status=%d body=%s", deny.StatusCode, denyBody)
	}
	if !strings.Contains(string(denyBody), "protected_branch") {
		t.Fatalf("403 body missing protected_branch: %s", denyBody)
	}
	if strings.Contains(string(denyBody), smokePAT) {
		t.Fatal("credential leaked in 403 body")
	}

	hitsMu.Lock()
	afterDeny := append([]smokeHit(nil), hits...)
	hitsMu.Unlock()
	if smokeHitsContain(afterDeny, "git-receive-pack") {
		t.Fatalf("origin saw receive-pack on denied push: %+v", afterDeny)
	}
	if !smokeHitsContain(afterDeny, "/protection") {
		t.Fatalf("origin never saw protection lookup: %+v", afterDeny)
	}
	if !smokeHitsHaveAuth(afterDeny, "Bearer "+smokePAT) {
		t.Fatalf("protection lookup missing injected creds: %+v", afterDeny)
	}

	allow := smokeMustDo(t, client, http.MethodPost, pushURL, []byte("refs/heads/feature"))
	defer allow.Body.Close()
	allowBody, _ := io.ReadAll(allow.Body)
	if allow.StatusCode != http.StatusOK {
		t.Fatalf("allowed push status=%d body=%s", allow.StatusCode, allowBody)
	}
	if !strings.Contains(string(allowBody), "unpack ok") {
		t.Fatalf("allowed push body=%s", allowBody)
	}

	hitsMu.Lock()
	afterAllow := append([]smokeHit(nil), hits...)
	hitsMu.Unlock()
	if !smokeHitsContain(afterAllow, "git-receive-pack") {
		t.Fatalf("origin never saw receive-pack: %+v", afterAllow)
	}
	if !smokeHitsHaveBody(afterAllow, "refs/heads/feature") {
		t.Fatalf("pack body not from sidecar: %+v", afterAllow)
	}
	if !smokeHitsHaveAuth(afterAllow, "Bearer "+smokePAT) {
		t.Fatalf("pack missing injected creds: %+v", afterAllow)
	}
}

func writeSmokeJSON(w http.ResponseWriter, status int, v any) {
	raw, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func smokeProxyClient(mitm *url.URL, user *url.Userinfo) *http.Client {
	u := *mitm
	u.User = user
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&u),
		},
	}
}

func smokeProxyDo(mitm *url.URL, userinfo, method, dest string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, dest, rdr)
	if err != nil {
		return 0, nil, err
	}
	user, vault, ok := strings.Cut(userinfo, ":")
	var ui *url.Userinfo
	if ok && vault != "" {
		ui = url.UserPassword(user, vault)
	} else {
		ui = url.User(userinfo)
	}
	resp, err := smokeProxyClient(mitm, ui).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func smokeMustDo(t *testing.T, c *http.Client, method, dest string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, dest, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func smokeHitsContain(hits []smokeHit, substr string) bool {
	for _, h := range hits {
		if strings.Contains(h.Path, substr) {
			return true
		}
	}
	return false
}

func smokeHitsHaveAuth(hits []smokeHit, auth string) bool {
	for _, h := range hits {
		if h.Authorization == auth {
			return true
		}
	}
	return false
}

func smokeHitsHaveBody(hits []smokeHit, substr string) bool {
	for _, h := range hits {
		if strings.Contains(h.Body, substr) {
			return true
		}
	}
	return false
}
