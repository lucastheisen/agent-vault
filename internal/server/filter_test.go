package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

const filteredServicesJSON = `[{"name":"github-push","host":"github.com/*/git-receive-pack",` +
	`"auth":{"type":"bearer","token":"GITHUB_TOKEN"},` +
	`"filter":{"url":"https://policy.example.com/hook","policy_vault":"default"}}]`

func seedFilteredService(ms *mockStore) {
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id", ServicesJSON: filteredServicesJSON,
	}
}

func storedServices(t *testing.T, ms *mockStore) []broker.Service {
	t.Helper()
	bc := ms.brokerConfigs["root-ns-id"]
	if bc == nil {
		return nil
	}
	var svcs []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &svcs); err != nil {
		t.Fatalf("unmarshal stored services: %v", err)
	}
	return svcs
}

func doAuthed(t *testing.T, srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, r)
	return rec
}

// An admin upsert that says nothing about the filter must not drop it —
// upsert replaces the whole entry, so silence has to mean "preserve".
func TestUpsertPreservesOmittedFilter(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	seedFilteredService(ms)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack",` +
		`"auth":{"type":"bearer","token":"ROTATED_TOKEN"}}]}`
	rec := doAuthed(t, srv, http.MethodPost, "/v1/vaults/default/services", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	svcs := storedServices(t, ms)
	if len(svcs) != 1 {
		t.Fatalf("len(services) = %d, want 1", len(svcs))
	}
	if svcs[0].Auth.Token != "ROTATED_TOKEN" {
		t.Errorf("Auth.Token = %q, want the rotation to land", svcs[0].Auth.Token)
	}
	if svcs[0].Filter == nil {
		t.Fatal("Filter = nil — an omitted field dropped the policy hop")
	}
	if svcs[0].Filter.URL != "https://policy.example.com/hook" {
		t.Errorf("Filter.URL = %q", svcs[0].Filter.URL)
	}
}

// An explicit null is the admin's way to remove one.
func TestUpsertExplicitNullClearsFilter(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	seedFilteredService(ms)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack",` +
		`"auth":{"type":"bearer","token":"GITHUB_TOKEN"},"filter":null}]}`
	rec := doAuthed(t, srv, http.MethodPost, "/v1/vaults/default/services", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	svcs := storedServices(t, ms)
	if svcs[0].Filter != nil {
		t.Errorf("Filter = %+v, want an explicit null to clear it", svcs[0].Filter)
	}
}

func TestUpsertRejectsUnacknowledgedCleartextFilter(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com",` +
		`"auth":{"type":"bearer","token":"GITHUB_TOKEN"},"filter":{"url":"http://filter:12345"}}]}`
	rec := doAuthed(t, srv, http.MethodPost, "/v1/vaults/default/services", token, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allow_insecure_private_http") {
		t.Errorf("body = %s, want the acknowledgement error", rec.Body.String())
	}
}

// Naming a policy vault the actor does not administer is a delegation
// they are not entitled to make.
func TestUpsertDualAdminRequiredForDifferentPolicyVault(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	// A second vault the owner has no grant on.
	ms.vaults["policy"] = &store.Vault{ID: "policy-ns-id", Name: "policy"}
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com",` +
		`"auth":{"type":"bearer","token":"GITHUB_TOKEN"},` +
		`"filter":{"url":"https://p.example.com","policy_vault":"policy"}}]}`
	rec := doAuthed(t, srv, http.MethodPost, "/v1/vaults/default/services", token, body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "admin on both") {
		t.Errorf("body = %s, want the dual-admin message", rec.Body.String())
	}

	// Granting admin on the policy vault makes the same request legal.
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "policy-ns-id", "admin")
	rec = doAuthed(t, srv, http.MethodPost, "/v1/vaults/default/services", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("after granting admin on both: status = %d: %s", rec.Code, rec.Body.String())
	}
}

// Naming the source vault is Layout A and needs only the admin check the
// handler already did.
func TestUpsertSameVaultPolicyNeedsNoSecondGrant(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com",` +
		`"auth":{"type":"bearer","token":"GITHUB_TOKEN"},` +
		`"filter":{"url":"https://p.example.com","policy_vault":"default"}}]}`
	rec := doAuthed(t, srv, http.MethodPost, "/v1/vaults/default/services", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestUpsertUnknownPolicyVaultRejected(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com",` +
		`"auth":{"type":"bearer","token":"GITHUB_TOKEN"},` +
		`"filter":{"url":"https://p.example.com","policy_vault":"ghost"}}]}`
	rec := doAuthed(t, srv, http.MethodPost, "/v1/vaults/default/services", token, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// An admin round trip through list -> set must not silently strip a
// filter, so the list has to include it.
func TestServicesListIncludesFilterForAdmin(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	seedFilteredService(ms)
	srv := newTestServer(withStore(ms))

	rec := doAuthed(t, srv, http.MethodGet, "/v1/vaults/default/services", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Services []broker.Service `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Services) != 1 || resp.Services[0].Filter == nil {
		t.Fatalf("admin list did not include the filter: %s", rec.Body.String())
	}
	if resp.Services[0].Filter.PolicyVault != "default" {
		t.Errorf("policy_vault = %q", resp.Services[0].Filter.PolicyVault)
	}
}

// A proxy-role caller — which is what an agent is — sees the service
// without its policy topology, matching /discover.
func TestServicesListHidesFilterFromProxyRole(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	seedFilteredService(ms)

	agent := &store.Agent{ID: "agent-1", Name: "coder", Status: "active", Role: "member"}
	ms.agents["coder"] = agent
	ms.GrantVaultRole(context.Background(), "agent-1", "agent", "root-ns-id", "proxy")
	sess, err := ms.CreateAgentToken(context.Background(), "agent-1", nil)
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/services", nil)
	req.Header.Set("Authorization", "Bearer "+sess.ID)
	req.Header.Set("X-Vault", "default")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "policy.example.com") {
		t.Errorf("a proxy-role caller saw the filter block: %s", rec.Body.String())
	}
}

// --- proposals -------------------------------------------------------

func agentProposalSession(t *testing.T, ms *mockStore) string {
	t.Helper()
	ms.agents["coder"] = &store.Agent{ID: "agent-1", Name: "coder", Status: "active", Role: "member"}
	ms.GrantVaultRole(context.Background(), "agent-1", "agent", "root-ns-id", "proxy")
	sess, err := ms.CreateAgentToken(context.Background(), "agent-1", nil)
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	return sess.ID
}

func postProposal(t *testing.T, srv *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Vault", "default")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func TestProposalCannotSetFilter(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	token := agentProposalSession(t, ms)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"action":"set","name":"new-svc","host":"api.example.com",` +
		`"auth":{"type":"bearer","token":"GITHUB_TOKEN"},` +
		`"filter":{"url":"https://attacker.example.com"}}]}`
	rec := postProposal(t, srv, token, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "administrator-only") {
		t.Errorf("body = %s, want the admin-only message rather than a silent drop", rec.Body.String())
	}
}

func TestProposalCannotDeleteFilteredService(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	seedFilteredService(ms)
	token := agentProposalSession(t, ms)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"action":"delete","name":"github-push","host":"github.com/*/git-receive-pack"}]}`
	rec := postProposal(t, srv, token, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "policy-filtered") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestProposalMayDeleteUnfilteredService(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"plain","host":"api.example.com","auth":{"type":"bearer","token":"T"}}]`,
	}
	token := agentProposalSession(t, ms)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"action":"delete","name":"plain","host":"api.example.com"}]}`
	rec := postProposal(t, srv, token, body)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want success: %s", rec.Code, rec.Body.String())
	}
}

// --- capability sweeper ----------------------------------------------

func TestFilterCapabilitySweeperRemovesExpiredRows(t *testing.T) {
	ms := newMockStore()
	ctx := context.Background()

	_, live, err := ms.CreateFilterCapability(ctx, store.CreateFilterCapabilityParams{
		Kind: store.FilterCapContinuation, VaultID: "v", SourceSessionHash: "h", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, dead, err := ms.CreateFilterCapability(ctx, store.CreateFilterCapabilityParams{
		Kind: store.FilterCapContinuation, VaultID: "v", SourceSessionHash: "h", TTL: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := ms.DeleteExpiredFilterCapabilities(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("swept %d rows, want 1", n)
	}
	if _, err := ms.GetFilterCapability(ctx, live); err != nil {
		t.Errorf("the live capability was swept: %v", err)
	}
	if _, err := ms.GetFilterCapability(ctx, dead); err == nil {
		t.Error("the expired capability survived the sweep")
	}
}
