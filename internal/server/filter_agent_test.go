package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestServicesUpsertMintsFilterAgent(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"bearer","token":"GITHUB_TOKEN"},"filter":{"url":"http://127.0.0.1:12345"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert: %d %s", rec.Code, rec.Body.String())
	}

	wantName := broker.FilterAgentName("default", "http://127.0.0.1:12345")
	ag := ms.agents[wantName]
	if ag == nil || ag.Status != "active" || ag.Role != "no-access" {
		t.Fatalf("filter agent %q: %+v", wantName, ag)
	}

	bc := ms.brokerConfigs["root-ns-id"]
	var svcs []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &svcs); err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Filter == nil || svcs[0].Filter.AgentID != ag.ID {
		t.Fatalf("persisted filter: %+v", svcs)
	}
	if svcs[0].Filter.URL != "http://127.0.0.1:12345" || svcs[0].Filter.Vault != "default" {
		t.Fatalf("persisted filter fields: %+v", svcs[0].Filter)
	}

	raw, err := srv.FilterAgentToken(context.Background(), ag.ID)
	if err != nil || raw == "" {
		t.Fatalf("FilterAgentToken: %q %v", raw, err)
	}

	get := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/services", nil)
	get.Header.Set("Authorization", "Bearer "+token)
	getRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", getRec.Code, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), `"url":"http://127.0.0.1:12345"`) {
		t.Fatalf("admin list must include filter.url, got %s", getRec.Body.String())
	}
}

func TestServicesUpsertOmitPreservesFilter(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	first := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"bearer","token":"GITHUB_TOKEN"},"filter":{"url":"http://127.0.0.1:12345"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(first))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upsert: %d %s", rec.Code, rec.Body.String())
	}

	second := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"bearer","token":"GITHUB_TOKEN_2"}}]}`
	req = httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(second))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second upsert: %d %s", rec.Code, rec.Body.String())
	}

	var svcs []broker.Service
	if err := json.Unmarshal([]byte(ms.brokerConfigs["root-ns-id"].ServicesJSON), &svcs); err != nil {
		t.Fatal(err)
	}
	if svcs[0].Auth.Token != "GITHUB_TOKEN_2" {
		t.Fatalf("auth not updated: %s", svcs[0].Auth.Token)
	}
	if svcs[0].Filter == nil || svcs[0].Filter.URL != "http://127.0.0.1:12345" {
		t.Fatalf("filter must be preserved, got %+v", svcs[0].Filter)
	}
}

func TestServicesUpsertNullClearsFilter(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	first := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(first))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upsert: %d %s", rec.Code, rec.Body.String())
	}
	wantName := broker.FilterAgentName("default", "http://127.0.0.1:12345")
	if ms.agents[wantName] == nil || ms.agents[wantName].Status != "active" {
		t.Fatal("expected minted filter agent")
	}

	second := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"passthrough"},"filter":null}]}`
	req = httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(second))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear upsert: %d %s", rec.Code, rec.Body.String())
	}

	var svcs []broker.Service
	if err := json.Unmarshal([]byte(ms.brokerConfigs["root-ns-id"].ServicesJSON), &svcs); err != nil {
		t.Fatal(err)
	}
	if svcs[0].Filter != nil {
		t.Fatalf("filter must be cleared, got %+v", svcs[0].Filter)
	}
	if ms.agents[wantName].Status != "revoked" {
		t.Fatalf("unused filter agent must be revoked, status=%s", ms.agents[wantName].Status)
	}
}

func TestServicesUpsertUnknownFilterVault(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345","vault":"missing"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestServicesUpsertSharesFilterAgentByURLVault(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	body := `{"services":[
		{"name":"push-a","host":"github.com/a/*/git-receive-pack","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345"}},
		{"name":"push-b","host":"github.com/b/*/git-receive-pack","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345"}}
	]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert: %d %s", rec.Code, rec.Body.String())
	}

	var svcs []broker.Service
	if err := json.Unmarshal([]byte(ms.brokerConfigs["root-ns-id"].ServicesJSON), &svcs); err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 2 || svcs[0].Filter == nil || svcs[1].Filter == nil {
		t.Fatalf("services: %+v", svcs)
	}
	if svcs[0].Filter.AgentID == "" || svcs[0].Filter.AgentID != svcs[1].Filter.AgentID {
		t.Fatalf("expected shared agent_id, got %q vs %q", svcs[0].Filter.AgentID, svcs[1].Filter.AgentID)
	}
}

func TestServicesUpsertRemintsRevokedFilterAgent(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upsert: %d %s", rec.Code, rec.Body.String())
	}
	wantName := broker.FilterAgentName("default", "http://127.0.0.1:12345")
	ag := ms.agents[wantName]
	if err := ms.RevokeAgent(context.Background(), ag.ID); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-apply: %d %s", rec.Code, rec.Body.String())
	}
	ag = ms.agents[wantName]
	if ag.Status != "active" {
		t.Fatalf("expected reminted agent active, status=%s", ag.Status)
	}
	if _, err := srv.FilterAgentToken(context.Background(), ag.ID); err != nil {
		t.Fatalf("expected stored token after remint: %v", err)
	}
}

func TestHandleAgentCreateRejectsFilterPrefix(t *testing.T) {
	srv, _, sessID := setupAgentTest(t)

	body := strings.NewReader(`{"name":"filter-dev-abcd"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents", body)
	req.Header.Set("Authorization", "Bearer "+sessID)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "reserved") {
		t.Fatalf("expected reserved-name error, got %s", rec.Body.String())
	}
}

func TestHandleAgentRenameRejectsFilterPrefix(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)
	ms.agents["oldbot"] = &store.Agent{ID: "a1", Name: "oldbot", Status: "active", CreatedBy: "owner-user-id"}

	body := strings.NewReader(`{"name":"filter-sneaky"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/oldbot/rename", body)
	req.Header.Set("Authorization", "Bearer "+sessID)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
}
