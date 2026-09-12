package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestServicesUpsertPersistsFilterNoAgent(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"bearer","token":"GITHUB_TOKEN"},"filter":{"url":"http://127.0.0.1:12345","policy_vault":"default"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert: %d %s", rec.Code, rec.Body.String())
	}

	for name, ag := range ms.agents {
		if strings.HasPrefix(name, "filter-") {
			t.Fatalf("must not mint filter-agent, got %q %+v", name, ag)
		}
	}

	var svcs []broker.Service
	if err := json.Unmarshal([]byte(ms.brokerConfigs["root-ns-id"].ServicesJSON), &svcs); err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Filter == nil || svcs[0].Filter.URL != "http://127.0.0.1:12345" {
		t.Fatalf("persisted filter: %+v", svcs)
	}
	if svcs[0].Filter.PolicyVault != "default" {
		t.Fatalf("policy_vault: %+v", svcs[0].Filter)
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
	if !strings.Contains(getRec.Body.String(), `"policy_vault":"default"`) {
		t.Fatalf("admin list must include policy_vault, got %s", getRec.Body.String())
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
}

func TestServicesUpsertUnknownPolicyVault(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345","policy_vault":"missing"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestServicesUpsertPolicyVaultRequiresDualAdmin(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.vaults["policy"] = &store.Vault{ID: "policy-id", Name: "policy"}
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"github-push","host":"github.com/*/git-receive-pack","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345","policy_vault":"policy"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without dual-admin, got %d %s", rec.Code, rec.Body.String())
	}

	if ms.grants == nil {
		ms.grants = make(map[string]map[string]string)
	}
	if ms.grants["owner-user-id"] == nil {
		ms.grants["owner-user-id"] = make(map[string]string)
	}
	ms.grants["owner-user-id"]["policy-id"] = "admin"
	req = httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dual-admin upsert: %d %s", rec.Code, rec.Body.String())
	}
}
