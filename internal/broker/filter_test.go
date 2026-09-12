package broker

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFilterValidate(t *testing.T) {
	tests := []struct {
		name    string
		filter  *Filter
		wantErr string // substring; "" means valid
	}{
		{name: "nil filter is valid", filter: nil},
		{
			name:    "url required",
			filter:  &Filter{},
			wantErr: `"url" is required`,
		},
		{
			name:    "url whitespace only",
			filter:  &Filter{URL: "   "},
			wantErr: `"url" is required`,
		},
		{
			name:    "relative url rejected",
			filter:  &Filter{URL: "/policy"},
			wantErr: "must be absolute",
		},
		{
			name:    "non-http scheme rejected",
			filter:  &Filter{URL: "ftp://policy.example.com"},
			wantErr: "must use http or https",
		},
		{
			name:    "missing host rejected",
			filter:  &Filter{URL: "https://"},
			wantErr: "must include a host",
		},
		{
			name:    "userinfo rejected",
			filter:  &Filter{URL: "https://user:pass@policy.example.com/hook"},
			wantErr: "must not contain userinfo",
		},
		{name: "public https allowed", filter: &Filter{URL: "https://policy.example.com/github-push"}},
		{name: "loopback v4 http needs no flag", filter: &Filter{URL: "http://127.0.0.1:12345"}},
		{name: "loopback v6 http needs no flag", filter: &Filter{URL: "http://[::1]:12345"}},
		{
			name:    "localhost is a name, not a literal loopback IP",
			filter:  &Filter{URL: "http://localhost:12345"},
			wantErr: "cleartext http to a non-loopback host",
		},
		{
			name:    "compose sidecar http needs the flag",
			filter:  &Filter{URL: "http://filter:12345"},
			wantErr: "allow_insecure_private_http",
		},
		{
			name:   "compose sidecar http with the flag",
			filter: &Filter{URL: "http://filter:12345", AllowInsecurePrivateHTTP: true},
		},
		{
			name:   "public http with the flag passes config validation",
			filter: &Filter{URL: "http://policy.example.com", AllowInsecurePrivateHTTP: true},
			// The dialer, not config validation, is what refuses to
			// actually reach a public address over cleartext.
		},
		{
			name:    "policy_vault must be a valid slug",
			filter:  &Filter{URL: "https://p.example.com", PolicyVault: "Not A Vault"},
			wantErr: "invalid policy_vault",
		},
		{name: "policy_vault slug", filter: &Filter{URL: "https://p.example.com", PolicyVault: "policy"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.filter.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestIsLoopbackURLHost(t *testing.T) {
	tests := []struct {
		hostport string
		want     bool
	}{
		{"127.0.0.1:12345", true},
		{"127.0.0.1", true},
		{"127.5.6.7:80", true},
		{"[::1]:12345", true},
		{"::1", true},
		{"localhost:12345", false},
		{"filter:12345", false},
		{"10.0.0.5:12345", false},
		{"policy.example.com", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := IsLoopbackURLHost(tc.hostport); got != tc.want {
			t.Errorf("IsLoopbackURLHost(%q) = %v, want %v", tc.hostport, got, tc.want)
		}
	}
}

func TestValidateRejectsBadFilterOnService(t *testing.T) {
	cfg := &Config{
		Vault: "dev",
		Services: []Service{{
			Name:   "github-push",
			Host:   "github.com",
			Path:   "/*/git-receive-pack",
			Auth:   Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
			Filter: &Filter{URL: "http://filter:12345"},
		}},
	}
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "allow_insecure_private_http") {
		t.Fatalf("Validate() = %v, want the cleartext-http acknowledgement error", err)
	}

	cfg.Services[0].Filter.AllowInsecurePrivateHTTP = true
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil once the flag is set", err)
	}
}

// The three-way distinction between "filter omitted", "filter: null",
// and "filter: {...}" is what makes preserve-on-upsert safe. It has to
// survive YAML -> Go -> JSON, because that is the CLI's path to the API.
func TestFilterPresenceRoundTrip(t *testing.T) {
	t.Run("omitted stays omitted", func(t *testing.T) {
		var svc Service
		if err := yaml.Unmarshal([]byte("name: a\nhost: example.com\n"), &svc); err != nil {
			t.Fatal(err)
		}
		if svc.FilterExplicit {
			t.Error("FilterExplicit = true for a document with no filter key")
		}
		b, err := json.Marshal(svc)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "filter") {
			t.Errorf("marshalled %s, want no filter key", b)
		}
	})

	t.Run("explicit null survives as null", func(t *testing.T) {
		var svc Service
		if err := yaml.Unmarshal([]byte("name: a\nhost: example.com\nfilter: null\n"), &svc); err != nil {
			t.Fatal(err)
		}
		if !svc.FilterExplicit {
			t.Fatal("FilterExplicit = false for `filter: null`")
		}
		if svc.Filter != nil {
			t.Fatalf("Filter = %+v, want nil", svc.Filter)
		}
		b, err := json.Marshal(svc)
		if err != nil {
			t.Fatal(err)
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(b, &probe); err != nil {
			t.Fatal(err)
		}
		raw, ok := probe["filter"]
		if !ok {
			t.Fatalf("marshalled %s, want an explicit filter key", b)
		}
		if string(raw) != "null" {
			t.Errorf("filter = %s, want null", raw)
		}

		// And the server side reads that back as an explicit clear.
		var back Service
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if !back.FilterExplicit || back.Filter != nil {
			t.Errorf("round trip gave FilterExplicit=%v Filter=%+v, want true/nil", back.FilterExplicit, back.Filter)
		}
	})

	t.Run("populated block survives", func(t *testing.T) {
		var svc Service
		doc := "name: a\nhost: example.com\nfilter:\n  url: https://p.example.com\n  policy_vault: policy\n  allow_insecure_private_http: true\n"
		if err := yaml.Unmarshal([]byte(doc), &svc); err != nil {
			t.Fatal(err)
		}
		if !svc.HasFilter() {
			t.Fatal("HasFilter() = false")
		}
		if svc.FilterPolicyVault() != "policy" {
			t.Errorf("FilterPolicyVault() = %q, want %q", svc.FilterPolicyVault(), "policy")
		}
		b, err := json.Marshal(svc)
		if err != nil {
			t.Fatal(err)
		}
		var back Service
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Filter == nil {
			t.Fatal("Filter = nil after round trip")
		}
		if back.Filter.URL != "https://p.example.com" ||
			back.Filter.PolicyVault != "policy" ||
			!back.Filter.AllowInsecurePrivateHTTP {
			t.Errorf("Filter = %+v after round trip", back.Filter)
		}
	})
}

func TestHasFilterNilSafe(t *testing.T) {
	var svc *Service
	if svc.HasFilter() {
		t.Error("HasFilter() = true on a nil *Service")
	}
	if svc.FilterPolicyVault() != "" {
		t.Error("FilterPolicyVault() non-empty on a nil *Service")
	}
}
