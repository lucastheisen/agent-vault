package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFilterAgentNameIsValidSlug(t *testing.T) {
	name := FilterAgentName("dev", "http://127.0.0.1:12345")
	if err := ValidateSlug(name); err != nil {
		t.Fatalf("FilterAgentName %q: %v", name, err)
	}
	if !strings.HasPrefix(name, FilterAgentNamePrefix) {
		t.Fatalf("expected prefix %s, got %q", FilterAgentNamePrefix, name)
	}
}

func TestFilterAgentNameStableAndShared(t *testing.T) {
	a := FilterAgentName("policy", "http://127.0.0.1:12345")
	b := FilterAgentName("policy", "http://127.0.0.1:12345")
	if a != b {
		t.Fatalf("same url+vault must share name, got %q vs %q", a, b)
	}
	c := FilterAgentName("other", "http://127.0.0.1:12345")
	if a == c {
		t.Fatal("different vault must produce a different agent name")
	}
	d := FilterAgentName("policy", "http://127.0.0.1:9999")
	if a == d {
		t.Fatal("different url must produce a different agent name")
	}
}

func TestFilterAgentNameLongVault(t *testing.T) {
	long := strings.Repeat("v", 64)
	name := FilterAgentName(long, "https://filter.example.com")
	if err := ValidateSlug(name); err != nil {
		t.Fatalf("long vault name produced invalid slug %q: %v", name, err)
	}
}

func TestUnmarshalJSONFilterOmitSetClear(t *testing.T) {
	var omit Service
	if err := json.Unmarshal([]byte(`{"name":"s","host":"h.example","auth":{"type":"passthrough"}}`), &omit); err != nil {
		t.Fatal(err)
	}
	if omit.FilterOp != FilterOpOmit || omit.Filter != nil {
		t.Fatalf("omit: op=%d filter=%v", omit.FilterOp, omit.Filter)
	}

	var set Service
	if err := json.Unmarshal([]byte(`{"name":"s","host":"h.example","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:12345","vault":"policy"}}`), &set); err != nil {
		t.Fatal(err)
	}
	if set.FilterOp != FilterOpSet || set.Filter == nil || set.Filter.URL != "http://127.0.0.1:12345" {
		t.Fatalf("set: %+v op=%d", set.Filter, set.FilterOp)
	}

	var clr Service
	if err := json.Unmarshal([]byte(`{"name":"s","host":"h.example","auth":{"type":"passthrough"},"filter":null}`), &clr); err != nil {
		t.Fatal(err)
	}
	if clr.FilterOp != FilterOpClear || clr.Filter != nil {
		t.Fatalf("null: op=%d filter=%v", clr.FilterOp, clr.Filter)
	}

	var empty Service
	if err := json.Unmarshal([]byte(`{"name":"s","host":"h.example","auth":{"type":"passthrough"},"filter":{}}`), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.FilterOp != FilterOpClear {
		t.Fatalf("empty object should clear, op=%d", empty.FilterOp)
	}
}

func TestApplyFilterWrite(t *testing.T) {
	existing := Service{Filter: &Filter{URL: "http://127.0.0.1:1", AgentID: "abc"}}

	omit := existing
	ApplyFilterWrite(&omit, Service{FilterOp: FilterOpOmit})
	if omit.Filter == nil || omit.Filter.AgentID != "abc" {
		t.Fatal("omit must preserve filter")
	}

	clear := existing
	ApplyFilterWrite(&clear, Service{FilterOp: FilterOpClear})
	if clear.Filter != nil {
		t.Fatal("clear must drop filter")
	}

	set := existing
	ApplyFilterWrite(&set, Service{FilterOp: FilterOpSet, Filter: &Filter{URL: "http://127.0.0.1:2"}})
	if set.Filter == nil || set.Filter.URL != "http://127.0.0.1:2" {
		t.Fatalf("set: %+v", set.Filter)
	}

	keepID := existing
	ApplyFilterWrite(&keepID, Service{FilterOp: FilterOpSet, Filter: &Filter{URL: "http://127.0.0.1:1"}})
	if keepID.Filter == nil || keepID.Filter.AgentID != "abc" {
		t.Fatalf("same url+vault must keep agent_id, got %+v", keepID.Filter)
	}
}

func TestMarshalJSONFilterClear(t *testing.T) {
	svc := Service{
		Name:     "s",
		Host:     "h.example",
		Auth:     Auth{Type: "passthrough"},
		FilterOp: FilterOpClear,
	}
	b, err := json.Marshal(svc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"filter":null`) {
		t.Fatalf("clear must emit filter:null, got %s", b)
	}
}

func TestValidateFilter(t *testing.T) {
	if err := ValidateFilter(&Filter{URL: "http://127.0.0.1:12345"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFilter(&Filter{URL: "ftp://127.0.0.1"}); err == nil {
		t.Fatal("expected ftp rejected")
	}
	if err := ValidateFilter(&Filter{URL: "http://127.0.0.1", Vault: "Not_A_Slug"}); err == nil {
		t.Fatal("expected bad vault slug rejected")
	}
}
