package proposal

import (
	"reflect"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func filteredService(name, host string) broker.Service {
	return broker.Service{
		Name: name,
		Host: host,
		Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
		Filter: &broker.Filter{
			URL:         "https://policy.example.com/hook",
			PolicyVault: "policy",
		},
	}
}

// An agent proposal re-supplying a filtered service's auth is a full
// replacement inside MergeServices. The filter has to survive it.
func TestMergeServicesPreservesFilterOnUpsert(t *testing.T) {
	existing := []broker.Service{filteredService("github-push", "github.com")}
	proposed := []Service{{
		Action: ActionSet,
		Name:   "github-push",
		Host:   "github.com",
		Auth:   &broker.Auth{Type: "bearer", Token: "ROTATED_TOKEN"},
	}}

	merged, _ := MergeServices(existing, proposed)
	if len(merged) != 1 {
		t.Fatalf("len(merged) = %d, want 1", len(merged))
	}
	if merged[0].Auth.Token != "ROTATED_TOKEN" {
		t.Errorf("Auth.Token = %q, want the proposed rotation to land", merged[0].Auth.Token)
	}
	if merged[0].Filter == nil {
		t.Fatal("Filter = nil — a proposal stripped an admin-only policy hop")
	}
	if merged[0].Filter.URL != "https://policy.example.com/hook" || merged[0].Filter.PolicyVault != "policy" {
		t.Errorf("Filter = %+v, want the stored block unchanged", merged[0].Filter)
	}
}

// The enable/disable overlay never rebuilt the service, but assert it
// anyway so a future refactor of that branch can't quietly drop the block.
func TestMergeServicesPreservesFilterOnEnableToggle(t *testing.T) {
	existing := []broker.Service{filteredService("github-push", "github.com")}
	off := false
	merged, _ := MergeServices(existing, []Service{{
		Action:  ActionSet,
		Name:    "github-push",
		Host:    "github.com",
		Enabled: &off,
	}})
	if merged[0].Filter == nil {
		t.Fatal("Filter = nil after an enabled-only overlay")
	}
	if merged[0].IsEnabled() {
		t.Error("IsEnabled() = true, want the overlay to have applied")
	}
}

// A newly proposed service must not somehow acquire a filter.
func TestMergeServicesNewServiceHasNoFilter(t *testing.T) {
	merged, _ := MergeServices(nil, []Service{{
		Action: ActionSet,
		Name:   "new-svc",
		Host:   "api.example.com",
		Auth:   &broker.Auth{Type: "bearer", Token: "TOKEN"},
	}})
	if len(merged) != 1 {
		t.Fatalf("len(merged) = %d, want 1", len(merged))
	}
	if merged[0].Filter != nil {
		t.Errorf("Filter = %+v, want nil on a proposal-created service", merged[0].Filter)
	}
}

func TestFilteredServiceDeletes(t *testing.T) {
	existing := []broker.Service{
		filteredService("github-push", "github.com"),
		{Name: "github-api", Host: "api.github.com", Auth: broker.Auth{Type: "bearer", Token: "GITHUB_TOKEN"}},
		filteredService("openai", "api.openai.com"),
	}

	tests := []struct {
		name     string
		proposed []Service
		want     []string
	}{
		{
			name:     "deleting an unfiltered service is fine",
			proposed: []Service{{Action: ActionDelete, Name: "github-api"}},
			want:     nil,
		},
		{
			name:     "deleting a filtered service is caught",
			proposed: []Service{{Action: ActionDelete, Name: "github-push"}},
			want:     []string{"github-push"},
		},
		{
			name: "several, deduplicated, in proposal order",
			proposed: []Service{
				{Action: ActionDelete, Name: "openai"},
				{Action: ActionDelete, Name: "github-push"},
				{Action: ActionDelete, Name: "openai"},
			},
			want: []string{"openai", "github-push"},
		},
		{
			name:     "a set action on a filtered service is not a delete",
			proposed: []Service{{Action: ActionSet, Name: "github-push", Host: "github.com", Auth: &broker.Auth{Type: "bearer", Token: "T"}}},
			want:     nil,
		},
		{
			name:     "deleting a name that does not exist",
			proposed: []Service{{Action: ActionDelete, Name: "ghost"}},
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FilteredServiceDeletes(existing, tc.proposed)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FilteredServiceDeletes() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilteredServiceDeletesNoFilteredServices(t *testing.T) {
	existing := []broker.Service{{Name: "plain", Host: "example.com"}}
	if got := FilteredServiceDeletes(existing, []Service{{Action: ActionDelete, Name: "plain"}}); got != nil {
		t.Errorf("FilteredServiceDeletes() = %v, want nil", got)
	}
}
