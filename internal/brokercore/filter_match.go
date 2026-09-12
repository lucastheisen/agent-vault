package brokercore

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

// Errors from the frozen-match codec. Each one is fail-closed: a match
// that cannot be reconstructed exactly must not lead to any credential
// read.
var (
	ErrFrozenMatchVersion = errors.New("brokercore: unsupported frozen-match format version")
	ErrFrozenMatchInvalid = errors.New("brokercore: malformed frozen match")
)

// FrozenMatch is the versioned, non-secret serialization of a
// CredentialMatch as stored in a filter capability row.
//
// A shared capability store cannot hold an in-process pointer, so the
// match travels as data. What travels is the matched service exactly as
// it was at hop start: identity, matcher, auth *configuration*, and
// substitution declarations — all of which reference credentials by key
// name and never by value.
//
// Reconstructing from this snapshot is what makes the continuation
// immune to a mid-window service edit: Resolve never re-runs the
// matcher against the vault's current, mutable service list.
type FrozenMatch struct {
	// Version gates the whole record. It is checked before the payload
	// is trusted, because encoding/json silently drops fields it does
	// not know — a newer replica writing a field an older one cannot
	// read would otherwise resolve a subtly different request.
	Version int `json:"version"`

	// Service is the matched service. Serialized through
	// broker.Service's own codec, which is the same shape already
	// persisted in broker_config.services_json, so the snapshot adds no
	// storage format to keep in step and no new exposure.
	Service *broker.Service `json:"service"`
}

// FreezeMatch serializes a match for storage in a capability row.
// Passthrough matches are never filtered, so freezing one is a
// programming error rather than a runtime condition.
func FreezeMatch(m *CredentialMatch) (string, error) {
	if m == nil || m.Service == nil {
		return "", fmt.Errorf("%w: no service to freeze", ErrFrozenMatchInvalid)
	}
	if m.Passthrough {
		return "", fmt.Errorf("%w: passthrough matches are not filtered", ErrFrozenMatchInvalid)
	}
	b, err := json.Marshal(FrozenMatch{
		Version: store.FilterMatchSnapshotVersion,
		Service: m.Service,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFrozenMatchInvalid, err)
	}
	return string(b), nil
}

// ThawMatch reconstructs the immutable match a continuation was issued
// against.
//
// Anything unexpected — an unknown version, malformed JSON, a missing
// service, a service with no name or host — fails closed here, before a
// caller has any chance to resolve a credential from it.
func ThawMatch(snapshot string) (*CredentialMatch, error) {
	if snapshot == "" {
		return nil, fmt.Errorf("%w: empty snapshot", ErrFrozenMatchInvalid)
	}
	var fm FrozenMatch
	if err := json.Unmarshal([]byte(snapshot), &fm); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFrozenMatchInvalid, err)
	}
	if fm.Version != store.FilterMatchSnapshotVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrFrozenMatchVersion, fm.Version, store.FilterMatchSnapshotVersion)
	}
	if fm.Service == nil {
		return nil, fmt.Errorf("%w: snapshot carries no service", ErrFrozenMatchInvalid)
	}
	svc := *fm.Service
	// broker.Service marshals Host in joined inline form; split it back
	// so the thawed value is identical to what Match produced.
	svc.Host, svc.Path, svc.Port = broker.SplitInlineHost(svc.Host, svc.Path)
	if svc.Name == "" || svc.Host == "" {
		return nil, fmt.Errorf("%w: snapshot service is missing name or host", ErrFrozenMatchInvalid)
	}
	return &CredentialMatch{Service: &svc}, nil
}
