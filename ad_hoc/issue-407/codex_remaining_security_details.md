# Remaining security details for the hybrid filter plan

The revised hybrid plan resolves the earlier design disagreements: destination credentials remain unresolved until an exact continuation succeeds, capabilities are short-lived and replica-safe, same-vault access is explicit, private cleartext sidecars require opt-in, and filtered WebSockets are supported.

Two security details must be specified before implementation begins.

## 1. Capability revocation semantics

Continuation and policy capabilities retain the initiating actor and are valid for at most 30 seconds. The plan must state whether revoking that actor's session or agent immediately invalidates capabilities already issued from it.

The required rule is immediate invalidation:

- A capability row records its source session or agent identity in addition to actor and vault scope.
- On proxy authentication and again when consuming a continuation, Agent Vault verifies that the source session or agent remains active and authorized for the source vault.
- Revocation, expiry, or removal of that source authority causes the capability request to fail closed, even if its own TTL has not elapsed.
- A policy capability checked on a persistent CONNECT tunnel must be revalidated for each new proxied request, not only when the tunnel is established.

Thirty seconds is a maximum capability lifetime, not a permitted post-revocation grace period. This preserves the ordinary expectation that revoking an agent removes its effective proxy authority immediately.

## 2. Frozen-match persistence format

A shared capability store cannot retain an in-process `CredentialMatch` pointer. It must store a versioned, non-secret snapshot sufficient to resolve the exact service that matched at filter-hop creation time.

The required record contains:

- format version;
- source vault identifier and initiating actor/session identity;
- capability kind, random-token hash, expiry, and issued/claimed/consumed state;
- exact request binding: method, scheme, authority, escaped path, and query;
- canonical matched-service name, host, path, and port;
- a non-secret snapshot of the service auth and substitution configuration, including credential **key names** but never credential values;
- policy-vault scope when the capability is for a policy call.

At continuation consumption, Agent Vault reconstructs an internal immutable match from this snapshot and resolves its credential keys against the source vault. It must not re-run service matching against current mutable service configuration. Consequently, an administrator changing or replacing a service during the 30-second window cannot redirect the continuation to a different credential.

Malformed, unknown-version, incomplete, expired, or inconsistent snapshots fail closed. Database access controls and logs must treat the snapshot as sensitive policy metadata, while the record must never contain decrypted credentials, bearer capability tokens, or their reversible forms.

## Verification

Add tests proving that:

1. Revoking a source agent/session after capability issuance rejects both a policy call and a continuation.
2. A revoked capability cannot be revived by reconnecting through a new CONNECT tunnel.
3. An administrator changing service credentials or matcher configuration after issuance does not affect the continuation's frozen match.
4. Unknown snapshot versions and malformed serialized matches fail closed without credential reads.
5. Capability rows and request logs contain no credential values or raw capability tokens.
