# Per-service request filters — round 2 supplement

**This file supplements `service-filters.plan.md`; it does not replace it.**
Only corrections, changed decisions, and new requirements appear here. Every
original decision not modified below remains in force.

Inputs: the three implementations at `issue-407-codex@a0dd71b`,
`origin/issue-407-cursor@a79e069`, and `origin/issue-407-claude@8cb1897`;
`claude_reviews_codex_and_cursor_combined.md`; `cursor-morning-review.md`; and
`codex-round2-review.md`.

Local working spec. Do not include `ad_hoc/` in the upstream pull request.

---

## 0. Corrections to the original document

These correct contract language; they do not change product behavior.

1. Remove the implementation-status sentence near the top and restate the
   Layout A smoke paragraph as a requirement. Branch state is not part of the
   specification.

2. Replace the revocation comparison to ordinary CONNECT traffic. The current
   unfiltered path captures a session scope for an established tunnel, so
   ordinary `agent revoke` takes effect on the next CONNECT, not on each request
   in the existing tunnel. Filter capabilities intentionally provide the
   stricter guarantee because their shared row can be revalidated cheaply. Do
   not widen ordinary CONNECT revocation in this feature.

3. Replace “auth + substitution snapshot: credential key names only” with:
   “the complete non-secret configuration needed to reproduce Resolve,
   including auth type, header name, prefix, custom header templates, and each
   substitution's key, placeholder, and surfaces; credential references remain
   key names and values are resolved only after consume.” Operator-authored
   custom templates are arbitrary text and may contain literals, just as they
   already may in `broker_config.services_json`; do not claim the database can
   prove such literals are non-secret.

---

## 1. New locked decisions

Numbering continues from the original checklist.

### 19. Proposals cannot shadow a filtered matcher

At proposal creation, reject a proposed effective service that is unfiltered
and whose matcher can win over, or tie, an existing filtered service for any
request. Repeat the check at apply against the then-current broker config; a
conflict introduced after proposal creation returns `409` and the proposal is
not applied.

The comparison operates on the **effective merge**, so an update to the same
service that preserves its filter is not rejected. Normalize inline host/path/
port forms before checking.

Implement a reusable matcher-overlap helper using the real matching semantics:

- host languages overlap for equal exact hosts, equal one-label wildcards, or
  an exact host matched by the other one-label wildcard;
- port languages overlap when the explicit ports agree or either side omits a
  port;
- path languages overlap according to the existing `*` glob language, not a
  string-prefix approximation; use a small DP/NFA intersection or an
  equivalently exact helper;
- on a shared witness request, compare the actual priority tuple: host tier,
  port specificity, then literal path-prefix length. Reject when the proposed
  tuple is better or equal.

Equal priority is rejected even though today's append order normally leaves the
existing service first; proposal safety must not depend on a later serialization
or reorder preserving declaration order. The error identifies both proposed
and filtered service names/matchers.

This restriction is proposal-only. A vault admin may create an intentional
overlapping unfiltered exception through direct YAML/upsert, preserving current
matcher semantics and explicit admin control.

### 20. Policy capabilities use configured-service-only matching

A policy capability never reads or honors `unmatched_host_policy`. Add an
explicit strict matching operation/mode that searches configured services only:

- no configured match: fail closed;
- disabled match: fail closed;
- filtered match: fail closed (no recursion);
- unfiltered configured match, including an explicitly configured passthrough
  service: proceed normally.

Do not implement this as “call ordinary Match and reject a Passthrough result”
if ordinary Match has already consulted the vault setting. Keep the strict mode
separate enough that tests can prove the setting store was never read.

For CONNECT authenticated by a policy capability, perform a pre-hijack
authority eligibility check: the target host and port must be covered by at
least one enabled, unfiltered configured service in the policy vault. Path is
checked by strict matching on each inner request. This prevents unmatched policy
tokens from being used as a leaf-minting or tunnel-admission oracle.

### 21. Security enforcement is mandatory by interface and error path

Match, Resolve-frozen, capability claim/consume/validate, source-authority
revalidation, strict policy matching, and policy-vault lookup are required
contracts. Do not guard them with optional type assertions that mean “skip the
check” when absent. Test doubles must implement the same security surface as
production stores.

Any error from Match, capability persistence, source revalidation, snapshot
decode, or policy-vault resolution fails closed. A configured filter with no
filter engine or shared capability store returns `502 filter_misconfigured`; it
never falls back to ordinary Inject. An in-memory store is permitted only when
selected explicitly for tests/single-instance development, never as an implicit
production fallback.

### 22. Remove destination credential header slots before the sidecar

Before the request is sent to `filter.url`, derive the header names the frozen
service would overwrite during Resolve without reading credential values:

- bearer/basic: `Authorization`;
- api-key: the configured header, or its default;
- custom: every configured output header name;
- passthrough: none.

Delete those client-supplied headers from the sidecar request, along with
`Proxy-Authorization`, `X-Vault`, hop-by-hop headers, and the reserved
`X-Agent-Vault-*` namespace. Do **not** unconditionally strip `Authorization`
when a different destination auth slot is used; it may be ordinary application
data that continuation must preserve.

Continuation resolution still overwrites each injected header with `Set`, not
`Add`, and the reserved namespace is stripped again before origin.

### 23. Capability pairs have an invocation lifecycle

Mint the continuation and optional policy capability as one logical invocation.
Resolve the policy-vault scope first, then insert both rows in one transaction;
a partial pair must never become visible.

If the sidecar cannot be reached, times out, rejects without using the
continuation, fails its WebSocket upgrade, or the client-side filtered stream
ends, retire every still-live capability for that invocation immediately.
Cleanup is best-effort defense in depth—expiry and validation remain mandatory—
and operates by hashes/row IDs without persisting raw tokens. A scheduled
sweeper removes any rows cleanup misses.

The sidecar contract is synchronous: returning its final response means the
decision is complete. It may not retain a policy capability for asynchronous
work after that response.

---

## 2. Amendments to original locked decisions

### Amend decisions 5 and 15 — explicit three-state continuation FSM

The continuation state machine is `issued -> claimed -> consumed`:

1. The first admission through either ingress atomically changes `issued` to
   `claimed` after source-authority and bound-authority validation:
   - CONNECT: before hijack, leaf mint, or tunnel setup;
   - absolute-form HTTP: before processing that same request.
2. A second admission, including a second CONNECT to the correct authority,
   fails because the row is no longer `issued`.
3. The exact HTTP/WebSocket request atomically changes `claimed` to `consumed`.
   Resolve is permitted only after that successful transition.

Wrong authority at admission, or wrong method/scheme/authority/escaped-path/
raw-query at consume, transitions the row to `consumed` and commits the burn.
The token holder already has enough authority to spend the correct request, so
leaving a mismatched bearer reusable provides no useful safety property.

Source-session existence/expiry, actor identity/status, and source-vault grant
are revalidated in the same transaction as each state transition. The
conditional `UPDATE ... WHERE state = ?` plus `RowsAffected == 1` is the atomic
mechanism on SQLite; `SELECT ... FOR UPDATE` is additional PostgreSQL locking,
not the basis of SQLite correctness. Document this in the store code.

Policy capabilities remain reusable while live, but source authority is
revalidated on every inner request in a persistent CONNECT tunnel. Observing a
revoked/expired source burns or deletes that policy capability so re-granting
the actor cannot revive it during the original TTL.

### Amend decision 9 — capability namespace and strip ordering

Use distinct raw-token prefixes:

- `av_cont_` for continuations;
- `av_pol_` for policy capabilities.

Only token hashes are stored. Prefix-based dispatch never tries a capability as
an ordinary session or vice versa, and redaction rules recognize both forms.

Namespace handling is **strip untrusted headers, then set trusted headers** on
the sidecar hop. On sidecar response/error handling, strip its reserved
namespace first and only then set Agent Vault's own
`X-Agent-Vault-Proxy-Error` envelope header. The same namespace is stripped
from continuation requests before origin.

### Amend decision 10 — complete URL validation

`filter.url` must be absolute `http` or `https`, include a host, and contain no
userinfo or fragment. A path prefix is allowed. Reject a configured query or
`ForceQuery`, because the protocol replaces it with the original request query;
silently accepting unused query material is ambiguous and can put secrets in
configuration/logs.

Validate `AGENT_VAULT_FILTER_PROXY_URL` at startup. It must be a base URL with
no userinfo, path, query, or fragment; HTTPS is required except for HTTP to a
literal loopback IP. If the operator explicitly supplies an invalid value,
startup fails rather than silently advertising another address.

Redirect behavior must be implemented, not merely documented: direct
`Transport.RoundTrip` does not follow redirects; an `http.Client` must set
`CheckRedirect` to return `http.ErrUseLastResponse`.

### Amend decision 12 — proposal write semantics

An explicit `filter` key in proposal JSON, including `filter: null`, is rejected
with an admin-only explanation rather than silently ignored. Filtered-service
delete and matcher-shadow checks run at both create and apply.

`enabled: false` on a filtered service remains allowed: the disabled match
returns a fail-closed denial rather than falling through to unmatched-host
passthrough, so this is denial of service rather than filter bypass. Document
the intentional asymmetry with delete.

### Amend decisions 16 and 17 — source identity and frozen payload

Persist the initiating session's **sessions-table hash**, never `Session.ID`
from `GetSession` and never the raw token. Provide an explicit lookup by stored
hash. A source-session foreign key with `ON DELETE CASCADE` is useful defense in
depth, but runtime expiry/status/grant checks remain required.

Use a versioned frozen-service projection containing every field used by
Resolve and no field used only to decide whether to enter the filter. In
particular, exclude `Filter` so continuation cannot accidentally re-enter it;
include the complete auth and substitution shapes described in §0.

Decode in two stages: read and validate the envelope version first, then decode
that version's typed payload. Unknown versions, unknown required semantics,
malformed data, derived credential-key disagreement, or invalid service config
fail closed before any credential-store read. Updating service YAML cannot
retarget the slot; updating the frozen key's value remains visible at Resolve.

---

## 3. Store and portability requirements

- Put database constraints on kind/state and indexes on token hash, expiry, and
  source-session hash. Never persist raw session/capability tokens or resolved
  credential values.
- Scheduled cleanup follows the server's existing ticker-until-context-cancel
  pattern. Correctness never depends on cleanup; every read checks expiry.
- Verify the state transitions and N-way single winner on real SQLite, not only
  an in-memory fake.
- Keep PostgreSQL SQL parameterized through the dialect. Provide an opt-in live
  PostgreSQL integration test when a test DSN is available. Until it runs in
  CI, state plainly in the PR that PostgreSQL is compile/review checked but the
  filter-capability path is executed only on SQLite.

---

## 4. Required test additions

These supplement, rather than replace, the original test matrix.

### Blocking findings

1. Proposal adds an unfiltered exact/longer-path matcher over a filtered
   wildcard/path matcher: reject at create. Repeat after config changes between
   create and apply: `409`, no mutation. Cover disjoint host/path/port patterns
   to prove the overlap helper does not reject harmless services.
2. Policy capability against an unmatched host while the vault setting is
   `passthrough`: deny, do not contact origin, and assert the unmatched-policy
   store method was never called.
3. Policy CONNECT to an authority with no eligible unfiltered configured
   service: reject before hijack/leaf mint. A path mismatch after an otherwise
   eligible CONNECT also fails closed.

### Capability and revocation

4. N concurrent claims on real SQLite: exactly one `issued -> claimed`; N
   concurrent consumes: exactly one `claimed -> consumed`.
5. Wrong CONNECT authority burns the continuation before hijack; wrong inner
   bind also burns it; a subsequent correct attempt fails.
6. Agent revoke, session revoke/expiry, user deactivation, and source-vault
   grant removal reject both capability kinds. Re-grant does not revive a
   capability observed revoked. Exercise requests inside an existing CONNECT.
7. Inspect the real database: no column equals any live raw source-session,
   continuation, policy, or credential value.
8. Force failure of the second row in pair issuance and assert neither row is
   visible. Fail/deny a hop and assert remaining invocation rows are retired.

### Frozen match and interfaces

9. YAML matcher/auth-key edits do not retarget; a value update of the frozen
   key is used; deletion fails closed. Custom auth header templates and all
   substitution fields round-trip.
10. Unknown envelope version and malformed/incomplete payload fail before any
    credential read. Add a compile-time interface assertion for production and
    test stores; a Match error never falls through to Inject.
11. A filtered service with absent filter engine/store returns
    `502 filter_misconfigured` with zero origin and credential reads.

### Headers, URLs, WebSocket, and smoke

12. Client values in destination injection header slots do not reach the
    sidecar. An unrelated `Authorization` header on a service using another
    auth slot is preserved. Reserved response headers cannot spoof Agent Vault's
    own error header.
13. Reject `filter.url` userinfo/fragment/query and callback URL userinfo/path/
    query/fragment/non-loopback HTTP. Confirm redirects are returned, not
    followed.
14. Full filtered WebSocket bridge: sidecar callback through continuation,
    bidirectional frames, origin gets injected credential, Resolve exactly
    once. Denied upgrade yields zero Resolve; unfiltered WS is unchanged.
15. `TestSmoke_FilterLayoutA` uses `store.Open` with real SQLite and asserts
    both denial (zero origin/credential reads) and allow (origin receives the
    injected destination credential), with no filter-agent row.

---

## 5. Explicitly unchanged / out of scope

- Keep proposal-only shadow prevention; do not change global matcher semantics
  to “any overlapping filtered matcher always wins.”
- Do not add ordinary established-CONNECT revocation to this feature.
- Do not add a TTL flag/env setting; 30 seconds remains a named constant.
- Do not add RFC 9457, a filter-agent, an in-process plugin system, or nested
  filter hops.
- Do not hide filtered services from `/discover`; hide only filter topology and
  capability material as already required.

---

## 6. Round 2 checklist

19. Proposal effective matchers cannot shadow filtered services; check create
    and apply with exact matcher-language overlap.
20. Policy capabilities match configured, enabled, unfiltered services only and
    never consult unmatched-host policy; CONNECT has a pre-hijack authority gate.
21. Security interfaces and errors fail closed; no optional enforcement or
    implicit production memory fallback.
22. Destination credential header slots are removed before the sidecar without
    stripping unrelated application headers.
23. Continuation/policy rows are minted and retired as one invocation.

Amended: 5/15 (three-state FSM, burn, transactional source check), 9 (per-kind
prefixes and strip ordering), 10 (complete URL/callback validation), 12
(explicit proposal filter rejection and shadow checks), 16/17 (session hash and
version-first complete frozen projection).
