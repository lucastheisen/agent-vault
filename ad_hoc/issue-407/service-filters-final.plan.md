# Per-service request filters — final plan

**Status: final. This document is self-contained and is the implementation
contract.** It supersedes `service-filters.plan.md` and all three round-2
supplements. Phase 3 implements from this file alone; nothing here requires
reading the earlier documents.

Working design for an out-of-process "servlet filter" hop on the MITM proxy:
after a service matches, Agent Vault reverse-proxies the live request to an
operator-configured URL **without resolving destination credentials**. The
sidecar may short-circuit (any HTTP response) or continue through Agent Vault
with short-lived capabilities.

Local working spec, not upstream docs. Canonical issue:
https://github.com/Infisical/agent-vault/issues/407. Do not include `ad_hoc/`
in the pull request. After merge, operator-facing behavior belongs in Mintlify
(`docs/learn/services.mdx`, CLI reference), not here.

### Provenance

Three agents independently implemented the round-1 plan, reviewed each other,
and produced round-2 supplements. This document reconciles them. Where they
disagreed, the resolution and its reason are recorded inline. Notable
attributions:

- The three-state capability FSM, burn-on-mismatch, in-transaction source
  revalidation, auth-slot-derived header stripping, the policy CONNECT
  eligibility gate, transactional capability-pair minting, and exact
  matcher-language overlap came from **Codex**, which produced the strongest
  supplement.
- Per-kind token prefixes and the operator-facing `filter: null` tri-state came
  from **Cursor**.
- The two blocking findings (proposal matcher shadowing; policy capability
  inheriting unmatched-host passthrough), the interface-discipline rule, and
  the session-hash handling came from **Claude**.
- The `AGENT_VAULT_FILTER_PROXY_URL` failure mode was decided by the operator:
  **refuse to start**.

---

## Problem

The broker matcher is host/path/port plus credential injection. Some policies
need **arbitrary logic** on the request — inspect a git-receive-pack body, call
GitLab's protection API, rewrite an OpenAI model — **before** destination
secrets are attached.

That logic must not live in Agent Vault. The OSS seam is: match → hop to
sidecar → sidecar decides.

Motivating example (not the only consumer): `git push` over HTTPS. The sidecar
parses the target ref, asks whether the branch is protected, returns 403 or lets
the push proceed with credentials attached.

## Non-goals

- In-process plugins, WASM, Go `.so`, or a new rules language.
- Filter as a chained HTTP forward-proxy (absolute-form / CONNECT **to the
  sidecar**). v1 is **reverse-proxy to `filter.url`**. Continuation and policy
  callbacks **to Agent Vault** use the existing MITM forward-proxy, including
  CONNECT.
- Durable filter-agents, recoverable long-lived filter tokens, `kind` on agents,
  reserved `filter-` names.
- Per-request DB writes on the **unfiltered** Inject path.
- RFC 9457 Problem Details. Keep `{error, message}` + `X-Agent-Vault-Proxy-Error`.
- `/discover` exposure, agent skill exposure, dashboard UI, `--filter-*` flags,
  `vault service filter` subcommands.
- Binding the continuation to request-body bytes — packfiles must stream.
- Changing global matcher semantics, widening revocation of ordinary unfiltered
  CONNECT tunnels, or a TTL flag. See §12.

---

## 1. Placement in the pipeline

Today: authenticate → rate limit → **Inject (match + decrypt)** → substitutions
→ origin (or WebSocket dial).

**Unfiltered** services: unchanged, including WebSocket to origin. **No**
capability-table write, ever — a filter-path outage must not degrade ordinary
proxying.

**Filtered** match: authenticate → rate limit → **match (no dest decrypt)** →
reverse-proxy to `filter.url` → the sidecar's response is the client's response.

`CredentialProvider` splits **Match** from **Resolve**. A `CredentialMatch`
holds service metadata and no decrypted destination secret. `Resolve` runs only
after a valid continuation is consumed, or immediately on the unfiltered path.

**Invariant:** denied, timed-out, or unreachable filter → **zero** reads or
decryptions of the destination credential. Test this by *counting* credential
store calls, not by asserting a status code — a status assertion passes even if
the DEK was opened and the result discarded.

Disabled service / no match: unchanged. Do not call the filter.

---

## 2. Config (operator)

Optional block on `broker.Service`. YAML-only, same precedent as substitutions.

```yaml
services:
  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: https://policy.example.com/github-push
      policy_vault: policy          # optional; see modes below
```

| Field | Required | Meaning |
|---|---|---|
| `url` | yes if `filter` present | Sidecar origin. `https` normally. Literal-loopback `http` is allowed without a flag. Non-loopback `http` requires `allow_insecure_private_http: true`. |
| `policy_vault` | no | Vault the **policy capability** is scoped to. **Omitted = no policy capability.** Source vault name = Layout A. Different vault = Layout B. |
| `allow_insecure_private_http` | no | Explicit opt-in for cleartext to a loopback or RFC1918 sidecar. Weaker than TLS; document it as such. |

`policy_vault` modes:

| Value | Policy capability | Use |
|---|---|---|
| omitted | none | Body/header-only decision. |
| source vault name | 30s capability on the source vault | Layout A. Must be written explicitly. |
| different vault name | 30s capability on that vault | Layout B. Configuring actor must be **vault admin of both**. |

Agent Vault does not constrain which *unfiltered* services live in the policy
vault. No `agent_id`; nothing is minted into the agents table.

### 2.1 `filter.url` validation

Absolute `http` or `https`, with a host. A path prefix is allowed — the original
path and query are appended after it. Reject:

- userinfo (would smuggle sidecar credentials past `allow_insecure_private_http`,
  and contradicts "secrets are not in URLs");
- a fragment;
- a configured query or `ForceQuery` — the protocol replaces the query with the
  original request's, so accepting unused query material is ambiguous and can
  put secrets in config and logs;
- any scheme other than `http`/`https`.

### 2.2 `AGENT_VAULT_FILTER_PROXY_URL`

The forward-proxy base URL a remote sidecar calls back on. Unset means advertise
the process's own loopback listener, which only a same-host sidecar can reach.

Must be a **base URL**: no userinfo, path, query, or fragment. `https`, except
`http` to a literal loopback IP.

**An invalid value is fatal at startup.** The operator set it explicitly, so a
bad value is a configuration error, not a degraded capability — and silently
advertising a different address than intended is exactly the failure mode this
rule exists to prevent. Do not warn-and-fall-back.

Document in `.env.example`, `docs/self-hosting/environment-variables.mdx`, and
the env table in `docs/reference/cli.mdx`.

---

## 3. Who writes what

| Write | `filter` |
|---|---|
| Agent proposal that sets or clears `filter` | **Reject** with an admin-only explanation. An explicit `filter` object *or* `filter: null` is a 400 — silently dropping the unknown key is not enough, because the agent would believe it had configured a policy hop. |
| Agent proposal that **deletes** a filtered service | **Reject.** |
| Agent proposal that introduces a competing matcher | **Reject.** See §4. |
| Agent proposal that updates auth/host of a filtered service | **Preserve** `filter`. |
| Agent proposal with `enabled: false` on a filtered service | **Allow.** A disabled service returns a fail-closed denial rather than falling through to unmatched-host passthrough, so this is denial of service, not bypass. Document the intentional asymmetry with delete. |
| `vault service add` / POST upsert, field omitted | **Preserve.** |
| `vault service add` with `filter:` or `filter: null` | Set or clear. Requires a tri-state on the wire: omitted and explicit-null both decode to a nil pointer, so key *presence* must survive YAML → JSON → API. |
| `vault credential set` | Does not touch services. |
| `vault service set` (replace list) / `clear` | **Not preserved.** Document. List output includes `filter` so a round trip is safe. |
| Interactive `service set` "Replace all" | Same as `set` (wipe). No wizard prompt for filter in v1. |
| Admin delete service | Allowed — explicit policy removal. |

Admin `vault service list` **must include** `url`, `policy_vault`, and
`allow_insecure_private_http` when set, so a list-then-set round trip cannot
silently strip a filter. Never include capability material. Proxy-role callers
read services without the filter block, matching `/discover`.

---

## 4. Proposals cannot shadow a filtered matcher

`MatchScore.Better` ranks host tier → port specificity → path literal length and
**ignores declaration order**. An agent can therefore propose
`github.com/acme/app.git/git-receive-pack` (unfiltered, referencing a PAT
already in the vault) over an admin's filtered `github.com/*/git-receive-pack`,
win the match, and get the credential injected with no filter hop. The human
approving the proposal sees "add a service".

**Rule.** At proposal **create** and again at **apply** against then-current
config, reject a proposed effective service that is unfiltered and whose matcher
can win or **tie** an existing filtered service for any request. Create returns
400; a conflict introduced between create and apply returns 409 and the proposal
is not applied. The error names both the proposed and the filtered service.

The comparison runs on the **effective merge**, so updating a filtered service in
a way that preserves its filter is not rejected. Normalize inline host/path/port
forms first.

Implement a reusable overlap helper using real matching semantics:

- host languages overlap for equal exact hosts, equal one-label wildcards, or an
  exact host matched by the other's one-label wildcard;
- port languages overlap when explicit ports agree or either side omits a port;
- path languages overlap per the existing `*` glob language — an exact
  intersection (DP or NFA), **not** a string-prefix approximation;
- on a shared witness request, compare the real priority tuple (host tier, port
  specificity, literal path-prefix length) and reject when the proposed tuple is
  better **or equal**.

Equal priority is rejected deliberately: today's append order usually leaves the
existing service first, but proposal safety must not depend on a later
serialization or reorder preserving declaration order.

**Proposal-only.** A vault admin may still author an intentional overlapping
unfiltered exception through YAML or direct upsert. Do **not** change
`MatchScore` so that any overlapping filtered matcher always hops — that removes
deliberate admin exceptions and changes semantics for unfiltered traffic.

---

## 5. The two capabilities

Both are random opaque tokens. Production state is **shared TTL rows in the
existing database** — never a process-local map, because a sidecar callback can
land on any replica. An in-memory backend with identical semantics is permitted
only when selected explicitly for tests or single-instance development, never as
an implicit production fallback.

Rows store a token **hash**. No credential values, no raw tokens, no reversible
form of either. Audit and rate-limit attribution stay with the **initiating
actor**, not the sidecar. This write happens only on the filtered path.

Capabilities authorize the MITM **data plane only**. They are accepted only as
proxy credentials and never as bearer sessions on `/discover`, proposals,
vault administration, or any other control-plane endpoint. Their effective
vault role is always `proxy`; never persist or inherit an initiating actor's
`member`, `admin`, or instance-level authority into a capability scope.

Token prefixes, following the existing `av_sess_` / `av_agt_` convention:

- `av_cont_` — continuation
- `av_pol_` — policy capability

Distinct prefixes let ingress dispatch deterministically rather than "try a
session, fall back to a capability", and give log redaction a stable match.

### 5.1 Continuation — per invocation, single use

Bound to `{method, scheme, authority, escaped path, raw query}` plus the frozen
match. Escaped path and raw query are compared verbatim: two different wire
requests can decode to the same path, and only one of them is the request the
filter saw.

The sidecar opens a **new** request to that exact target with
`Proxy-Authorization` set to the continuation token, against
`X-Agent-Vault-Continuation-Proxy`. Agent Vault verifies, consumes, **skips this
service's filter**, resolves the frozen match, injects **those** destination
credentials, and forwards whatever body the sidecar sent.

A continuation cannot retarget the host. Retargeting (GitLab → GitHub) is the
policy capability's job, against a **different unfiltered** service.

Both admission claim and exact-request consume must occur before `expires_at`.
Claiming at second 29 does not pin an unused continuation indefinitely. Once
consumed, ordinary origin body / first-header / WebSocket idle budgets apply;
the 30-second deadline does **not** kill the established stream.

### 5.2 Three-state lifecycle

`issued → claimed → consumed`:

1. **`issued → claimed`** — the first admission through either ingress, after
   source-authority and bound-authority validation:
   - CONNECT: before hijack, leaf mint, or tunnel setup, so a real HTTP status
     can still be written;
   - absolute-form HTTP: before processing that same request.
2. A second admission — including a second CONNECT to the *correct* authority —
   fails, because the row is no longer `issued`.
3. **`claimed → consumed`** — the exact bound request, while the row is still
   unexpired. Resolve is permitted only after this transition succeeds.

Without the authority check, a stolen continuation admits a tunnel to any host
and Agent Vault mints a leaf certificate before the method/path bind is ever
compared: a cert-minting and tunnel-resource oracle, even though the inner
request still fails before an origin dial or credential attachment. Without the
*claim*, the authority check alone still admits unboundedly many concurrent
tunnels to the correct authority.

**Burn on mismatch.** A wrong authority at admission, or a wrong
method/scheme/authority/escaped-path/raw-query at consume, transitions the row
to `consumed` and **commits** that transition. The holder already has enough
authority to spend the correct request, so leaving a mismatched bearer reusable
buys nothing, while burning turns a mistargeted use into one visible failure
instead of a live token for the rest of its TTL.

**Transactional revalidation.** Source-session existence and expiry, actor
identity and status, and the source-vault grant are revalidated in the **same
transaction** as pair issuance and each state transition. Checking separately
leaves a window where the session is revoked between check and mint/spend.

The conditional `UPDATE ... WHERE state = ?` plus `RowsAffected == 1` is the
atomic mechanism on SQLite. `SELECT ... FOR UPDATE` is additional PostgreSQL
locking, **not** the basis of SQLite correctness — say so in the store code,
because a reader will otherwise assume the locking is doing the work.

### 5.3 Policy capability — optional, reusable in window

Exists only when `policy_vault` is set. Scoped to that vault's immutable id
(retain its name only for display/audit). Used for side-channel calls and for
self-completing on a **different unfiltered** service. Vault deletion invalidates
the row; a rename does not retarget it.

It **cannot**: spend the originating continuation's destination credential;
invoke **any** filtered service, originating or otherwise; or outlive 30s.

**Strict, configured-service-only matching.** A policy capability never reads or
honors `unmatched_host_policy`. That setting defaults to `passthrough`, so
without this rule a stolen policy token is a 30-second **open forward proxy**
attributed to the initiating actor.

- no configured match → fail closed;
- disabled match → fail closed;
- filtered match → fail closed (no recursion, no second capability mint);
- unfiltered configured match, **including an explicitly configured passthrough
  service** → proceed normally.

Do not implement this as "call ordinary Match and reject a `Passthrough`
result" if ordinary Match has already consulted the vault setting. Keep the
strict mode separable enough that a test can assert the setting store was never
read.

**Policy CONNECT eligibility.** A CONNECT authenticated by a policy capability
is gated pre-hijack: the target host and port must be covered by at least one
enabled, unfiltered configured service in the policy vault. Path is checked by
strict matching on each inner request. Without this the policy token is the same
tunnel-admission and leaf-minting oracle described in §5.2 — the inner-request
rule protects the origin but does not gate tunnel setup.

Layout A residual: a stolen policy capability can still reach other *unfiltered*
services in the source vault for up to 30 seconds. Document it. Layout B removes
it.

### 5.4 Revocation

Thirty seconds is a **maximum lifetime, not a post-revocation grace period.**

The row records source session and agent identity. Agent Vault re-checks that
the source authority is active and still authorized for the source vault: when
authenticating a policy-capability request, when consuming a continuation, and
on **each** new request through a persistent CONNECT tunnel — not only at tunnel
setup. Revocation, expiry, or removal → fail closed. A revoked capability cannot
be revived by opening a new CONNECT. Observing a revoked or expired source
**burns** the policy capability, so re-granting the actor cannot revive it within
the original TTL.

**Rationale, corrected.** This is *stricter* than the unfiltered path, not the
same as it. `handleConnect` resolves the session once and captures the scope for
the tunnel's life, so ordinary `agent revoke` takes effect on the next CONNECT,
not on each request inside an established tunnel. Capabilities get the stronger
guarantee because a shared row already exists and can be revalidated cheaply. Do
not widen ordinary CONNECT revocation in this change.

### 5.5 Source identity

Persist the **sessions-table hash** — never the raw token, and never
`Session.ID` as returned by `GetSession`, which overwrites that field with the
raw token and so makes the wrong thing look like the obvious thing. Provide an
explicit lookup by stored hash. `ProxyScope` may carry only the hash.

A source-session foreign key with `ON DELETE CASCADE` is useful defense in
depth; runtime expiry, status, and grant checks remain required.

### 5.6 Frozen match

A shared store cannot hold an in-process pointer, so the match travels as data:
a **versioned, non-secret projection** of the matched service from which Agent
Vault reconstructs an immutable match at consume time. It **must not** re-run
service matching against current mutable config.

Contents — everything Resolve needs and nothing used only to decide whether to
*enter* the filter:

| Field | Notes |
|---|---|
| Envelope format version | Read and validated **first**, before the payload is decoded |
| Source vault id | |
| Initiating actor + session hash and agent id | Audit and revocation |
| Kind, token hash, expiry, issued/claimed/consumed | The FSM |
| Exact request bind | method, scheme, authority, escaped path, raw query |
| Canonical matched service | name, host, path, port |
| Complete non-secret auth shape | `type`, header name, prefix, and the whole `custom.headers` template map — credential references stay key names |
| Complete substitution shape | each `key`, `placeholder`, and `in` surfaces |
| Policy-vault scope | when kind is policy |

**`Filter` is excluded** — a continuation must never re-enter the hop.

Decode in two stages: validate the envelope version, then decode that version's
typed payload. Unknown version, unknown required semantics, malformed or
incomplete data, credential-key disagreement, or invalid service config all fail
closed **before** any credential-store read. Bump the version whenever a field
that affects injection is added; `encoding/json` drops unknown fields silently,
so a mixed-version pair would otherwise resolve a subtly different request.

Operator-authored `custom.headers` templates are arbitrary text and may contain
literals, exactly as they already may in `broker_config.services_json`. The row
is not a secret store, but do not claim the database can prove such literals are
non-secret. Never persist credential *values*.

| Admin change during the window | Continuation |
|---|---|
| Host / path / name / auth **key** / substitutions | **Frozen** — cannot retarget the slot |
| Credential **value** (`vault credential set KEY=…`) | **Not frozen** — Resolve uses the current value for the frozen key |
| Filter block | Irrelevant — continuation does not re-enter the filter |
| Key deleted from the vault | Fail closed, no origin |

### 5.7 Capability pairs are one invocation

Resolve the policy-vault scope first, then insert both rows in **one
transaction**. A partial pair must never become visible.

If the sidecar is unreachable, times out, rejects without using the
continuation, fails its WebSocket upgrade, or the filtered stream ends, retire
every still-live capability for that invocation immediately, by hash or row id.
Cleanup is best-effort defense in depth — expiry and validation remain
mandatory — and a scheduled sweeper removes anything cleanup misses.

The sidecar contract is **synchronous**: returning its final response means the
decision is complete. It may not retain a policy capability for asynchronous
work afterwards.

### 5.8 Rate limits and request logs

The initiating filtered request is charged once under the initiating actor and
source vault. Its single-use continuation is the completion of that same
logical request and is **not charged a second time**. Policy-capability calls are
new outbound requests and are rate-limited normally under the initiating actor
and policy vault. Reusable policy authority must not become a 30-second
rate-limit bypass.

Logging follows the same distinction:

- the initial filter-hop row records matched service identity but no credential
  keys, because no credential was resolved;
- the continuation origin row is attributed to the initiator and records the
  frozen service/key names that were actually resolved, while correlating to
  the filter invocation;
- policy calls are attributed to the initiator in the policy vault and record
  their own matched service/key names;
- raw session/capability tokens and credential values never enter logs, spans,
  metrics labels, or error text.

---

## 6. Enforcement is mandatory, and errors fail closed

Match, frozen-match resolution, capability claim/consume/validate,
source-authority revalidation, strict policy matching, and policy-vault lookup
are **required interface members**. Never guard them with an optional type
assertion that means "skip the check when absent" — a security control behind an
optional assertion is not a control. Test doubles must implement the same
security surface as production stores, or the control is unreachable in the
test suite that is supposed to prove it.

Any error from Match, capability persistence, source revalidation, snapshot
decode, or policy-vault resolution **fails closed**. In particular, a `Match`
error must never fall through to ordinary Inject, and a continuation must never
fall back to a live re-match if frozen resolution is unavailable.

A service configured with a filter, on a proxy with no filter engine or no
shared capability store, returns `502 filter_misconfigured`. "Cannot run the
policy" must never resolve to "skip the policy".

---

## 7. Skip / deny on the way back

- **Continuation** (valid, exact bind, frozen match): skip **this** service's
  filter, Resolve the frozen match, forward.
- **Policy capability** matching **any** filtered service: fail closed. Do not
  recurse, do not inject.
- Anything else on a filtered service: hop to the sidecar as usual.

---

## 8. The reverse-proxy hop

Treat `filter.url` as an **origin**. Preserve method, path, query, streaming
body, and the original `Host`. Overwrite — never trust client copies of — hop
headers. **Secrets are not in URLs.**

| Header | Purpose |
|---|---|
| `X-Agent-Vault-Original-URL` | Exact original destination URL |
| `X-Agent-Vault-Continuation-Proxy` | Reachable MITM proxy **base URL**, no credentials |
| `X-Agent-Vault-Continuation-Token` | 30s single-use continuation bearer |
| `X-Agent-Vault-Policy-Proxy` | Optional policy proxy base URL, no credentials |
| `X-Agent-Vault-Policy-Token` | Optional 30s policy bearer |
| `X-Agent-Vault-CA` | Agent Vault MITM root, base64 — a sidecar is not `vault run` |
| `X-Agent-Vault-Service` | Matched service name |

The sidecar sends the matching token as `Proxy-Authorization` when using that
proxy URL. Tokens must not be logged or persisted.

**Ordering is strip-then-set.** Strip untrusted headers, then set trusted ones,
on the hop. On the sidecar's response, strip its reserved namespace **first**
and only then set Agent Vault's own `X-Agent-Vault-Proxy-Error` envelope — or
the rule eats its own header. The namespace is stripped again from continuation
requests before origin: that request is assembled by a sidecar that was just
handed capability headers.

### 8.1 Destination credential header slots

Before sending to `filter.url`, derive the header names the frozen service
*would* overwrite during Resolve — computable with **no credential read**:

- bearer / basic → `Authorization`
- api-key → the configured `header`, or `Authorization` by default
- custom → every configured output header name
- passthrough → none

Delete exactly those client-supplied headers, along with `Proxy-Authorization`,
`X-Vault`, hop-by-hop headers, and the reserved `X-Agent-Vault-*` namespace.

**Do not unconditionally strip `Authorization`.** When the service authenticates
through a different slot, `Authorization` is ordinary application data that the
continuation must preserve and deliver to the origin. Stripping it blindly both
loses that data *and* leaks the slot that actually matters.

Continuation resolution still writes each injected header with `Set`, not `Add`,
so injected values win over client-supplied duplicates.

### 8.2 WebSocket

Reverse-proxy the upgrade and byte stream to the sidecar, preserving `Upgrade` /
`Connection` on **this** hop. The sidecar either rejects, or opens a new
WebSocket via the exact continuation and bridges. Agent Vault consumes the
exact upgrade request **before** Resolve and the origin dial; the origin's 101
response is not a prerequisite for consumption. After a successful origin
upgrade, the existing 10-minute WS idle budget governs the bridge. Unfiltered
services keep today's direct origin WS path.

### 8.3 Dial policy

A dedicated transport, which does **not** consult
`AGENT_VAULT_ALLOW_PRIVATE_RANGES` — where an origin may live has no bearing on
where a policy sidecar may live.

- `https`: normal TLS verification; public allowed; metadata endpoints blocked.
- `http` to a **literal loopback IP**: allowed. A *name* that resolves to
  loopback (`localhost`) is not — resolution is not part of the config.
- `http` to anything else: requires `allow_insecure_private_http: true`, and
  then **every resolved address** must be loopback or RFC-1918 (or the IPv6
  equivalents); dial the validated IP so a rebind cannot slip between check and
  connect; public, link-local, CGN, and metadata addresses stay blocked.

**Redirects are not followed.** Implement the property, do not merely assert it:
`http.Transport.RoundTrip` (and `httputil.ReverseProxy` over it) does not follow
redirects, which satisfies the requirement; an `http.Client` must set
`CheckRedirect` to return `http.ErrUseLastResponse`. State in the code which
mechanism provides it.

### 8.4 Failure

| Failure | Response |
|---|---|
| Dial, TLS, reset, capability mint or store failure | `502` `filter_unreachable` (or `filter_misconfigured` for state/config) |
| No response headers before the budget expires | `504` `filter_timeout` |

Envelope: `Content-Type: application/json`, `{"error":"<code>","message":"..."}`,
`X-Agent-Vault-Proxy-Error: true`. None of these resolves a credential or
reaches the origin.

**Success:** copy status, headers (minus hop-by-hop, reserved broker headers,
the reserved namespace, and `Set-Cookie` under the existing proxy response
policy) and body to the client, at whatever status the sidecar chose. Agent
Vault does not map "deny" to a fixed 403. Bodies stream; a filter that consumes
a non-replayable body must buffer before claiming the continuation.

Request-log rows for a filter hop carry the matched service identity and **no**
credential keys — no credential was resolved, and the log should say so by
omission.

---

## 9. Layouts

Sidecar listens on `:12345`. It is not a vault object and not an agent. Policy
lives in the sidecar. clone/fetch (`git-upload-pack`) never match the push row;
the protection API is a **different, unfiltered** service. The operator never
types agent names, tokens, or `--filter-*` flags.

### Layout A — same vault (explicit opt-in)

```yaml
# dev-services.yaml
services:
  - name: github-api
    host: api.github.com
    auth: {type: bearer, token: GITHUB_TOKEN}

  - name: github-push
    host: github.com/*/git-receive-pack
    auth: {type: bearer, token: GITHUB_TOKEN}
    filter:
      url: http://127.0.0.1:12345
      policy_vault: dev
```

| Who | Request | What happens |
|---|---|---|
| coding agent | `POST https://github.com/acme/app.git/git-receive-pack` | match, **no PAT decrypt**, hop to sidecar |
| sidecar, policy cap | `GET https://api.github.com/repos/…/protection` | unfiltered → inject `GITHUB_TOKEN` |
| sidecar, allowed | new receive-pack via **continuation** | consume, Resolve frozen match, inject, GitHub |
| sidecar, protected | 403 (or any status) on the client hop | no dest decrypt, no origin |
| stolen policy cap → `git-receive-pack` | filtered service | **fail closed** |
| stolen policy cap → other unfiltered write service in `dev` | 30s residual | document; prefer Layout B |

A Compose sidecar would use `url: http://filter:12345` plus
`allow_insecure_private_http: true`.

### Layout B — split vault

`policy_vault: policy`, holding only the read API, unfiltered. The configuring
admin must be admin of **both** vaults. A stolen policy capability cannot attach
the write PAT. Retargeting (GitLab → GitHub) uses the policy capability against
an unfiltered GitHub write service in `policy_vault`.

---

## 10. Implementation seam

- `broker.Service`: `Filter {url, policy_vault, allow_insecure_private_http}`;
  validation per §2.1; no `agent_id`; a presence tri-state so `filter: null`
  survives the CLI → API hop.
- `proposal`: preserve `filter`; reject an explicit `filter` key; reject delete
  of a filtered service; reject shadowing matchers at create and apply (§4).
- `brokercore`: **Match** vs **Resolve** as required interface members; frozen
  match freeze/thaw with a version envelope; no dest decrypt on the filter path.
- `store`: capability table with constraints on kind and state, indexes on token
  hash, expiry, and source-session hash; the three-state FSM; transactional pair
  minting; invocation correlation/retirement; scheduled sweep following the
  existing ticker-until-context-cancel pattern.
- `mitm`: reverse-proxy to `filter.url`; admission-time claim on both ingress
  shapes; token-vs-proxy-URL headers; strip-then-set both directions; dedicated
  dialer; filtered WS reverse-proxy plus continuation bridge; capability tokens
  accepted on the data plane only.
- `server` / `cmd`: dual-admin when `policy_vault` differs; omitted
  `policy_vault` mints nothing; `AGENT_VAULT_FILTER_PROXY_URL` validated fatally
  at startup.
- CLI: none beyond YAML parse and print.
- Docs: `docs/learn/services.mdx`, `docs/reference/cli.mdx`,
  `docs/self-hosting/environment-variables.mdx`, `.env.example`, `README.md`,
  `CLAUDE.md`, and `cmd/skill_cli.md` (filter error codes; a filter denial is
  the operator's policy and is relayed, not worked around).

---

## 11. Test matrix

### Blocking behaviours

1. Proposal adding an unfiltered exact/longer-path matcher over a filtered
   wildcard/path matcher: rejected at create; rejected with 409 and no mutation
   when introduced between create and apply. Include disjoint host/path/port
   cases proving the overlap helper does not reject harmless services. Admin
   YAML writing the same exception is **allowed**.
2. Policy capability + unmatched host + vault `unmatched_host_policy=passthrough`
   → denied, origin never contacted, and the unmatched-policy store method
   **was never called**.
3. Policy CONNECT to an authority with no eligible unfiltered configured service
   → rejected before hijack and leaf mint. A path mismatch after an otherwise
   eligible CONNECT also fails closed.

### Capability lifecycle and revocation

4. N concurrent claims on **real SQLite**: exactly one `issued → claimed`. N
   concurrent consumes: exactly one `claimed → consumed`.
5. Wrong CONNECT authority burns the continuation before hijack; a wrong inner
   bind also burns it; a subsequent correct attempt fails.
   Claim immediately before expiry and consume after expiry: reject and retire;
   no credential read or origin contact.
6. Agent revoke, session revoke and expiry, user deactivation, and source-vault
   grant removal each reject both capability kinds, including on requests inside
   an existing CONNECT. Re-granting does not revive a capability observed
   revoked.
7. Inspect the real database: no column equals any live raw source-session,
   continuation, policy, or credential value.
8. Force failure of the second row in pair issuance → neither row visible. Fail
   or deny a hop → remaining invocation rows retired.
   Source revocation racing pair issuance cannot produce a committed usable row.

### Frozen match, interfaces, no-read invariant

9. YAML matcher and auth-key edits do not retarget; a value update of the frozen
   key **is** used; deletion fails closed. Custom auth templates and all
   substitution fields round-trip.
10. Unknown envelope version and malformed or incomplete payload fail before any
    credential read. Compile-time interface assertions for production **and**
    test stores. A `Match` error never falls through to Inject.
11. A filtered service with no filter engine or store returns
    `502 filter_misconfigured` with zero origin and zero credential reads.
12. The no-read invariant on the denied path is asserted by **counting**
    credential-store calls, not by status code.

### Headers, URLs, WebSocket, smoke

13. Client values in destination injection header slots do not reach the
    sidecar. An unrelated `Authorization` on a service using a different auth
    slot **is preserved**. A sidecar cannot spoof Agent Vault's own error header
    or set a client cookie.
14. `filter.url` with userinfo, fragment, or query is rejected; callback URL with
    userinfo, path, query, fragment, or non-loopback HTTP is rejected and is
    **fatal at startup**. Redirects are returned, not followed.
15. Full filtered WebSocket bridge: sidecar callback through the continuation,
    bidirectional frames, origin receives the injected credential, Resolve runs
    exactly once. An origin rejection after consume cannot make the continuation
    reusable. A denied sidecar upgrade yields zero Resolve. Unfiltered WS
    unchanged.
16. Dial policy: loopback HTTP allowed, RFC-1918 HTTP requires the flag, public
    HTTP denied, metadata and link-local blocked, and
    `AGENT_VAULT_ALLOW_PRIVATE_RANGES` has no effect on any of it.
17. `TestSmoke_FilterLayoutA` uses `store.Open` with **real SQLite** — not a mock
    — and asserts both directions: denial reaches neither origin nor credential;
    allow reaches the origin carrying the injected destination credential. No
    filter-agent row exists.
18. Omitted `policy_vault` mints no policy headers and no policy row.
19. Capability prefixes presented as Bearer credentials to control-plane
    endpoints are rejected. A capability scope is always proxy-only.
20. One filtered request plus its continuation consumes one proxy rate-limit
    unit; policy calls consume their own units. Request logs have initiator,
    vault, service, and key-name attribution as specified in §5.8, with no raw
    tokens or credential values.
21. Escaped path and raw query are preserved on the sidecar hop and compared
    byte-for-byte on continuation, including encoded slashes and repeated query
    keys.

---

## 12. Out of scope

- Changing global matcher semantics so any overlapping filtered matcher always
  hops. §4 is proposal-only, deliberately.
- Widening revocation to ordinary established unfiltered CONNECT tunnels.
- Rewriting the frozen projection as raw `broker.Service` JSON, or including
  `Filter` in it.
- A TTL flag or env override. 30s stays a named constant unless a real sidecar
  misses the window.
- RFC 9457, filter-agents, in-process plugins, nested filter hops.
- Hiding filtered *services* from `/discover` — hiding the filter *block* and
  capability material is the requirement.
- Relitigating Match/Resolve, "no filter-agents", "omitted `policy_vault` = no
  capability", or Layout A same-vault mode.

---

## 13. Known-unverified

PostgreSQL. All three round-1 implementations shipped dual-dialect SQL that has
only ever executed on SQLite; no branch has a PG harness. Keep PostgreSQL SQL
parameterized through the dialect and provide an opt-in live integration test
gated on a test DSN. Until that runs in CI, state plainly in the PR that the
PostgreSQL path is compile- and review-checked but the filter-capability path is
executed only on SQLite. Do not let it read as tested.

---

## 14. Locked decisions

1. Reverse-proxy to the sidecar — not a chained forward-proxy, not in-process.
2. Per matched service only.
3. Match without destination decrypt; Resolve only after a consumed continuation
   or on the unfiltered path. Frozen match in the continuation.
4. **No filter-agent.** Optional 30s policy capability plus a single-use
   continuation.
5. Continuation binds exact method / scheme / authority / escaped path / raw
   query; both claim and consume occur before the 30s expiry; the consumed stream
   then runs on origin budgets; body comes from the sidecar; it cannot retarget
   the host.
6. `policy_vault` omitted = **no** policy capability. Source vault name = Layout
   A, written explicitly. Another vault = Layout B plus dual-admin.
7. A policy capability cannot spend the originating destination credential and
   cannot invoke **any** filtered service. Capabilities are data-plane-only,
   proxy-role authority. Audit as the initiator.
8. Fail closed on hop or capability failure: 502/504 with the existing JSON
   envelope.
9. Reserved headers as listed in §8, per-kind token prefixes (`av_cont_`,
   `av_pol_`), strip-then-set in both directions, tokens never in URLs.
10. `filter.url` and `AGENT_VAULT_FILTER_PROXY_URL` validated per §2.1 and §2.2;
    an invalid callback URL is **fatal at startup**; dedicated dialer per §8.3;
    redirects implemented as not-followed.
11. Filtered WebSocket upgrades hop to the sidecar; the exact continuation
    upgrade request is consumed before Resolve/origin dial and is not restored
    if the origin rejects the upgrade.
12. Hidden from `/discover` and the skill. Proposals cannot set, clear, or
    delete filters or filtered services, and an explicit `filter` key is
    rejected rather than ignored. `enabled: false` remains allowed.
13. Preserve on `service add` omit; wipe on `set`/`clear`. List prints `filter`.
14. YAML only, following the substitutions precedent.
15. Capabilities are shared DB TTL rows: token hash, three-state FSM with atomic
    conditional updates, versioned frozen projection, source session hash.
    Process-local storage is dev/single-instance only and never an implicit
    production fallback. No capability write on the unfiltered path.
16. Source revocation, expiry, or removal invalidates issued capabilities
    immediately — re-checked on policy auth, continuation consume, and every
    request inside a persistent CONNECT tunnel. Stricter than the unfiltered
    path by design (§5.4).
17. The frozen projection carries matcher identity and complete non-secret auth
    and substitution shape, never credential values, and excludes `Filter`. Do
    not re-run the matcher. Resolve current values for frozen key names. Unknown
    version fails closed before any credential read.
18. No RFC 9457 in this change.
19. Proposals may not introduce a matcher that wins **or ties** an existing
    filtered service, checked at create and apply with exact matcher-language
    overlap (§4). Proposal-only; admin YAML may author exceptions.
20. Policy capabilities match configured, enabled, unfiltered services only and
    never consult `unmatched_host_policy`; CONNECT has a pre-hijack authority
    eligibility gate (§5.3).
21. Continuations are claimed at admission against the bound authority, before
    hijack; consume requires state `claimed`; mismatches burn the row; source
    authority is revalidated inside the same transaction (§5.2).
22. Capability rows store the session token **hash**, never the raw token (§5.5).
23. Security enforcement is mandatory by interface, and every error on the
    filter path fails closed. No optional type assertions, no implicit in-memory
    production fallback, no fall-through to Inject (§6).
24. Destination credential header slots — derived from the frozen auth
    configuration without reading values — are removed before the sidecar.
    `Authorization` is **not** stripped unconditionally (§8.1).
25. A continuation and its optional policy capability are minted in one
    transaction and retired together; the sidecar contract is synchronous (§5.7).
26. Filtered ingress is rate-limited once, continuation does not double-charge,
    and every policy request is charged; logs retain initiator/service/key-name
    attribution without raw tokens or values (§5.8).
