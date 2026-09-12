# Per-service request filters — final plan

Complete implementation contract for Infisical/agent-vault#407. This file **replaces** `service-filters.plan.md` plus the three `service-filters-round2.plan.md` supplements. Phase 3 implements this document from a clean branch.

Provenance: Cursor/Codex hybrid plan; Claude’s six findings; three independent hops (`issue-407-cursor` @ `a79e069`, `issue-407-codex` @ `a0dd71b`, `issue-407-claude` @ `8cb1897`); three round-2 supplements. Resolution of the supplements is recorded in `cursor-phase2-review.md`.

Local working spec. Do not include `ad_hoc/` in the pull request. After merge, operator-facing behavior belongs in Mintlify (`docs/learn/services.mdx`, CLI reference), not this file.

---

## Problem

The broker matcher is host/path/port plus credential injection. Some policies need **arbitrary logic** on the request (inspect a git-receive-pack body, call a protection API, retarget GitLab → GitHub, rewrite an OpenAI model) **before** destination secrets are attached.

That logic must not live in Agent Vault. The OSS seam is: match → hop to sidecar → sidecar decides.

Motivating example (not the only consumer): `git push` over HTTPS. Sidecar parses the target ref, asks whether the branch is protected, returns 403 or lets the push proceed with credentials attached.

---

## Non-goals (v1)

- In-process plugins, WASM, Go `.so`, or a new rules language.
- Filter as a chained HTTP forward-proxy (absolute-form / CONNECT **to the sidecar**). v1 is **reverse-proxy to `filter.url`**. Continuation/policy callbacks **to Agent Vault** use the existing MITM forward-proxy (including CONNECT).
- Durable filter-agents, recoverable long-lived filter tokens, `kind` on agents, reserved `filter-` names.
- Per-request DB writes on the **unfiltered** Inject path.
- RFC 9457 Problem Details (existing `{error, message}` + `X-Agent-Vault-Proxy-Error`).
- `/discover`, agent skill, dashboard UI (unless a reviewer blocks without it), `--filter-*` flags, `vault service filter` subcommands.
- Binding the continuation to request-body bytes (packfiles must stream).
- Structural “any overlapping filtered matcher always hops.”
- Killing ordinary (unfiltered) CONNECT tunnels on `agent revoke`.
- A TTL flag or env override. 30s is a named constant.
- Hiding filtered *services* from `/discover`; hiding the `filter` *block* is enough.
- In-process WebSocket origin bridge (the sidecar callbacks via continuation).

---

## Placement in the existing pipeline

Today (simplified):

authenticate → rate limit → **Inject (match + decrypt creds)** → substitutions → origin (or WebSocket dial).

**Unfiltered** services: unchanged, including WebSocket to origin. **No** capability-table write.

**Filtered** match:

authenticate → rate limit → **Match (no dest decrypt)** → reverse-proxy to `filter.url` → sidecar’s response is the client’s response.

`CredentialProvider` splits **Match** from **Resolve**. Both are **required** interface members, not optional assertions. A `CredentialMatch` holds service metadata and a private handle, **no decrypted destination secret**. `Resolve` / `InjectFrozen` runs only after a continuation is **consumed** against that frozen match, or immediately on the unfiltered path.

**Invariant:** denied, timeout, unreachable, or misconfigured filter → **zero** reads/decryptions of the destination credential.

A `Match` error, a missing filter engine, or a capability mint/store failure on a service that **has** a `filter` block is `502 filter_misconfigured` — never “skip the filter” / fall through to Inject.

Disabled service / no match on the **ordinary** path: unchanged. Do not call the filter.

---

## Config (operator)

On `broker.Service`, optional block. YAML-only, same precedent as substitutions.

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
| `url` | yes if `filter` present | Sidecar origin. Absolute `http` or `https`, host required, **no userinfo, fragment, or configured query/`ForceQuery`**. Path prefix is allowed (joined with the original request path). `https` is the default expectation. Literal-loopback `http` is allowed without a flag. Non-loopback `http` requires `allow_insecure_private_http: true`. |
| `policy_vault` | no | Vault the **policy capability** is scoped to. **Omitted = no policy capability**. Set to the **source vault name** for Layout A. Set to a **different** vault for Layout B. |
| `allow_insecure_private_http` | no | Explicit opt-in for cleartext to a loopback or RFC1918 sidecar (`http://filter:12345`). Weaker than TLS; document it as such. |

`policy_vault` modes:

| Value | Policy capability | Use |
|---|---|---|
| omitted | none | Body/header-only decision. |
| source vault name | 30s cap on the source vault | Layout A: logic in front of the same creds. Must be written explicitly. |
| different vault name | 30s cap on that vault | Layout B. Configuring actor must be **vault admin of both**. |

Agent Vault does **not** constrain which *unfiltered* services live in the policy vault. Policy cap **cannot** invoke any **filtered** service (including the originator). Dual-admin only when the named vault differs from the source.

No `agent_id`. Nothing is minted into the agents table.

Clear on upsert: `filter: null` on **`vault service add`**. CLI YAML→JSON must preserve `filter: null` (`FilterOp` omit/set/clear).

Compose sidecar example:

```yaml
filter:
  url: http://filter:12345
  policy_vault: dev
  allow_insecure_private_http: true
```

Remote sidecars that must call back through Agent Vault also need **`AGENT_VAULT_FILTER_PROXY_URL`**: an advertised MITM **base URL** (no userinfo, path, query, fragment). `https`, or `http` only to a literal loopback IP. Validated at **startup**. An invalid explicit value **fails startup** — do not warn-and-advertise loopback, do not advertise the raw string. Local sidecars with no env set use the process’s loopback MITM listener.

Document in `.env.example` and the env-var tables.

---

## Who writes what (merge)

| Write | `filter` |
|---|---|
| Agent proposal that sets/clears `filter` (object or `null`) | **Reject** 400. |
| Agent proposal that **deletes** a filtered service | **Reject** at create and apply. |
| Agent proposal whose effective `set` matcher equals or can win over an existing **filtered** matcher | **Reject** at create (400) and re-check at apply (409). See lock 19. |
| Agent proposal that updates auth/host of a filtered service **and keeps that service’s filter** | **Preserve** `filter`. |
| Agent proposal `enabled: false` on a filtered service | **Allow.** Fail-closed DoS (`ErrServiceDisabled`), not a bypass. Document why delete is rejected and disable is not. |
| `vault service add` / POST upsert, field omitted | **Preserve.** |
| `vault service add` with `filter:` / `filter: null` | Set or clear. |
| `vault credential set` | Does not touch services. |
| `vault service set` (replace list) / `clear` | **Not preserved.** Document this. List output includes `filter` so round-trip is safe. |
| Interactive `service set` “Replace all” | Same as `set` (wipe). No wizard prompts for filter in v1. |
| Admin delete service | Allowed (explicit policy removal). |
| Admin YAML / upsert of an overlapping **unfiltered** exception | **Allowed.** Exceptions are an admin act. |

Admin `vault service list` **must include** `url`, `policy_vault`, and `allow_insecure_private_http` when set. Never include capability material. Still omitted from `/discover`.

---

## Two capabilities (not the inbound agent token, not a filter-agent)

Do **not** forward the inbound `Proxy-Authorization` / agent session to the sidecar. Do **not** create an agent row.

Both capabilities: random opaque tokens with **distinct prefixes** — `av_cont_` continuation, `av_pol_` policy. **Production:** shared TTL rows in the existing database. **No credential values, no raw tokens, no reversible token material.** Prefix dispatch never tries a capability as a session or vice versa.

**Development:** a process-local map with **identical semantics** is allowed only as an **explicit** single-instance/test backend. It is not an implicit production fallback.

Audit and rate-limit attribution stay the **initiating actor** recorded on the capability row, not the sidecar. Request-log rows for a filter hop carry the matched service identity and **no** credential keys.

This write happens only on the **filtered** path. Unfiltered Inject must not touch the capability table, so a filter-path outage cannot degrade ordinary proxying.

### Invocation pair

Mint the continuation and the optional policy capability as **one logical invocation**. Resolve the policy-vault scope first, then insert both rows in **one transaction**. A partial pair must never become visible.

If the sidecar cannot be reached, times out, returns without consuming the continuation, fails its WebSocket upgrade, or the client-side filtered stream ends, **retire every still-live capability for that invocation** immediately (best-effort; expiry and revalidation remain mandatory). Operate by hashes/row IDs. A scheduled sweeper (existing ticker-until-ctx-cancelled pattern) removes rows cleanup misses. Correctness never depends on the sweeper.

The sidecar contract is **synchronous**: its final HTTP response (or WS close of the client hop) means the decision is complete. It may not retain a policy capability for asynchronous work after that response.

### 1. Continuation (per invocation, single-use)

Bound to `{method, scheme, authority, escaped path, query}` plus the **frozen match** (inbound vault, original actor for logs). Claim TTL **30 seconds**.

Three-state machine: **`issued → claimed → consumed`**.

| Transition | When | Checks |
|---|---|---|
| `issued → claimed` | First admission on **either** ingress: CONNECT **before hijack / leaf mint / dial**, or absolute-form forward-proxy **before** handling that request | Token live; source authority live; presented authority == bound authority |
| `claimed → consumed` | The exact bound HTTP/WebSocket request | Exact method/scheme/authority/escaped-path/query; source still live; snapshot usable |
| any mismatch | Wrong authority at admission, or wrong bind at consume | Row moves to `consumed` and the burn is **committed** |

A second admission (including a second CONNECT to the **correct** authority) fails — the row is no longer `issued`. Resolve / dest decrypt is permitted **only** after a successful `claimed → consumed`.

Sidecar opens a **new** MITM request to that exact target with `Proxy-Authorization` = continuation token against `X-Agent-Vault-Continuation-Proxy`. Agent Vault verifies, consumes, **skips this service’s filter**, Resolves the **frozen** match, injects **those** destination credentials, forwards whatever body the sidecar sent.

Cannot retarget host (GitLab → GitHub). That path is the policy capability against a **different unfiltered** service in `policy_vault`.

Conditional `UPDATE … WHERE state = ?` plus `RowsAffected == 1` is the atomic mechanism on SQLite (`SELECT … FOR UPDATE` is a no-op there). If a `FOR UPDATE` clause is emitted for Postgres, comment that SQLite relies on the conditional update.

Once consumed, origin body / first-header / WebSocket idle budgets apply. The 30s deadline does **not** kill an established stream.

### 2. Policy capability (only if `policy_vault` is set; 30s, reusable in-window)

Scoped to the named vault. Sidecar uses it for **side-channel** calls and for **self-complete on a different unfiltered service**.

**Strict matching — never consult `unmatched_host_policy`:**

- no configured match → fail closed;
- disabled match → fail closed;
- filtered match → fail closed (no recursion, no dest inject);
- unfiltered configured match, including an explicitly configured passthrough **service** → ordinary Inject.

Implement this as a **separate** strict Match mode. Do not call ordinary Match and then reject `Passthrough` after the setting was read. Tests must prove the unmatched-policy store method was **never called**.

**Policy CONNECT** (pre-hijack): the CONNECT `host:port` must be covered by at least one enabled, **unfiltered** configured service in the policy vault. Path is checked by strict matching on each inner request. This closes the leaf-minting oracle on unmatched names.

It **cannot**:

- spend the originating continuation’s destination credential;
- invoke **any** filtered service;
- outlive 30s;
- be used after the invocation is retired.

It **can** use **unfiltered** services in that vault. Stolen same-vault policy cap can still hit other unfiltered write services **until the hop ends or 30s**, whichever is first. Layout B (read-only policy vault) removes the residual.

On every inner request of a policy CONNECT tunnel, revalidate source authority. Observing a revoked/expired source **burns** that policy capability so a re-grant cannot revive it during the original TTL.

### 3. Revocation (source authority, not capability TTL)

Thirty seconds is a **maximum** lifetime, not a permitted window after the inbound actor is revoked.

The capability row records **source session hash and/or agent identity** plus actor and vault scope.

Re-check that this source authority is still **active** and **authorized for the source vault**, **inside the same transaction** as each state transition / policy validate:

- session row still present for the stored hash;
- `!sess.IsExpired(now)` (picks up user-session sliding idle);
- agent/user still active;
- `GetVaultRole(actorID, sourceVaultID) != ""`.

`store.GetSession` takes a raw token and sets `sess.ID = rawToken` on the way out. Persist **`sessions.id` (the hash)**, never that returned `ID`. `ProxyScope` may carry the hash only. Lookup is `GetSessionByTokenHash` / `GetSessionByHash` — a **required** store method, not an optional assertion. Missing row, expired row, or missing method → fail closed.

A source-session FK with `ON DELETE CASCADE` is useful defense in depth. Runtime expiry/status/grant checks remain required.

**This is stricter than ordinary `agent revoke`.** Unfiltered CONNECT captures `scope` for the tunnel life; revoke takes effect on the **next** CONNECT. Do not widen unfiltered CONNECT revoke in this feature. Document the discrepancy.

A revoked capability cannot be revived by opening a new CONNECT or by re-granting the actor during the original TTL (once a revoked use has been observed and burned).

### 4. Frozen-match snapshot (shared-store format)

A replica cannot store an in-process `CredentialMatch` pointer. The capability row holds a **versioned, non-secret projection** from which Agent Vault reconstructs an immutable match at consume time. It **must not** re-run service matching against current mutable YAML. It **must not** include `Filter` (continuation never re-enters the hop).

Do **not** persist raw `broker.Service` JSON as the snapshot if that would include `Filter`. A dedicated projection (Cursor `MatchSnapshot` / Codex `CredentialMatchSnapshot`) is the shape.

Decode in two stages: read and validate the envelope `format_version` **first**, then decode that version’s typed payload. Unknown version, malformed data, derived credential-key disagreement, or invalid reconstructed config → fail closed **before** any credential-store read.

Required record:

| Field | Notes |
|---|---|
| Format version | Unknown → fail closed, no dest decrypt |
| Source vault id | |
| Initiating actor + **session hash / agent id** | Audit and revocation |
| Kind, token **hash**, state, expiry, issued/claimed/consumed | Atomic transitions |
| Exact request bind | method, scheme, authority, escaped path, query |
| Canonical matched service | name, host, path, port |
| Non-secret auth + substitution shape | `auth.type`, header, prefix, entire `custom.headers` **templates**, each substitution’s key / `placeholder` / `in`. Credential **references** are key names. Never values. |
| Policy-vault scope | When kind is policy |

`custom.headers` templates are operator-written free text and **may** contain literals — same as `broker_config.services_json`. The row is not a secret store; “contains no secrets” is not an absolute the code can enforce. State that.

At continuation consume: rebuild the internal match from this snapshot, re-check source authority in the same transaction, then **Resolve those key names** against the source vault’s current credential store.

| Admin change during the 30s window | Continuation |
|---|---|
| Host / path / name / auth **key** / substitutions | **Frozen** — cannot retarget which slot is used |
| Credential **value** (`vault credential set KEY=…`) | **Not frozen** — Resolve uses the current value for the frozen key name |
| Filter block | Irrelevant — continuation does not re-enter the filter |
| Key deleted from the vault | Fail closed (missing credential), no origin |

If the credential provider cannot Resolve from a frozen snapshot (`InjectFrozen` / `RestoreCredentialMatch`+`Resolve`), fail closed. **No** fallback to live `Inject` / re-match.

---

## Skip / deny on the way back

- **Continuation** (consumed, exact URL, frozen match): skip **this** service’s filter, Resolve dest, forward.
- **Policy capability** matching **any** filtered service, or no configured unfiltered service: **fail closed**.
- Anything else on a filtered service: hop to the sidecar as usual.

---

## Reverse-proxy hop (Agent Vault → sidecar)

Treat `filter.url` as an **origin**. Preserve method, path (joined with any `filter.url` path prefix), original request query, body (stream), and original `Host`. Overwrite (never trust client copies of) hop headers. **Secrets are not in URLs.**

**Strip untrusted, then set trusted.**

Before the sidecar request, delete:

- `Proxy-Authorization`, `X-Vault`, hop-by-hop headers, all `X-Agent-Vault-*`;
- **destination injection header slots** derived from the frozen service **without reading values**:
  - bearer / basic → `Authorization`;
  - api-key → the configured header (or its default);
  - custom → every configured output header name;
  - passthrough service → none.

Do **not** unconditionally strip `Authorization` when dest auth uses a different slot; it may be ordinary application data the continuation must preserve.

Then set:

| Header | Purpose |
|---|---|
| `X-Agent-Vault-Original-URL` | Exact original destination URL |
| `X-Agent-Vault-Continuation-Proxy` | Reachable MITM proxy **base URL**, no credentials |
| `X-Agent-Vault-Continuation-Token` | 30s single-use continuation bearer (`av_cont_…`) |
| `X-Agent-Vault-Policy-Proxy` | Optional policy proxy base URL, no credentials |
| `X-Agent-Vault-Policy-Token` | Optional 30s policy bearer (`av_pol_…`) |
| `X-Agent-Vault-CA` | Agent Vault MITM root (sidecar is not `vault run`) |
| `X-Agent-Vault-Service` | Matched service name |

The sidecar sends the matching token as `Proxy-Authorization` when using that proxy URL.

On the sidecar **response**: strip the reserved namespace first, **then** set Agent Vault’s own `X-Agent-Vault-Proxy-Error` on hop-failure envelopes. Tokens must not be logged or persisted.

On the **continuation request to origin**: strip `X-Agent-Vault-*` again. Continuation resolution overwrites each injected header with `Set`, not `Add`.

**Redirects:** use `http.Transport.RoundTrip` directly (`httputil.ReverseProxy` does this) — transports do not follow redirects. If an `http.Client` is used, `CheckRedirect` must return `http.ErrUseLastResponse`. State the mechanism; do not merely claim “redirects disabled.”

**WebSocket:** reverse-proxy the upgrade and the byte stream to the sidecar (`Upgrade` / `Connection` preserved on **this** hop). Filter either rejects or opens a new WebSocket via the **exact continuation** and bridges. Continuation is consumed at successful upgrade; existing **10 min** WS idle governs the bridge. Unfiltered services keep today’s origin WS path.

**Timeouts:** origin hop budgets for TLS / first header / stream. Capability **claim** is 30s.

**Dial policy:** dedicated **per-service** transport (`allow_insecure_private_http` on that service), **not** `AGENT_VAULT_ALLOW_PRIVATE_RANGES`.

- `https`: normal TLS verify; public allowed; IMDS still blocked.
- `http` to a **literal loopback IP**: allowed.
- `http` to any other name/address: requires `allow_insecure_private_http: true`, then **every resolved dial address** must be loopback or RFC1918; public, link-local, and IMDS blocked; re-check the address on each connection.

**Hop failure** (dial, TLS, timeout, reset, capability mint/store failure): **502** (dial/TLS/reset/state) or **504** (timeout to first filter response header). Envelope: `Content-Type: application/json`, `{"error":"<code>","message":"..."}`, `X-Agent-Vault-Proxy-Error: true`. Codes: `filter_unreachable`, `filter_timeout`, `filter_misconfigured`. No dest Resolve, no origin. Retire the invocation’s leftover capabilities.

**Sidecar success path:** copy status, headers (minus hop-by-hop / reserved broker headers / `Set-Cookie` policy as today), and body to the client. Any status. Agent Vault does not map “deny” to a fixed 403.

Bodies stream. A filter that consumes a non-replayable body must buffer/spool before claiming continuation.

---

## Proposal matcher-shadow check (lock 19)

At create and apply, reject a proposed **effective** service that is unfiltered and whose matcher can win over, or **tie**, an existing filtered service for any request. The comparison uses the **effective merge**, so an update to the same service that preserves its filter is not rejected. Normalize inline host/path/port forms first.

Reusable helper, real matching semantics (not a string-prefix approximation):

- host languages overlap for equal exact hosts, equal one-label wildcards, or an exact host matched by the other one-label wildcard;
- port languages overlap when the explicit ports agree or either side omits a port;
- path languages overlap according to the existing `*` glob language (DP/NFA intersection or equivalent);
- on a shared witness request, compare the actual priority tuple: host tier, port specificity, then literal path-prefix length. Reject when the proposed tuple is **better or equal**.

Equal priority is rejected so safety does not depend on declaration order. The error names both services and matchers.

Straw-man example that **must** reject: filtered `github.com/*/git-receive-pack` vs proposed unfiltered `github.com/acme/app.git/git-receive-pack`. Also cover disjoint host/path/port patterns that **must not** reject.

Admin YAML/upsert may still write an overlapping unfiltered exception.

---

## Straw-man configuration (git push / protected branch)

Sidecar listens on `:12345`. It is **not** a vault object and **not** an agent. Policy lives in the sidecar.

clone/fetch (`git-upload-pack`) never match the push row. Protection API is `api.github.com` — a **different, unfiltered** service.

What the operator does **not** type: agent names, tokens, `--filter-*` flags.

### Layout A — same vault (explicit opt-in)

`policy_vault` **names the source vault**. Omitted would mean no side channel (cannot call `api.github.com` as the filter).

```yaml
# dev-services.yaml
services:
  - name: github-api
    host: api.github.com
    auth:
      type: bearer
      token: GITHUB_TOKEN

  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: http://127.0.0.1:12345
      policy_vault: dev
```

Loopback HTTP needs no `allow_insecure_private_http`. A compose sidecar would add `allow_insecure_private_http: true` and `url: http://filter:12345`.

| Who | Request | What happens |
|---|---|---|
| coding agent | `POST https://github.com/acme/app.git/git-receive-pack` | match, **no PAT decrypt**, hop to sidecar |
| sidecar, policy cap | `GET https://api.github.com/repos/…/protection` | unfiltered → inject `GITHUB_TOKEN` |
| sidecar, allowed | new receive-pack via **continuation** | claim/consume, Resolve frozen match, inject, GitHub |
| sidecar, protected | 403 (or any status) on the client hop | no dest decrypt, no origin; leftover caps retired |
| stolen policy cap → `git-receive-pack` | filtered service | **fail closed** |
| stolen policy cap → unmatched public host | vault passthrough default | **fail closed** (strict match; no setting read) |
| stolen policy cap → other **unfiltered** write service in `dev` | residual until hop end / 30s | document; prefer Layout B if unacceptable |

### Layout B — split vault (residual blast gone)

`policy_vault: policy`. Configuring admin must be admin of `dev` **and** `policy`. Policy vault has only the read API, unfiltered.

```yaml
# dev-services.yaml
services:
  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: http://127.0.0.1:12345
      policy_vault: policy
```

```yaml
# policy-services.yaml
services:
  - name: github-api
    host: api.github.com
    auth:
      type: bearer
      token: GITHUB_READ_TOKEN
```

Stolen policy cap cannot attach the write PAT. Allowed push is still continuation → frozen `dev` match.

Retarget (GitLab → GitHub): continuation cannot change host. Sidecar uses the policy cap against an **unfiltered** GitHub write service in `policy_vault`.

Layout A is the straw man. Layout B is the same shape with a different `policy_vault`.

`TestSmoke_FilterLayoutA` (`make test-smoke`) **must** use `store.Open` (real SQLite), the capability hop (no filter-agent row), and assert both directions: denial reaches neither origin nor credential store; allow reaches origin with the injected destination credential.

---

## Implementation seam

- `broker.Service`: `Filter` `{url, policy_vault, allow_insecure_private_http}`; `FilterOp` omit/set/clear; URL validation including no userinfo/fragment/query; no `agent_id`.
- `proposal`: reject explicit `filter`; reject filtered deletes at create and apply; reject shadowing matchers (helper above); preserve `filter` on same-name updates.
- `brokercore`: required `Match` / `Resolve` (and frozen restore); strict policy Match that never reads unmatched-host policy; `av_cont_` / `av_pol_`.
- Store: capability table (format version, token hash, kind, **state**, TTL, actor, **session hash**, vault, frozen projection, URL bind, invocation id). Constraints on kind/state; indexes on token hash, expiry, source-session hash. Atomic conditional updates. Pair insert in one tx. Optional in-memory backend only when **explicitly** selected. Scheduled sweeper.
- `mitm`: ReverseProxy (or Transport.RoundTrip) to `filter.url`; CONNECT claim pre-hijack; policy CONNECT eligibility; dest-auth slot strip; reserved-namespace strip-then-set; per-service dialer; filtered WS reverse-proxy + continuation bridge.
- `server` / `cmd/server`: dual-admin if `policy_vault` differs; omit `policy_vault` → no policy cap; validate `AGENT_VAULT_FILTER_PROXY_URL` at startup (fail on invalid).
- CLI: none beyond YAML parse/print. Docs: file-only; `set`/`clear` wipe warning; Layout A residual; private-HTTP weaker than TLS; disable vs delete asymmetry; capabilities stricter than ordinary CONNECT revoke.
- Postgres: keep dual-dialect SQL. Opt-in live PG test when a DSN is set. Until it runs in CI, the PR must say the filter-capability path is **executed on SQLite only**.

Phase 3 composition (not a product lock — a build note):

- Store / CONNECT FSM from Codex.
- Prefixes, `FilterOp`, per-service dial, ReverseProxy hop from Cursor.
- Required interfaces, session-hash API, bridged WS test, fail-closed missing engine from Claude.

---

## Locked decisions

1. Reverse-proxy to sidecar (not chained forward-proxy to the filter, not in-process).
2. Per matched service only.
3. Match without dest decrypt; Resolve only after continuation **consume** or on the unfiltered path. Frozen match in the continuation. Match/Resolve are required interface members.
4. **No filter-agent.** Optional 30s policy capability + single-use continuation, minted as one invocation.
5. Continuation: exact method/scheme/authority/path/query; 30s claim TTL; stream uses origin timeouts; body from sidecar; cannot retarget host. FSM `issued → claimed → consumed`; burn on mismatch; second admission fails.
6. `policy_vault` omitted = **no** policy cap. Source vault name = Layout A (explicit). Other vault = Layout B + dual-admin.
7. Policy cap cannot spend originating dest creds and cannot invoke **any** filtered service. Audit as initiator. Strict configured-service-only match; never read `unmatched_host_policy`.
8. Fail closed on hop / capability / Match / snapshot / missing-engine failure. 502/504, existing JSON envelope. A configured filter that cannot be run is never a bypass.
9. Hop headers: Original-URL, Continuation-Proxy **and** Continuation-Token, optional Policy-Proxy/Token, CA, Service. Prefixes `av_cont_` / `av_pol_`. Tokens not in URLs. Strip untrusted `X-Agent-Vault-*` then set trusted hop headers; strip sidecar namespace before setting `X-Agent-Vault-Proxy-Error`; strip the namespace again before origin.
10. `filter.url`: HTTPS default; loopback HTTP ok; non-loopback HTTP only with `allow_insecure_private_http` (RFC1918/loopback, no redirects, IMDS blocked). No userinfo, fragment, or configured query. Dedicated **per-service** dialer. Remote callback: `AGENT_VAULT_FILTER_PROXY_URL` validated at startup; invalid explicit value fails startup.
11. Proxy WebSocket to the sidecar when the service has a filter; continuation consumed at upgrade; sidecar bridges via continuation.
12. Hidden from `/discover` / skill. Proposals cannot set, clear, or delete filters/filtered services, and cannot introduce a matcher that equals or beats a filtered matcher.
13. Preserve on `service add` omit; wipe on `set`/`clear`. List prints `filter`.
14. YAML only (substitutions precedent). `FilterOp` omit/set/clear so `filter: null` survives encoding.
15. Production capabilities are **shared DB TTL rows** (hash + three-state FSM + versioned frozen projection + source session hash + invocation id). Process-local only when explicitly selected. No capability write on unfiltered Inject. Source revalidation inside each transition transaction. Scheduled sweeper is hygiene, not correctness.
16. Source session/agent revoke, expiry, or removal **immediately** invalidates issued capabilities (re-check on claim, consume, policy auth, and each CONNECT policy request). 30s is not a post-revoke grace period. Stricter than ordinary CONNECT; do not widen the unfiltered path here.
17. Frozen snapshot: complete non-secret Resolve shape, never values, never `Filter`. Do not re-run match. Resolve current values for frozen keys. Version-first decode; unknown version fails closed.
18. No RFC 9457 in this change.
19. Proposals may not shadow a filtered matcher (exact matcher-language overlap; reject better **or equal** priority). Admin YAML may. Check create and apply.
20. Policy-capability requests never consult `unmatched_host_policy`. Policy CONNECT is refused pre-hijack unless the authority is covered by an enabled unfiltered configured service.
21. Security controls on the filter path are compile-time obligations. Optional type-assert “skip the check” is illegal. Errors fail closed.
22. Capability rows store the session token **hash**, never the raw token. Test: no row equals any live raw session, capability, or credential value.
23. Destination **injection header slots** are removed before the sidecar. Unrelated `Authorization` on a non-Authorization dest-auth service is preserved.
24. Continuation/policy rows are minted and retired as one invocation.

---

## Tests

Original matrix, plus:

**Smoke.** `TestSmoke_FilterLayoutA` on real SQLite (`store.Open`): deny → zero origin and zero credential reads; allow → origin receives injected dest cred; no filter-agent row.

**Blocking**

- Proposal adding a longer-literal / exact-host unfiltered matcher over a filtered wildcard is rejected at create; apply after an intervening config change is 409. Disjoint matchers are accepted.
- Policy capability + unmatched host + vault passthrough → fail closed; origin never contacted; unmatched-policy store method never called.
- Policy CONNECT to an authority with no eligible unfiltered service: refused pre-hijack, no leaf, no dial.
- Continuation CONNECT to an unbound authority: refused pre-hijack, burned; a second CONNECT with an already-claimed continuation is refused; a later correct attempt after burn fails.

**Store / revoke**

- N concurrent claims on real SQLite: exactly one `issued → claimed`. N concurrent consumes: exactly one `claimed → consumed`.
- Agent revoke, session revoke/expiry, user deactivation, and source-vault grant removal reject both kinds; re-grant does not revive a burned cap; exercise inside an existing policy CONNECT.
- Force failure of the second row in pair issuance → neither row visible. Failed/denied hop retires leftovers.
- Inspect the real database: no column equals any live raw token or credential value.

**Frozen / interfaces**

- YAML matcher / auth-key edit does not retarget; value rotation of the frozen key attaches the new secret; key deletion fails closed; custom templates and substitution fields round-trip.
- Unknown envelope version and malformed payload fail before any credential read.
- `Match` error and absent filter engine/store → `502 filter_misconfigured`, zero origin and credential reads. Compile-time interface assertions on production and test stores.

**Hop / headers / WS**

- Dest-auth slot values do not reach the sidecar; unrelated `Authorization` on another auth slot is preserved; sidecar cannot spoof `X-Agent-Vault-Proxy-Error`.
- `filter.url` userinfo/fragment/query rejected; callback URL userinfo/path/query/fragment/non-loopback HTTP rejected; startup fails on invalid callback env; redirects returned not followed.
- Full filtered WS bridge: sidecar callback through continuation, bidirectional frames, origin gets injected credential, Resolve exactly once. Denied upgrade → zero Resolve. Unfiltered WS unchanged.
- Client hop on a filtered service with omitted `policy_vault` mints no policy headers.
- Dial policy: loopback HTTP allowed; flagged RFC1918 HTTP; public HTTP denied; IMDS/link-local blocked.
- Proposal `filter: {}` / `filter: null` is 400.

Count credential-store calls on the denied path; do not rely on status alone.

---

## Upstream issue

https://github.com/Infisical/agent-vault/issues/407 — `RFC: per-service MITM request filter (out-of-process sidecar)`
