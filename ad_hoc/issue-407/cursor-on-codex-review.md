# Cursor on Codex’s review of the Cursor plan

Source reviewed: `ad_hoc/issue-407/codex-reviews-cursor.md` on `origin/issue-407-codex` (title there: “Codex review: policy-filter plans”).

This file is two parts:

1. **Review of that review** — where Codex is right, where it overfits, what the conversation already locked.
2. **Updated plan** — the spec that follows. Canonical working copy is also `ad_hoc/issue-407/service-filters.plan.md` (same content as part 2).

Do not include `ad_hoc/` in an upstream PR.

---

# Part 1 — Review of Codex’s review

## Codex’s conclusion

Codex: keep *their* plan as the v1 security core (no dest resolve until continuation; no durable filter credential; separate policy vault; HTTPS remote; no filtered WebSockets). Steal Cursor’s operational lifecycle, timeouts, and examples. Do not steal Cursor’s mint-at-config filter-agent.

**Mostly right on security. Wrong as a full product veto.** The review treats “stronger least privilege” as automatically the v1 bar, and treats conversation-locked product decisions (same vault, filtered WS, HTTP sidecar) as optional polish. Those were not polish. They were the feature.

The correct reading of Codex’s review is: **accept the capability model, reject the product amputations**, and fix Cursor’s actual holes (durable agent, replayable HMAC, missing CA/callback, proposal delete).

---

## Point-by-point on Codex’s comparison table

### Destination credentials — agree, and we under-specified

Codex: equivalent *intent*, their plan states and tests the no-read invariant more explicitly.

**Accept.** “Filter before inject” is not the same as “Match vs Resolve; denied hop never opens the dest DEK.” The updated plan takes their invariant verbatim. This was not a conversation lock; we were sloppy.

### Filter authority — agree; mint-at-config was a bad compromise

Codex: 30s opaque policy capability vs recoverable long-lived filter-agent token. Durable token is a larger theft/rotation target.

**Accept.** Conversation history: the user asked for ephemeral (“duration of the filter”), then rejected per-request **DB** sessions as a write storm. Mint-at-config was our efficiency hack, not a product requirement. Codex’s in-memory map is ephemeral **and** has no SQLite write. That is the design we should have locked in Q6/Q7.

Visible `filter-` agents were an identity-model convenience (`agent list` / revoke). They are not worth a PAT-equivalent sitting in the source vault.

### Vault separation — reject “must differ”; accept dual-admin

Codex: policy vault must be separate; configurator admins both. Cursor default-same is worse least privilege; Cursor even documents that a stolen same-vault filter token can push.

**Half.** Dual-admin when `filter.vault` is *another* vault is an authorization hole we never specified. Adopt it.

**Must-differ is not v1.** Q17–Q18 locked same-vault as the primary value: complex logic in front of the **same** creds. Forcing a second vault makes operators skip the feature or dump write creds into the policy vault anyway.

Codex is reacting to Layout A **as we specified it** (long-lived agent with skip-filter that can push). That risk goes away if the policy capability **cannot spend the originating dest credential** and the push **must** use a single-use continuation. Residual: 30s on *other* unfiltered write services in the same vault. Layout B remains the way to zero that. Document, don’t forbid Layout A.

### Continuation binding — agree

Codex: single-use; method, scheme, authority, escaped path, query; frozen non-secret match. Cursor HMAC: method, host, path, expiry.

**Accept.** HMAC without consume is replayable until expiry with any body. Scheme/query omission is a real bind hole. Frozen match kills TOCTOU if YAML changes mid-window. In-memory consume is not the DB storm we refused.

### Continuation storage — agree with Codex’s trade, not Cursor’s “lighter is better”

Codex: opaque random, in-process, removed on consume/expiry. Cursor: stateless HMAC, dies on restart. Codex says Cursor is lighter; they buy single-use + preserved match.

**Accept Codex storage.** “Lighter” HMAC was the wrong optimization once in-memory exists. Restart fail-closed is the same either way.

**Gap neither review owned until we said it:** process-local capabilities do not work across MITM replicas. v1 is sticky MITM / single process. Do not add a per-hop DB table.

### Filter transport — accept public HTTPS; reject loopback-only HTTP

Codex: remote filter and return path HTTPS; cleartext HTTP only on a **literal loopback IP**. Cursor: any HTTP(S), including public cleartext.

**Accept the actual security win:** do not send continuation/policy bearers over public HTTP.

**Reject literal-loopback-only.** Q10: exemplar is `127.0.0.1` *or a sidecar container*. `http://filter:12345` is the compose case. Dedicated dialer, IMDS still blocked, not `AGENT_VAULT_ALLOW_PRIVATE_RANGES`. Public destinations HTTPS.

Codex also correctly requires an **advertised callback** (`AGENT_VAULT_FILTER_PROXY_URL`) and CA on the hop. Cursor’s hop assumed `vault run` env. Sidecars are not `vault run`. Adopt CA + proxy URLs.

### Header boundary — agree, tighten Cursor

Codex: strip all `X-Agent-Vault-*` at the destination **and** they imply response stripping so a policy API cannot spoof control headers to the agent.

**Accept namespace-wide strip both directions.** Cursor’s per-header broker-scoped list was the right prefix, incomplete boundary.

### Filter recursion — reject “skip all filters”

Codex: policy-vault capabilities cannot invoke another filter (simpler, fail-closed). Cursor: skip continuation or **that** filter-agent (broader self-complete, more exposure).

**Keep Cursor granularity.** Q11-era example: git sidecar must not bypass an unrelated OpenAI filter. Codex’s global skip is simpler and wrong.

Updated rule: continuation skips **this** service’s filter after exact claim. Policy cap **cannot spend originating dest creds** and cannot recurse **this** filter. Other filters still run.

### WebSockets — reject deferral

Codex: defer filtered WS; better v1 boundary unless a concrete use case is required.

**The use case was required.** Q11: git is one example; `api.openai.com` usage-limit / model rewrite may need the upgrade. Skip/Bypass was fail-open or 502-by-default for that service’s WS. We confirmed **Proxy**.

Unfiltered WS stays as today. Filtered WS reverse-proxies to the sidecar. That is not “Cursor more capable therefore later.” It is in-scope v1.

### Request bodies — agree (already equivalent)

Stream; filter that consumes must replay. Unchanged.

### Configuration lifecycle — Codex is asking to adopt work we already did

Codex: Cursor has the stronger operational spec (add/set/clear, list round-trip, sharing, revocation, remint). Their plan should add mutation semantics even without a filter-agent lifecycle.

**Agree they should have copied it; we already had it.** Keep YAML-only, preserve on `add` omit, wipe on `set`/`clear`, list prints `filter`. Sharing/revocation/**remint of agents** goes away with agents. Add what they missed on our side: proposal **delete** of a filtered service is fail-open → reject.

### Failure and timeout — already locked; they should copy us

502/504, existing JSON envelope, origin hop budgets, dedicated dialer/IMDS. Q8, Q10, Q14. Codex asked to add this. We keep it. Clarify 30s = **claim**, not packfile wall clock.

### Scope / implementation size — their “smaller” was “no agent table,” not “less product”

Codex: smaller, lower-risk upstream change (match/resolve + capabilities + existing sessions). Cursor: persistent filter-agent, encrypted token, sharing/revocation, extra APIs.

**Agree the agent machinery was extra risk.** Disagree that dropping WS, same-vault, and private HTTP is what makes a PR reviewable. The updated plan is **smaller schema than old Cursor** (no agents) and **not** smaller than the conversation’s feature.

---

## Codex’s numbered “keep current plan” list

1. No dest credential resolution before continuation — **keep (adopt into Cursor spec).**
2. Short-lived, exact, single-use continuations carrying original match — **keep.**
3. Separate policy vault with short-lived policy capability, **not** a durable filter agent — **keep the capability; do not require a separate vault.** Default same; optional `filter.vault`.
4. Cross-vault admin authorization and no agent-proposal control of filters — **keep dual-admin when vaults differ; keep proposal cannot set/clear; add cannot delete.**
5. HTTPS for every remote filter or callback hop — **keep for public; private/loopback HTTP remains.**
6. No filtered WebSockets in v1 — **reject.**

## Codex’s numbered “adopt from Cursor” list

1. Upsert / replace / clear / list-to-set — **already in the spec; keep.**
2. Timeouts, status codes, envelopes, dial restrictions — **already in; keep; add claim vs stream TTL.**
3. Explicit non-goals and operator examples — **keep Layout A/B.**
4. Document deferred filtered-WS + later extension path — **do not defer; implement Proxy as locked.**

---

## What Codex’s review got wrong about the conversation

- **“Durable filter-agent is a poor default.”** True of *that* mechanism. False that the sidecar must therefore be forbidden from same-vault **logic**. Ephemeral policy cap + dest-only-via-continuation is the synthesis.
- **“Better starting point for upstream v1” = their whole plan.** Upstream will like no dest decrypt and no agent rows. They will not like a feature that cannot run `http://filter:12345` or same-vault git-guard without a second vault.
- **WebSocket as “more capable.”** It was a closed Q11 decision, not a stretch goal.
- **Silence on HA.** Both RAM maps die on restart; only Cursor’s old DB token accidentally survived replicas. Call sticky MITM out instead of pretending.

---

## Outcome

Ship a **hybrid spec** (part 2). Do not ship old Cursor (agents + HMAC). Do not ship Codex unchanged (must-differ vault, no filtered WS, loopback-only HTTP).

The implementation on `issue-407-cursor` still matches the **pre-review** agent hop and is out of date relative to part 2.

---

# Part 2 — Updated plan

Canonical file: `ad_hoc/issue-407/service-filters.plan.md`.

# Per-service request filters

Working design for an out-of-process “servlet filter” hop on the MITM proxy: after a service matches, Agent Vault reverse-proxies the live request to an operator-configured URL **without resolving destination credentials**. The sidecar may short-circuit (any HTTP response) or continue through Agent Vault with in-memory capabilities.

This file is a **local working spec**, not upstream docs. Canonical copy for Infisical: https://github.com/Infisical/agent-vault/issues/407. Do not include `ad_hoc/` in the pull request. After merge, operator-facing behavior belongs in Mintlify (`docs/learn/services.mdx`, CLI reference), not this plan.

Status: **revised after Codex review** (`codex-reviews-cursor.md` on `issue-407-codex`). The implementation on `issue-407-cursor` still matches the *previous* mint-at-config agent spec and must be updated to this document before a PR. Local working copy; do not include `ad_hoc/` in the pull request.

---

## Revisions after Codex review

Codex’s review of the previous Cursor plan, plus Cursor’s review of Codex, plus the locked conversation. This section is the decision log; the rest of the file is the spec that follows from it.

### Adopt from Codex (conversation never needed a durable agent)

The conversation asked for an ephemeral sidecar identity, then rejected **per-request DB sessions** as a write storm. Mint-at-config was the compromise. Codex’s **in-memory capabilities** get ephemeral + no SQLite writes. That is the design we should have locked.

| Change | Why |
|---|---|
| Split **match** from **Resolve**; destination DEK unused until continuation (or unfiltered path) | Credential-broker invariant. “Filter before inject” was weaker. |
| Replace HMAC ticket with **single-use, in-memory** continuation; bind method, scheme, authority, escaped path, query; **retain the match object** | HMAC was replayable until expiry; YAML edits could swap creds mid-window. In-memory consume is not a DB write. |
| Replace mint-at-config **filter-agent** with a **30s policy capability** (optional) | Durable `filter-` agent on the source vault can push (Layout A). User originally wanted ephemeral. |
| Dual-admin when `filter.vault` names **another** vault | Conversation never specified this; source-vault admin must not mint proxy power into a vault they do not admin. |
| Policy capability **cannot spend the originating destination credential** | Keeps Layout A (same vault) without “stolen sidecar token can `git push`.” Side channel uses other services; the push uses continuation only. |
| Advertise **proxy URL + CA** on the hop; `AGENT_VAULT_FILTER_PROXY_URL` for remote callbacks | Sidecar is not `vault run`. Previous hop assumed the operator wired `HTTPS_PROXY` by hand. |
| Strip all `X-Agent-Vault-*` on the way **to origin and back to the client** | Codex namespace-wide boundary. |
| Proposals cannot **delete** (or strip) a filtered service | Preserve-on-update was not enough; delete is fail-open. |
| Claim TTL **30s**; stream TTL = existing origin hop budgets | 30s is to *open* continuation, not to finish a packfile. |

### Keep from the conversation (reject Codex “must”)

| Keep | Codex wanted | Why we keep it |
|---|---|---|
| `filter.vault` **optional, default same vault** | Must differ | Q17–Q18: feature is complex logic in front of the same creds. Split vault is Layout B, not the only mode. Stolen-policy-cap cost is now bounded (cannot spend dest; 30s). |
| Filtered **WebSocket** reverse-proxied | Defer WS | Q11: git is not the only consumer; an OpenAI usage filter may need the upgrade. Unfiltered WS unchanged. |
| HTTP to **loopback and private** sidecar URLs; public **HTTPS** | Literal-loopback HTTP only | Q10: `127.0.0.1` and compose `http://filter:12345`. Public cleartext was the actual Codex win; we take that without breaking k8s DNS HTTP. IMDS still blocked. Dedicated dialer, not `AGENT_VAULT_ALLOW_PRIVATE_RANGES`. |
| Skip **that** filter, not every filter in the vault | Policy cap skips all filters | Unrelated OpenAI filter must still run if the git sidecar’s policy cap happens to call that host. |
| YAML-only; preserve on `add` omit; wipe on `set`/`clear`; list prints `filter` | (Codex asked to adopt these) | Already locked Q13–Q19. |
| Fail closed 502/504, existing JSON envelope, no RFC 9457 | (Codex asked to specify this) | Already locked Q8–Q9. |
| YAML Layout A / B runbook | Thinner example | Keep; it is what a #407 reviewer implements against. |

### HA (neither plan had this)

Capabilities are **process-local**. Restart → fail closed (same as old HMAC key). Multiple MITM processes (`DATABASE_URL` / replicas) **do not share** the consume map. v1 documents **sticky MITM** (or a single proxy process). A shared TTL store is a later change; it is a write per hop and was the storm we refused. Do not silently pretend clustered MITM works.

---

## Problem

The broker matcher is host/path/port plus credential injection. Some policies need **arbitrary logic** on the request (inspect a git-receive-pack body, call GitLab’s protection API, maybe retarget GitLab → GitHub, maybe rewrite an OpenAI model) **before** destination secrets are attached.

That logic must not live in Agent Vault. The OSS seam is: match → hop to sidecar → sidecar decides.

Motivating example (not the only consumer): `git push` over HTTPS. Sidecar parses the target ref, asks whether the branch is protected, returns 403 or lets the push proceed with credentials attached.

---

## Non-goals (v1)

- In-process plugins, WASM, Go `.so`, or a new rules language.
- Filter as a true chained HTTP forward-proxy (absolute-form / CONNECT **to the sidecar**). v1 is **reverse-proxy to `filter.url`**. Continuation/policy callbacks **to Agent Vault** use the existing MITM forward-proxy (including CONNECT).
- Durable filter-agents, recoverable long-lived filter tokens, `kind` on agents, reserved `filter-` names.
- Per-request DB sessions or a shared capability table (v1 is process-local memory).
- RFC 9457 Problem Details (existing `{error, message}` + `X-Agent-Vault-Proxy-Error`).
- `/discover`, agent skill, dashboard UI (unless a reviewer blocks without it), `--filter-*` flags, `vault service filter` subcommands.
- Binding the continuation to request-body bytes (packfiles must stream).
- Clustered MITM without sticky routing.

---

## Placement in the existing pipeline

Today (simplified):

authenticate → rate limit → **Inject (match + decrypt creds)** → substitutions → origin (or WebSocket dial).

**Unfiltered** services: unchanged, including WebSocket to origin.

**Filtered** match:

authenticate → rate limit → **match (no dest decrypt)** → reverse-proxy to `filter.url` → sidecar’s response is the client’s response.

`CredentialProvider` splits **Match** from **Resolve**. A `CredentialMatch` holds service metadata and a private handle, **no decrypted destination secret**. `Resolve` runs only after a valid continuation claims that frozen match, or immediately on the unfiltered path.

**Invariant:** denied, timeout, or unreachable filter → **zero** reads/decryptions of the destination credential.

Disabled service / no match: unchanged. Do not call the filter.

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
      url: http://127.0.0.1:12345
      vault: policy          # optional; default = this service’s vault
```

| Field | Required | Meaning |
|---|---|---|
| `url` | yes if `filter` present | Sidecar origin. `http` only for loopback or private/link-local (compose/k8s sidecar). Public destinations must be `https`. |
| `vault` | no | Vault the **policy capability** is scoped to. **Default: the service’s vault.** May be the same (logic in front of the same creds) or another (Layout B). Agent Vault does **not** constrain which *other* services live there. |
| | | If `vault` names a **different** vault, the configuring actor must be **vault admin of both**. |

No `agent_id`. Nothing is minted into the agents table.

Clear on upsert: `filter: null` (or equivalent empty) on **`vault service add`**.

Remote sidecars that must call back through Agent Vault also need the process env **`AGENT_VAULT_FILTER_PROXY_URL`**: an `https` forward-proxy URL the sidecar can reach (literal-loopback `http` allowed). Local sidecars with no advertised URL use the process’s loopback MITM listener. Document in `.env.example` and the env-var tables when implemented.

---

## Who writes what (merge)

| Write | `filter` |
|---|---|
| Agent proposal that sets/clears `filter` | **Reject** (or ignore) the field. Implementation detail. |
| Agent proposal that **deletes** a filtered service | **Reject.** Delete would fail-open the policy. |
| Agent proposal that updates auth/host of a filtered service | **Preserve** `filter`. |
| `vault service add` / POST upsert, field omitted | **Preserve.** |
| `vault service add` with `filter:` / `filter: null` | Set or clear. |
| `vault credential set` | Does not touch services. |
| `vault service set` (replace list) / `clear` | **Not preserved.** Document this. |
| Interactive `service set` “Replace all” | Same as `set` (wipe). No wizard prompts for filter in v1. |

Admin `vault service list` **must include** `url` + `vault` so list→set round-trip does not drop filters. Never include capability material. Still omitted from `/discover`.

---

## Two in-memory capabilities (not the inbound agent token, not a filter-agent)

Do **not** forward the inbound `Proxy-Authorization` / agent A session to the sidecar. Do **not** create an agent row.

Both capabilities: random opaque tokens, **process-local map**, no DB write. Restart drops them (fail closed). Audit and rate-limit attribution stay the **initiating actor**.

### 1. Continuation (per invocation, single-use)

Bound to `{method, scheme, authority, escaped path, query}` plus the **frozen CredentialMatch** (inbound vault, original actor for logs). Claim TTL **30 seconds**. Consumed by the **first exact matching** request, including inside CONNECT. Mutated URL or replay → fail closed.

Sidecar opens a **new** MITM request to that exact target with this capability as `Proxy-Authorization` (or the advertised continuation-proxy URL). Agent Vault verifies, consumes, **skips this service’s filter**, **Resolves the frozen match**, injects **those** destination credentials, forwards whatever body the sidecar sent.

Cannot retarget host (GitLab → GitHub). That path is the policy capability against a **different** service in `filter.vault`.

A service YAML edit during the 30s window **cannot** change which credential is attached; the match object is the one from hop start.

### 2. Policy capability (optional, 30s, reusable in-window)

Minted when `filter` is present (always, including default same-vault). Scoped to `filter.vault`. Sidecar uses it like a short-lived proxy session for **side-channel** calls (protection API) and for **self-complete on a different service**.

It **cannot**:

- spend the originating continuation’s destination credential (no Resolve of that frozen match);
- invoke **this** filter again (no recurse / no nested capability mint on this service);
- outlive 30s.

It **can** use **other** services in `filter.vault` (unfiltered, or a different filter — that other filter still runs). Stolen policy cap in Layout A can still hit *other* write services in the same vault for 30s; it **cannot** `git push` on the originating `github-push` row. Layout B (separate vault with only read APIs) removes that residual.

---

## Skip the filter (no loops)

Do **not** reverse-proxy to the sidecar when:

1. Continuation is valid for this exact URL + frozen match, or
2. The caller presents **this hop’s** policy capability **and** the matched service is **the one that issued it**.

Skip is **not** global. A git sidecar’s policy cap calling `api.openai.com` still hits an OpenAI filter if one exists.

Without (2), “complete it myself” on the same route would recurse; we instead **forbid spending dest creds** on that path — same-route complete is **continuation only**. (2) is for the policy cap accidentally matching the originating host/path (fail closed / no recurse), not a way to inject dest creds.

---

## Reverse-proxy hop (Agent Vault → sidecar)

Treat `filter.url` as an **origin**. Preserve method, path, query, body (stream), and original `Host`. Overwrite (never trust client copies of) hop headers:

| Header | Purpose |
|---|---|
| `X-Agent-Vault-Original-URL` | Exact original destination URL |
| `X-Agent-Vault-Continuation-Proxy` | Forward-proxy URL that embeds the single-use continuation (bearer secret) |
| `X-Agent-Vault-Policy-Proxy` | Optional forward-proxy URL that embeds the 30s policy capability |
| `X-Agent-Vault-CA` | Agent Vault MITM root (so the sidecar can trust HTTPS callbacks without `vault run`) |
| `X-Agent-Vault-Service` | Matched service name |

Prefix matches `X-Agent-Vault-Proxy-Error`. All `X-Agent-Vault-*` are **broker-scoped**: stripped before origin **and** stripped from the sidecar’s response before it reaches the client. Capability URLs must not be logged or persisted.

**WebSocket:** reverse-proxy the upgrade and the byte stream to the sidecar (`Upgrade` / `Connection` preserved on **this** hop). Unfiltered services keep today’s origin WS path. Continuation for a WS handshake is still exact-URL + single-use; the sidecar is the WS client that, if it allows, claims continuation (or uses policy cap on another route).

**Timeouts:** origin hop budgets for TLS / first header / stream / WS idle **10 min**. Capability **claim** is 30s.

**Dial policy:** dedicated transport, **not** the default upstream `AGENT_VAULT_ALLOW_PRIVATE_RANGES` guard. Allow loopback and private/link-local **http**; require **https** for public destinations; **IMDS always blocked**. Re-check that dialer on redirects. Normal TLS verify for `https`.

**Hop failure** (dial, TLS, timeout, reset, capability mint failure): **502** (dial/TLS/reset) or **504** (timeout). Envelope: `Content-Type: application/json`, `{"error":"<code>","message":"..."}`, `X-Agent-Vault-Proxy-Error: true`. Codes: `filter_unreachable`, `filter_timeout`, `filter_misconfigured`. No dest Resolve, no origin.

**Sidecar success path:** copy status, headers (minus hop-by-hop / reserved broker headers / `Set-Cookie` policy as today), and body to the client. Any status. Agent Vault does not map “deny” to a fixed 403.

Bodies stream. A filter that consumes a non-replayable body must buffer/spool before claiming continuation.

---

## Straw-man configuration (git push / protected branch)

Sidecar listens on `:12345`. It is **not** a vault object and **not** an agent. Operator YAML names the matching service, the unfiltered protection-API service, and optionally `filter.vault`. Policy lives in the sidecar.

clone/fetch (`git-upload-pack`) never match the push row. Protection API is `api.github.com` — a **different** service.

What the operator does **not** type: agent names, tokens, `--filter-*` flags.

### Layout A — same vault (smallest)

`filter.vault` omitted. Policy cap is 30s proxy on `dev` **except** it cannot Resolve `github-push`’s frozen dest.

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
```

| Who | Request | What happens |
|---|---|---|
| coding agent | `POST https://github.com/acme/app.git/git-receive-pack` | match, **no PAT decrypt**, hop to `:12345` |
| sidecar, policy cap | `GET https://api.github.com/repos/…/protection` | inject `GITHUB_TOKEN`, GitHub |
| sidecar, allowed | new receive-pack via **continuation** (body from sidecar) | consume ticket, Resolve frozen match, inject `GITHUB_TOKEN`, GitHub |
| sidecar, protected | 403 (or any status) on the client hop | no dest decrypt, no origin |
| stolen policy cap, `git-receive-pack` | originating filtered service | **cannot** spend dest creds (30s residual: other unfiltered write services in `dev`) |

### Layout B — split vault (residual 30s blast gone)

`filter.vault: policy`. Configuring admin must be admin of `dev` **and** `policy`. Policy vault has only the read API.

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
      vault: policy
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

Retarget (GitLab → GitHub): continuation cannot change host. Sidecar uses the policy cap against a GitHub **write** service that lives in `filter.vault`.

Layout A is the straw man. Layout B is the same shape with `vault:` set.

A Layout A HTTP smoke (`TestSmoke_FilterLayoutA`, `make test-smoke`) exists for the **old** agent-based hop and must be rewritten against capabilities.

---

## Implementation seam (expected)

Small, localized; **smaller persistent schema than the previous Cursor spec** (no agent mint):

- `broker.Service`: `Filter` `{url, vault}`; JSON omitempty; URL scheme/host validation; no `agent_id`.
- `proposal.MergeServices`: preserve `filter`; never take `filter` from proposals; **reject delete** of a filtered service.
- `brokercore`: **Match** vs **Resolve**; frozen match on continuation; no dest decrypt on the filter path.
- `mitm`: in-memory capability map (continuation single-use, policy TTL); reverse-proxy to `filter.url`; CONNECT claim; strip `X-Agent-Vault-*` both ways; hop headers including CA + proxy URLs; dedicated dialer; filtered WS reverse-proxy.
- `server` / `cmd/server`: dual-admin if `filter.vault` differs; `AGENT_VAULT_FILTER_PROXY_URL`.
- CLI: none beyond YAML parse/print (`filter: null` via YAML→JSON). Docs: substitutions-style “file only”; `set`/`clear` wipe warning; sticky MITM for replicas.
- Tests: no dest decrypt on deny; single-use / exact URL / replay; retained match across YAML edit; dual-admin; proposal preserve + no-delete; hop header overwrite; skip that filter only; 502 on dead sidecar; WS unfiltered unchanged; filtered WS upgrade reaches sidecar; loopback/private HTTP vs public HTTPS.

---

## Locked decisions (checklist)

1. Reverse-proxy to sidecar (not chained forward-proxy to the filter, not in-process).
2. Per matched service only.
3. Match without dest decrypt; Resolve only after continuation or on the unfiltered path. Frozen match in the continuation.
4. **No filter-agent.** In-memory policy capability (30s, optional other vault) + single-use continuation. No per-request DB.
5. Continuation: exact method/scheme/authority/path/query; claim 30s; stream uses origin timeouts; body from sidecar; cannot retarget host.
6. Policy cap cannot spend originating dest creds; skip **that** filter only; audit as initiator.
7. `filter.vault` optional, default same vault, unconstrained *other* services; **dual-admin** when it differs.
8. Fail closed on hop / capability failure. 502/504, existing JSON envelope.
9. `X-Agent-Vault-*` headers including Continuation-Proxy, Policy-Proxy, CA; strip the namespace both directions.
10. `filter.url`: loopback/private `http` allowed; public `https`; IMDS blocked; dedicated dialer. Remote callback: `AGENT_VAULT_FILTER_PROXY_URL`.
11. Proxy WebSocket to the sidecar when the service has a filter.
12. Hidden from `/discover` / skill. Proposals cannot set, clear, or delete filters/filtered services.
13. Preserve on `service add` omit; wipe on `set`/`clear`. List prints `filter`.
14. YAML only (substitutions precedent).
15. Process-local capabilities; document sticky MITM for replicas.
16. No RFC 9457 in this change.

---

## Upstream issue

https://github.com/Infisical/agent-vault/issues/407 — `RFC: per-service MITM request filter (out-of-process sidecar)`
