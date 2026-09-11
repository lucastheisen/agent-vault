# Cursor reviews Codex — which plan is the better solution?

Compared:

- **Cursor:** `ad_hoc/issue-407/service-filters.plan.md` on `issue-407-cursor` (this branch).
- **Codex:** the same path on `issue-407-codex`.

This is a comparison of **plans**, not of the implementations sitting on those branches. The question is which design, if built as specified, is the better Agent Vault feature.

---

## Verdict

**Codex’s plan is the better security architecture for a credential broker. Cursor’s plan is the better product shape for the servlet-filter hop we actually specified.**

If the job is “do not decrypt or leak destination secrets until policy says yes, and do not mint a second long-lived key that can do the write,” Codex wins. Several of those properties are missing or weaker in the Cursor plan, and they matter more in this repo than WebSocket-on-filtered-services or same-vault convenience.

If the job is “a general out-of-process filter that can sit on any matched service, including same-vault logic and WS, with a local/k8s sidecar over HTTP,” Cursor wins. Codex forbids or degrades those cases on purpose.

A **better solution than either** is Codex’s capability model with three Cursor product decisions grafted on. Neither plan as written is that hybrid. Forced to ship one spec unchanged, **ship Codex’s**: Agent Vault’s reason to exist is credential isolation, and Cursor’s mint-at-config agent on the source vault can undo that for the git-push straw man.

---

## What both plans already agree on

These are locked the same way and should not be re-litigated:

- Out-of-process reverse-proxy hop after **match**, before destination credential inject.
- Sidecar may short-circuit any HTTP response, or continue via a **new** request (not a paused original body).
- Continuation is **not** the inbound agent session and is **not** bound to body bytes.
- Filters are admin-only; hidden from `/discover` / skill; YAML on the service; proposals preserve filters.
- Fail closed if the hop cannot be made. Stream bodies. No in-process plugins / WASM / rules language.
- Same upstream issue: Infisical/agent-vault#407.

The interesting delta is **what the sidecar is allowed to be**, and **what token it holds**.

---

## Where Codex’s plan produces a better solution

### 1. Destination secrets are not even decrypted until allow

Codex splits `Match` from `Resolve` and states an invariant: denied or unreachable filter → **zero** reads of the destination credential. Continuation carries a non-secret match handle.

Cursor says “no inject before the hop,” which is necessary but weaker. The hop still decrypts the **filter-agent** token every time. After skip, Inject runs on whatever the vault currently is. There is no stated “match object frozen at hop start.”

For a broker, “we never opened the DEK for this PAT unless policy allowed” is the right invariant. Codex designs it; Cursor hopes Inject is simply later.

### 2. Continuation is single-use, short-lived, and exact

Codex: random in-memory capability, **30s to claim**, **single-use**, bound to method / scheme / authority / escaped path / query, consumed on first exact match (including inside CONNECT). Replay and mutated URL fail closed. Match is retained so a YAML edit during the window cannot swap which credential is attached.

Cursor: HMAC over `{filter, vault, actor, method, host, path, expiry}`, **no consume bit** (explicitly no DB row). Until expiry, a stolen ticket is reusable on that route with **any body**. Restart invalidates in-flight tickets; that is not a replay defense while the process lives.

We chose HMAC to avoid a write storm. Codex’s in-memory consume map gets single-use **without** SQLite writes. That is the design we should have used for the ticket. Cursor’s plan is strictly worse on replay.

### 3. No long-lived filter principal

Codex non-goal: “dynamic per-filter agents or permanent filter credentials.” Policy access is a **30s capability** on an optional other vault. Stolen header dies quickly. Sidecar is not an `agent list` row.

Cursor mints a real agent at config time, stores a DEK-wrapped token, grants **proxy** on `filter.vault`, shares it by `(url, vault)`. In Layout A that agent **can push** (`github-push` is in the same vault; skip-filter exists so it does not recurse). Revoke is fail-closed until YAML re-apply — a footgun we documented rather than removed.

The conversation picked mint-at-config for efficiency. Codex shows efficiency and a small steal window are compatible: **memory, not agents**. Cursor’s visible `filter-` agent is honest about using the agent table; it is also a permanent write-capable identity in the common config. That is a worse trust story.

### 4. Policy vault is a real isolation boundary

Codex:

- `policy_vault` **must differ** from the source vault.
- Configuring admin must be **vault admin of both**.
- Policy capability cannot spend the original request’s credential authority and **cannot invoke another filter** (no capability-minting cycles).
- Audit/rate-limit attribution stays the **initiating actor**.

Cursor:

- `filter.vault` **may be the same** (default).
- No dual-admin check in the plan. A source-vault admin pointing `filter.vault` at a vault they should not mint proxy agents into is an authorization hole unless the implementation secretly requires a grant.
- Filter-agent calls GitHub **as that agent**, not as the pushing human/bot. Audit of the protection lookup and of a self-completed push is the wrong principal.
- Skip is per that agent (more precise than “no nested filters”). That precision does not make up for Layout A.

Forcing a second vault is heavier ops (see below). The **authorization and audit** rules around that second vault are better in Codex.

### 5. Remote hop is actually specified

Codex notices the sidecar must **call back** through Agent Vault:

- `X-Agent-Vault-Continuation-Proxy` / `X-Agent-Vault-Policy-Proxy` are **proxy URLs containing the capability**.
- Remote filters require `AGENT_VAULT_FILTER_PROXY_URL` (HTTPS, unless literal loopback).
- `X-Agent-Vault-CA` so the sidecar can trust MITM.
- Remote `filter.url` must be HTTPS; cleartext HTTP only on a **literal loopback IP**.

Cursor puts `Filter-Token` + `Filter-Nonce` on the hop and assumes the sidecar already speaks Agent Vault (`HTTPS_PROXY`, CA from `vault run`). A sidecar is not `vault run`. A **remote** filter is not told where the proxy is. CA distribution is missing. “Any http(s) URL” plus IMDS block is a smaller maintainer surface, but it ships an incomplete remote protocol and allows destination-adjacent secrets (the filter token) over cleartext to a non-loopback host.

Codex’s extra env var is justified. Cursor’s hop contract is enough for `127.0.0.1` only if the operator wires proxy+CA by hand.

### 6. Proposals cannot delete a filtered service

Cursor: preserve `filter` on proposal **update**; wipe on admin `set`/`clear`. An agent proposal that **deletes** `github-push` is not called out. That is fail-open for the policy.

Codex: proposals cannot delete a filtered service. That is the correct complement to “filters are an implementation detail.”

### 7. Header hygiene is stated in both directions

Both overwrite hop headers toward the sidecar. Codex also says every `X-Agent-Vault-*` is stripped **before origin and before the agent sees the response**, and treats capability URLs as bearer secrets not to log. Cursor strips broker-scoped headers toward origin; response-to-agent stripping and “do not log the ticket” are implied, not specified.

---

## Where Cursor’s plan produces a better solution

### 1. Same-vault “logic in front of the same PAT”

The motivating operator story is: one GitLab/GitHub token, add a branch-protection check, do not invent a second vault. Cursor Layout A is that story. Codex **forbids** `policy_vault == source vault`.

That is a real product cost. Operators who will not split vaults will either skip the feature or stuff write creds into the policy vault (same blast radius as Cursor Layout A, more YAML). Cursor is honest that Layout A’s stolen filter token can push; Codex makes isolation mandatory and may not get used.

Optional same-vault with Layout B as the documented hard mode is the better product. Codex’s must-differ rule is the better default **if and only if** dual-admin is enforced; it should not be the only mode.

### 2. Filtered WebSocket

The conversation explicitly refused Skip/Bypass: a usage-limit filter on `api.openai.com` may need the upgrade. Cursor reverse-proxies WS to the sidecar. Codex **rejects** filtered WS.

For git-receive-pack, Codex is enough. For “servlet filter on any matched service,” Cursor is the feature we agreed to. Codex shrinks the seam by dropping a case the user said is in scope.

### 3. Sidecar-container HTTP

Cursor’s dialer: loopback, private, and public; IMDS still blocked; dedicated transport so `127.0.0.1` works without `AGENT_VAULT_ALLOW_PRIVATE_RANGES`. A compose sidecar `http://filter:12345` works.

Codex: non-loopback HTTP is **invalid**. In-cluster DNS names need HTTPS and a real cert (or hostNetwork + loopback). That is safer. It also fights the “sidecar on the same machine / same pod network” exemplar unless TLS is set up first.

### 4. Operator documentation of the straw man

Cursor’s Layout A / Layout B tables are the piece a human reviewer of #407 can implement against. Codex’s YAML is a single filtered GitLab service plus `policy_vault:`; it does not show the unfiltered protection-API service, stolen-token consequences, or clone/fetch non-match. The Codex **protocol** is tighter; the Cursor **runbook** is better.

### 5. Timeouts and long bodies

Cursor reuses origin hop budgets (including 10-minute WS idle). Codex’s 30s is a **claim** deadline, which is fine if the stream may outlive the claim — the plan says consumed by the first matching request, then presumably the body can run. That should be an explicit sentence. Cursor’s “reuse origin timeouts” is unambiguous for a multi-minute packfile **decision+proxy** if someone misreads 30s as wall clock for the whole push.

### 6. Skip granularity

Cursor skips **that** filter-agent (and a valid ticket), not every filter in the vault. A git sidecar completing as itself should still hit an unrelated OpenAI filter. Codex’s “policy capabilities cannot invoke another filter” is simpler and cycle-proof; it is also coarser. If a policy vault ever had a legitimate second hop, Codex cannot express it. Unlikely in v1; still a Cursor precision win.

---

## Material holes (plan-level)

**Cursor**

- HMAC ticket is replayable until expiry; body unbound (acknowledged) **and** not single-use (not forced by “no DB”).
- Layout A = long-lived write-capable sidecar identity.
- No dual-admin / “may I mint proxy on vault B?” rule.
- No CA, no advertised proxy URL, no CONNECT-claim semantics for the continuation.
- Proposal delete of a filtered service unspecified.
- `filter.vault` unconstrained contents without isolating *who can aim it*.

**Codex**

- Same-vault mode impossible; WS-on-filtered-service impossible; HTTP sidecar-by-name impossible.
- 30s policy **and** continuation lifetimes may be tight if the sidecar must finish GitHub API + open continuation under load; not fatal if 30s is claim-only, but the plan should say the stream TTL separately.
- `AGENT_VAULT_FILTER_PROXY_URL` is a new operator knob (acceptable) and a new SSRF/TLS story (must stay as strict as `filter.url`).
- Capability-in-URL is easy to log (`X-Agent-Vault-Continuation-Proxy: http://…?token=`). The “must not log” sentence is load-bearing; a dedicated header like Cursor’s nonce is slightly harder to mishandle in access logs. Minor.
- In-memory capabilities die on restart (same as Cursor HMAC key). Fail closed. Fine. Multi-instance Agent Vault (Postgres mode) **cannot share** those tokens across processes. Cursor’s mint-at-config agent **does** work on every instance; Codex’s continuation does not without sticky routing or shared state. The plan does not mention multi-instance. For production HA, that is a Codex gap (or an implicit “filter hop is local to one process”).

The last point is the one Codex weakness that can dominate if someone runs several Agent Vault replicas. Cursor’s encrypted agent token in the DB is replica-friendly; Codex’s RAM map is not. A better Codex would say: single-instance / sticky MITM, or store capabilities in the existing session table with TTL (a write per hop — the cost we avoided). This is not solved in either plan for clustered MITM.

---

## Which plan to treat as source of truth

| Criterion | Winner |
|---|---|
| Credential isolation (the product) | **Codex** |
| Continuation / replay | **Codex** |
| Sidecar identity / steal window | **Codex** |
| Cross-vault authorization & audit | **Codex** |
| Remote filter protocol (URL, CA, TLS) | **Codex** |
| Proposal cannot strip policy | **Codex** |
| Same-vault convenience | **Cursor** |
| Filtered WebSocket | **Cursor** |
| Local/k8s HTTP sidecar | **Cursor** |
| Operator straw man (Layout A/B) | **Cursor** |
| Multi-instance MITM | **Cursor** (accidentally, via DB-backed agent token) |
| Small persistent schema | **Codex** (no agent rows, no `kind`) |

**Source of truth if we send one RFC to Infisical:** Codex, plus a short “open questions” list: optional same vault, filtered WS, loopback-or-private HTTP, and clustered capability state.

**Do not** send Cursor’s plan unchanged as the better solution. The mint-at-config filter-agent on the source vault is the largest design mistake relative to what this proxy is for. The missing CA/callback is the largest completeness hole. The replayable HMAC is the largest cheap fix Codex already has.

---

## Hybrid (not asked, but it is the actual better solution)

Keep Codex:

- Match vs Resolve; no dest decrypt until continuation.
- In-memory **single-use** continuation (and policy) capabilities; exact URL bind; retained match.
- Dual-admin if `policy_vault` is set; policy capability cannot nested-filter; audit as initiator.
- HTTPS for non-loopback `filter.url`; advertise proxy URL + CA on the hop.
- Proposal cannot delete/strip filters.

Keep Cursor:

- `policy_vault` / `filter.vault` **optional**, default same vault (Layout A), documented stolen-token cost.
- Filtered WS reverse-proxied (unfiltered WS unchanged).
- Dedicated dialer: loopback + private HTTP allowed, IMDS blocked, so `filter:12345` works.
- Layout A/B write-up in the issue.
- Skip **that** filter on continuation/policy, not every filter in the world.

Decide explicitly for HA: sticky MITM or shared TTL store for capabilities. Silent RAM-only is a landmine the moment `DATABASE_URL` implies multiple processes.
