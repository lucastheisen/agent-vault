# Per-service request filters

Working design for an out-of-process “servlet filter” hop on the MITM proxy: after a service matches, Agent Vault reverse-proxies the live request to an operator-configured URL **without resolving destination credentials**. The sidecar may short-circuit (any HTTP response) or continue through Agent Vault with short-lived capabilities.

This file is a **local working spec**, not upstream docs. Canonical copy for Infisical: https://github.com/Infisical/agent-vault/issues/407. Do not include `ad_hoc/` in the pull request. After merge, operator-facing behavior belongs in Mintlify (`docs/learn/services.mdx`, CLI reference), not this plan.

Status: **revised after Codex’s review of the Cursor hybrid** (`codex-on-cursor-review.md` / `codex-plan-amendments.md` on `issue-407-codex`). Cursor concurred. The implementation on `issue-407-cursor` still matches the *original* mint-at-config agent spec and must be rewritten against this document before a PR. Local working copy; do not include `ad_hoc/` in the pull request.

---

## Revisions

### After first Codex plan review

Adopted: match vs Resolve; no dest DEK until continuation; drop mint-at-config filter-agents; single-use exact continuation with frozen match; dual-admin when policy vault differs; dest-only-via-continuation; advertise callback + CA; strip `X-Agent-Vault-*` both ways; proposal cannot delete a filtered service; 30s is **claim** TTL.

Kept from conversation: same-vault **mode** (not must-differ); filtered WebSocket proxy; sidecar HTTP; YAML lifecycle; 502/504 envelope; Layout A/B runbook.

### After Codex’s review of that hybrid (this revision)

Cursor concurred with three refinements and two smaller protocol fixes:

| Change | Why |
|---|---|
| Omitted `policy_vault` means **no** policy capability. Naming the source vault opts into Layout A. | Silent “default same + always mint a cap” granted 30s of unfiltered source-vault proxy to every filter, including body-only ones. |
| `allow_insecure_private_http: true` for non-loopback HTTP. Without it, HTTP is literal-loopback only. | Compose `http://filter:12345` still works; cleartext is an acknowledged tradeoff, not the default. HTTPS remains the normal path. Redirects disabled on the filter hop; IMDS / public / link-local still blocked. |
| **Shared** TTL capability state in the existing DB (token **hash**, atomic consume). Process-local map is a documented single-instance/dev backend only. | Sticky MITM is a footgun once `DATABASE_URL` means multiple processes. A write on the **filtered** path is acceptable (already an extra sidecar RTT); it must not appear on unfiltered Inject. |
| Split `*-Proxy` (URL, no secret) from `*-Token` (bearer). | Capability-in-URL leaks in access logs. |
| Policy cap cannot invoke **any** filtered service (not “skip that filter only”). | Nested filter hops would mint another capability. A git sidecar calling filtered OpenAI with the policy cap **fails**, rather than starting a second filter. |

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
- Per-request DB writes on the **unfiltered** Inject path.
- RFC 9457 Problem Details (existing `{error, message}` + `X-Agent-Vault-Proxy-Error`).
- `/discover`, agent skill, dashboard UI (unless a reviewer blocks without it), `--filter-*` flags, `vault service filter` subcommands.
- Binding the continuation to request-body bytes (packfiles must stream).

---

## Placement in the existing pipeline

Today (simplified):

authenticate → rate limit → **Inject (match + decrypt creds)** → substitutions → origin (or WebSocket dial).

**Unfiltered** services: unchanged, including WebSocket to origin. **No** capability-table write.

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
      url: https://policy.example.com/github-push
      policy_vault: policy          # optional; see modes below
```

| Field | Required | Meaning |
|---|---|---|
| `url` | yes if `filter` present | Sidecar origin. `https` by default. Literal-loopback `http` is allowed without a flag. Non-loopback `http` requires `allow_insecure_private_http: true`. |
| `policy_vault` | no | Vault the **policy capability** is scoped to. **Omitted = no policy capability** (filter decides from the intercepted request only). Set to the **source vault name** for Layout A. Set to a **different** vault for Layout B. |
| `allow_insecure_private_http` | no | Explicit opt-in for cleartext to a loopback or RFC1918 sidecar (`http://filter:12345`). Weaker than TLS; document it as such. |

`policy_vault` modes:

| Value | Policy capability | Use |
|---|---|---|
| omitted | none | Body/header-only decision. |
| source vault name | 30s cap on the source vault | Layout A: logic in front of the same creds. Must be written explicitly. |
| different vault name | 30s cap on that vault | Layout B. Configuring actor must be **vault admin of both**. |

Agent Vault does **not** constrain which *unfiltered* services live in the policy vault. Policy cap **cannot** invoke any **filtered** service (including the originator). Dual-admin only when the named vault differs from the source.

No `agent_id`. Nothing is minted into the agents table.

Clear on upsert: `filter: null` on **`vault service add`**.

Compose sidecar example:

```yaml
filter:
  url: http://filter:12345
  policy_vault: dev
  allow_insecure_private_http: true
```

Remote sidecars that must call back through Agent Vault also need **`AGENT_VAULT_FILTER_PROXY_URL`**: an `https` forward-proxy URL the sidecar can reach (literal-loopback `http` allowed). Local sidecars with no advertised URL use the process’s loopback MITM listener. Document in `.env.example` and the env-var tables when implemented.

---

## Who writes what (merge)

| Write | `filter` |
|---|---|
| Agent proposal that sets/clears `filter` | **Reject** (or ignore) the field. |
| Agent proposal that **deletes** a filtered service | **Reject.** |
| Agent proposal that updates auth/host of a filtered service | **Preserve** `filter`. |
| `vault service add` / POST upsert, field omitted | **Preserve.** |
| `vault service add` with `filter:` / `filter: null` | Set or clear. |
| `vault credential set` | Does not touch services. |
| `vault service set` (replace list) / `clear` | **Not preserved.** Document this. List output includes `filter` so round-trip is safe. |
| Interactive `service set` “Replace all” | Same as `set` (wipe). No wizard prompts for filter in v1. |
| Admin delete service | Allowed (explicit policy removal). |

Admin `vault service list` **must include** `url`, `policy_vault`, and `allow_insecure_private_http` when set. Never include capability material. Still omitted from `/discover`.

---

## Two capabilities (not the inbound agent token, not a filter-agent)

Do **not** forward the inbound `Proxy-Authorization` / agent A session to the sidecar. Do **not** create an agent row.

Both capabilities: random opaque tokens. **Production:** shared TTL rows in the existing database (store a **hash** of the token, expiry, kind, issued/claimed/consumed, initiating actor, vault scope, frozen non-secret match, exact URL bind). **No credential values.** Atomic conditional update claims/consumes a continuation **once** across replicas. Expired rows swept opportunistically and on a schedule.

**Development:** a process-local map with **identical semantics** is allowed only as an explicit single-instance optimization. It is not the production design.

Audit and rate-limit attribution stay the **initiating actor**.

This write happens only on the **filtered** path. Unfiltered Inject stays decrypt-and-forward with no capability row.

### 1. Continuation (per invocation, single-use)

Bound to `{method, scheme, authority, escaped path, query}` plus the **frozen CredentialMatch** (inbound vault, original actor for logs). Claim TTL **30 seconds**. Consumed by the **first exact matching** request, including inside CONNECT. Mutated URL or replay → fail closed.

Sidecar opens a **new** MITM request to that exact target with `Proxy-Authorization` = continuation token against `X-Agent-Vault-Continuation-Proxy`. Agent Vault verifies, consumes, **skips this service’s filter**, **Resolves the frozen match**, injects **those** destination credentials, forwards whatever body the sidecar sent.

Cannot retarget host (GitLab → GitHub). That path is the policy capability against a **different unfiltered** service in `policy_vault`.

A service YAML edit during the 30s window **cannot** change which credential is attached; the match object is the one from hop start.

Once consumed, origin body / first-header / WebSocket idle budgets apply. The 30s deadline does **not** kill an established stream.

### 2. Policy capability (only if `policy_vault` is set; 30s, reusable in-window)

Scoped to the named vault. Sidecar uses it for **side-channel** calls (protection API) and for **self-complete on a different unfiltered service**.

It **cannot**:

- spend the originating continuation’s destination credential;
- invoke **any** filtered service (originating or otherwise) — no nested filter, no second capability mint;
- outlive 30s.

It **can** use **unfiltered** services in that vault. Stolen same-vault policy cap can still hit other unfiltered write services for 30s; it **cannot** `git push` on `github-push` and **cannot** drive a filtered OpenAI hop. Layout B (read-only policy vault) removes the residual.

---

## Skip / deny on the way back

- **Continuation** (valid, exact URL, frozen match): skip **this** service’s filter, Resolve dest, forward.
- **Policy capability** matching **any** filtered service: **fail closed** (do not recurse, do not inject dest). Unfiltered services in scope proceed with normal Inject.
- Anything else on a filtered service: hop to the sidecar as usual.

---

## Reverse-proxy hop (Agent Vault → sidecar)

Treat `filter.url` as an **origin**. Preserve method, path, query, body (stream), and original `Host`. Overwrite (never trust client copies of) hop headers. **Secrets are not in URLs.**

| Header | Purpose |
|---|---|
| `X-Agent-Vault-Original-URL` | Exact original destination URL |
| `X-Agent-Vault-Continuation-Proxy` | Reachable MITM proxy **base URL**, no credentials |
| `X-Agent-Vault-Continuation-Token` | 30s single-use continuation bearer |
| `X-Agent-Vault-Policy-Proxy` | Optional policy proxy base URL, no credentials |
| `X-Agent-Vault-Policy-Token` | Optional 30s policy bearer |
| `X-Agent-Vault-CA` | Agent Vault MITM root (sidecar is not `vault run`) |
| `X-Agent-Vault-Service` | Matched service name |

The sidecar sends the matching token as `Proxy-Authorization` when using that proxy URL. Prefix matches `X-Agent-Vault-Proxy-Error`. All `X-Agent-Vault-*` are stripped before origin **and** from the sidecar’s response before it reaches the client. Tokens must not be logged or persisted.

**WebSocket:** reverse-proxy the upgrade and the byte stream to the sidecar (`Upgrade` / `Connection` preserved on **this** hop). Filter either rejects or opens a new WebSocket via the **exact continuation** and bridges. Continuation is consumed at successful upgrade; existing **10 min** WS idle governs the bridge. Unfiltered services keep today’s origin WS path.

**Timeouts:** origin hop budgets for TLS / first header / stream. Capability **claim** is 30s.

**Dial policy:** dedicated transport, **not** `AGENT_VAULT_ALLOW_PRIVATE_RANGES`.

- `https`: normal TLS verify; public allowed; IMDS still blocked.
- `http` to a **literal loopback IP**: allowed.
- `http` to any other name/address: requires `allow_insecure_private_http: true`, then **every resolved dial address** must be loopback or RFC1918; **redirects disabled**; public, link-local, and IMDS blocked; re-check the address on each connection.

**Hop failure** (dial, TLS, timeout, reset, capability mint/store failure): **502** (dial/TLS/reset/state) or **504** (timeout to first filter response header). Envelope: `Content-Type: application/json`, `{"error":"<code>","message":"..."}`, `X-Agent-Vault-Proxy-Error: true`. Codes: `filter_unreachable`, `filter_timeout`, `filter_misconfigured`. No dest Resolve, no origin.

**Sidecar success path:** copy status, headers (minus hop-by-hop / reserved broker headers / `Set-Cookie` policy as today), and body to the client. Any status. Agent Vault does not map “deny” to a fixed 403.

Bodies stream. A filter that consumes a non-replayable body must buffer/spool before claiming continuation.

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
| sidecar, allowed | new receive-pack via **continuation** | consume, Resolve frozen match, inject, GitHub |
| sidecar, protected | 403 (or any status) on the client hop | no dest decrypt, no origin |
| stolen policy cap → `git-receive-pack` | filtered service | **fail closed** (cannot spend dest; cannot invoke filtered services) |
| stolen policy cap → other **unfiltered** write service in `dev` | 30s residual | document this; prefer Layout B if unacceptable |

### Layout B — split vault (residual 30s blast gone)

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

A Layout A HTTP smoke (`TestSmoke_FilterLayoutA`, `make test-smoke`) exists for the **old** agent-based hop and must be rewritten against capabilities.

---

## Implementation seam (expected)

- `broker.Service`: `Filter` `{url, policy_vault, allow_insecure_private_http}`; URL + opt-in HTTP validation; no `agent_id`.
- `proposal.MergeServices`: preserve `filter`; never take `filter` from proposals; **reject delete** of a filtered service.
- `brokercore`: **Match** vs **Resolve**; frozen match on continuation; no dest decrypt on the filter path.
- Store: capability table (hash, TTL, kind, consume state, actor, vault, match, URL bind). Atomic claim/consume. No secrets. Optional in-memory backend for single-instance dev.
- `mitm`: reverse-proxy to `filter.url`; CONNECT claim; token vs proxy-URL headers; strip `X-Agent-Vault-*` both ways; dedicated dialer + private-HTTP flag; filtered WS reverse-proxy + continuation bridge.
- `server` / `cmd/server`: dual-admin if `policy_vault` differs; omit `policy_vault` → no policy cap; `AGENT_VAULT_FILTER_PROXY_URL`.
- CLI: none beyond YAML parse/print. Docs: file-only; `set`/`clear` wipe warning; Layout A residual; private-HTTP weaker than TLS.
- Tests: no dest decrypt on deny; single-use / exact URL / replay; retained match; dual-admin; omitted `policy_vault` mints no cap; policy cap cannot hit any filtered service; proposal preserve + no-delete; header overwrite; 502 on dead sidecar; WS unfiltered unchanged; filtered WS bridge; loopback HTTP vs flagged RFC1918 vs public HTTPS; multi-replica atomic consume (or store fake).

---

## Locked decisions (checklist)

1. Reverse-proxy to sidecar (not chained forward-proxy to the filter, not in-process).
2. Per matched service only.
3. Match without dest decrypt; Resolve only after continuation or on the unfiltered path. Frozen match in the continuation.
4. **No filter-agent.** Optional 30s policy capability + single-use continuation.
5. Continuation: exact method/scheme/authority/path/query; claim 30s; stream uses origin timeouts; body from sidecar; cannot retarget host.
6. `policy_vault` omitted = **no** policy cap. Source vault name = Layout A (explicit). Other vault = Layout B + dual-admin.
7. Policy cap cannot spend originating dest creds and cannot invoke **any** filtered service. Audit as initiator.
8. Fail closed on hop / capability failure. 502/504, existing JSON envelope.
9. `X-Agent-Vault-*` headers: Original-URL, Continuation-Proxy **and** Continuation-Token, optional Policy-Proxy/Token, CA, Service. Strip the namespace both directions. Tokens not in URLs.
10. `filter.url`: HTTPS default; loopback HTTP ok; non-loopback HTTP only with `allow_insecure_private_http` (RFC1918/loopback, no redirects, IMDS blocked). Dedicated dialer. Remote callback: `AGENT_VAULT_FILTER_PROXY_URL`.
11. Proxy WebSocket to the sidecar when the service has a filter; continuation consumed at upgrade.
12. Hidden from `/discover` / skill. Proposals cannot set, clear, or delete filters/filtered services.
13. Preserve on `service add` omit; wipe on `set`/`clear`. List prints `filter`.
14. YAML only (substitutions precedent).
15. Production capabilities are **shared DB TTL rows** (hash + atomic consume). Process-local is dev/single-instance only. No capability write on unfiltered Inject.
16. No RFC 9457 in this change.

---

## Upstream issue

https://github.com/Infisical/agent-vault/issues/407 — `RFC: per-service MITM request filter (out-of-process sidecar)`
