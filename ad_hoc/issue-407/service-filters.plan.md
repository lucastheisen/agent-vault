# Per-service request filters

Working design for an out-of-process “servlet filter” hop on the MITM proxy: after a service matches, Agent Vault reverse-proxies the live request to an operator-configured URL instead of injecting credentials and forwarding to origin. The sidecar may short-circuit (any HTTP response) or complete the call through Agent Vault with a tight capability.

This file is a **local working spec**, not upstream docs. Canonical copy for Infisical: https://github.com/Infisical/agent-vault/issues/407. Do not include `ad_hoc/` in the pull request. After merge, operator-facing behavior belongs in Mintlify (`docs/learn/services.mdx`, CLI reference), not this plan.

Status: implemented against this spec. Local working copy; do not include `ad_hoc/` in the pull request.

---

## Problem

The broker matcher is host/path/port plus credential injection. Some policies need **arbitrary logic** on the request (inspect a git-receive-pack body, call GitLab’s protection API, maybe retarget GitLab → GitHub, maybe rewrite an OpenAI model) **before** secrets are attached.

That logic must not live in Agent Vault. The OSS seam is: match → hop to sidecar → sidecar decides.

Motivating example (not the only consumer): `git push` over HTTPS. Sidecar parses the target ref, asks whether the branch is protected, returns 403 or lets the push proceed with credentials attached.

---

## Non-goals (v1)

- In-process plugins, WASM, or a new rules language.
- Filter as a true chained HTTP forward-proxy (absolute-form / CONNECT to the sidecar). v1 is **reverse-proxy to `filter.url`**.
- RFC 9457 Problem Details (existing `{error, message}` + `X-Agent-Vault-Proxy-Error`).
- `/discover`, agent skill, or proposals exposing filters.
- Dashboard UI (unless a reviewer blocks without it).
- `--filter-*` CLI flags or `vault service filter` subcommands.
- `kind` column on agents.
- Per-service filter timeouts (reuse origin hop budgets; add later if needed).
- Binding the continuation ticket to the request body (packfiles must stream).

---

## Placement in the existing pipeline

Today (simplified):

authenticate → rate limit → **Inject (match + decrypt creds)** → substitutions → origin (or WebSocket dial).

With a filter on the **matched** service:

authenticate → rate limit → **match** (no inject yet) → reverse-proxy to `filter.url` → sidecar’s response is the client’s response.

Unfiltered services are unchanged, including WebSocket to origin.

Disabled service / no match: unchanged (403 / unmatched policy). Do not call the filter.

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
      vault: policy          # optional
```

| Field | Required | Meaning |
|---|---|---|
| `url` | yes if `filter` present | Sidecar origin (`http` or `https`). |
| `vault` | no | Vault the minted filter-agent is granted **proxy** on. **Default: the service’s vault.** May be the same vault (logic in front of the same creds) or another (different creds). Agent Vault does **not** constrain which services/credentials live there. |
| `agent_id` | server-filled | Link to the minted agent. Not typed by operators. |

Clear on upsert: `filter: null` (or equivalent empty) on **`vault service add`**.

---

## Who writes what (merge)

| Write | `filter` |
|---|---|
| Agent proposal | **Preserve.** Ignore or reject a `filter` field. Implementation detail. |
| `vault service add` / POST upsert, field omitted | **Preserve.** |
| `vault service add` with `filter:` / `filter: null` | Set or clear. |
| `vault credential set` | Does not touch services. |
| `vault service set` (replace list) / `clear` | **Not preserved.** Document this. |
| Interactive `service set` “Replace all” | Same as `set` (wipe). No wizard prompts for filter in v1. |

Admin `vault service list` **must include** `url` + `vault` so list→set round-trip does not drop filters. Never include token material. Still omitted from `/discover`.

---

## Filter-agent

Minted at **config time** (not per request). Visible in `agent list`. No `kind` field.

- **Name prefix** `filter-` (e.g. `filter-<vault>-<short-hash-of-url>`). `agent create` **rejects** that prefix.
- Instance role **no-access**; vault role **proxy** on `filter.vault`.
- Token stored **encrypted** (DEK), recoverable for the hop. Session hash alone is not enough.
- **Share by (`filter.url`, `filter.vault`)**: one agent and token for every service with that pair. First writer mints; later writers reuse `agent_id`. Last service to drop that pair revokes the agent. Changing URL or vault is a new pair (new or reused agent; old pair released if unused).

**Revoke** (`agent revoke`): fail **closed**. Filtered requests **502** until admin re-applies filter YAML and Agent Vault mints a new agent. Do not auto-remint on traffic. Do not clear the filter block.

---

## Two identities on the hop (not the inbound agent token)

Do **not** forward the inbound `Proxy-Authorization` / agent A session to the sidecar.

**1. Vault B token** (mint-at-config, long-lived)

Placed on the reverse-proxy hop as `X-Agent-Vault-Filter-Token`. Sidecar uses it like any instance-level agent token (`Proxy-Authorization` + `X-Vault` when needed) to:

- call other APIs (e.g. GitLab protection) through Agent Vault, and/or
- **complete the request itself** (e.g. push to GitHub with creds that live in `filter.vault`).

Power = whatever services exist in `filter.vault`. Operator choice.

**2. HMAC continuation ticket** (per invocation, no DB row)

Bound to `{filter, inbound vault, original actor for logs, method, host, path, expiry}`. Not a spare A session. Not a handle on the original body. Sidecar opens a **new** MITM request (same method/host/path) with this ticket as `Proxy-Authorization` → Agent Vault verifies HMAC, checks method/host/path, **skips the filter**, injects **inbound vault** credentials, forwards whatever body the sidecar sent.

Cannot retarget host (GitLab → GitHub). That path uses the vault B token and a **new** request.

Process-local HMAC key: in-flight tickets die on restart (fail closed). Fine.

---

## Skip the filter (no loops)

Do **not** reverse-proxy to the sidecar when:

1. Continuation ticket is valid, or
2. Caller is **that** filter-agent (`agent_id` for this URL+vault).

Skip is **not** global to every filter in the vault. A git filter-agent must not skip an unrelated OpenAI filter unless they share the same agent (same URL+vault).

Without a skip, “complete it myself” on the same matched route would recurse.

---

## Reverse-proxy hop (Agent Vault → sidecar)

Treat `filter.url` as an **origin**. Preserve method, path, query, body (stream; do not materialize for size), and original `Host`. Overwrite (never trust client copies of) hop headers:

| Header | Purpose |
|---|---|
| `X-Agent-Vault-Original-URL` | Full original URL (`https://github.com/…`) |
| `X-Agent-Vault-Filter-Token` | Mint-at-config token for `filter.vault` |
| `X-Agent-Vault-Filter-Nonce` | HMAC continuation ticket |
| `X-Agent-Vault-Service` | Matched service name (optional but useful) |
| Inbound vault / actor | Optional metadata, no secrets |

Prefix matches `X-Agent-Vault-Proxy-Error`. Token and nonce are **broker-scoped** (stripped before origin), like `X-Vault` and `Proxy-Authorization`.

**WebSocket:** reverse-proxy the upgrade and the byte stream to the sidecar (`Upgrade` / `Connection` preserved on **this** hop). Unfiltered services keep today’s origin WS path.

**Timeouts:** same as origin (TLS ~10s, ~5 min to first response header, then stream; WS idle 10 min).

**Dial policy:** dedicated transport, **not** the default upstream `AGENT_VAULT_ALLOW_PRIVATE_RANGES` guard (that blocks loopback by default and would break `http://127.0.0.1:12345`). Behavior: allow loopback, private, and public; keep existing **IMDS always-block**. Re-check that dialer on redirects. Normal TLS verify for `https`.

**Hop failure** (dial, TLS, timeout, reset): **502** (dial/TLS/reset) or **504** (timeout). Envelope: `Content-Type: application/json`, `{"error":"<code>","message":"..."}`, `X-Agent-Vault-Proxy-Error: true`. Suggested codes: `filter_unreachable`, `filter_timeout`, `filter_agent_revoked`. No inject, no origin.

**Sidecar success path:** copy status, headers (minus hop-by-hop / `Set-Cookie` policy as today), and body to the client. Any status (403, 200, 302, git error packet, …). Agent Vault does not map “deny” to a fixed 403.

---

## Straw-man configuration (git push / protected branch)

Motivating case for reviewers: intercept `git push` over HTTPS, parse the target ref, ask GitHub whether that branch is protected, write **403** on the client hop if so, otherwise attach credentials and forward.

The sidecar is a process listening on `:12345`. It is **not** a vault object. Operator YAML only names: which service matches the push, which unfiltered service lets the sidecar query protection, and (optionally) which vault the minted filter-agent may proxy as. Policy (which refs, how to parse receive-pack) lives in the sidecar.

clone/fetch (`git-upload-pack`) never match the push row. GitHub’s protection API is `api.github.com` — a **different**, unfiltered service.

What the operator does **not** type: filter-agent name, token, `agent_id`, `--filter-*` flags. Agent Vault mints a visible `filter-<vault>-<hash>` agent (instance `no-access`, vault `proxy`) and puts its token on the hop.

### Layout A — same vault (smallest)

Coding agent uses vault `dev`. One PAT. `filter.vault` omitted → minted agent is proxy on `dev`.

```bash
agent-vault vault credential set GITHUB_TOKEN=ghp_... --vault dev
agent-vault vault service add -f dev-services.yaml --vault dev
```

```yaml
# dev-services.yaml
services:
  # Unfiltered. Sidecar (and anyone with proxy on `dev`) uses this to
  # GET /repos/{owner}/{repo}/branches/{branch}/protection
  - name: github-api
    host: api.github.com
    auth:
      type: bearer
      token: GITHUB_TOKEN

  # Filtered. Only HTTPS git-receive-pack hits the sidecar.
  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: http://127.0.0.1:12345
```

| Who | Request | Match | What happens |
|---|---|---|---|
| coding agent | `POST https://github.com/acme/app.git/git-receive-pack` | `github-push` | hop to `:12345`, **no PAT**, no inbound agent token |
| sidecar, as filter-agent | `GET https://api.github.com/repos/acme/app/branches/main/protection` | `github-api` | inject `GITHUB_TOKEN`, GitHub |
| sidecar, allowed | new receive-pack with continuation ticket **or** re-issue as filter-agent (body from sidecar) | `github-push`, skip filter | inject `GITHUB_TOKEN`, GitHub |
| sidecar, protected | 403 (or any status) on the client hop | — | no inject, no origin |

**Stolen filter token in this layout can push.** It is proxy on `dev`, and `github-push` is in `dev`. Skip-filter exists so that agent does not recurse.

### Layout B — split vault (stolen filter token cannot push)

Same `filter:` object with `vault:` filled in. Inbound agent still uses `dev` (write PAT). Sidecar’s minted agent is proxy on `policy` (read-only PAT). Continuation ticket is how the **allowed** push still uses `dev`’s write creds.

```bash
agent-vault vault create policy
agent-vault vault credential set GITHUB_TOKEN=ghp_write_... --vault dev
agent-vault vault credential set GITHUB_READ_TOKEN=ghp_read_... --vault policy
```

```yaml
# dev-services.yaml — what the coding agent hits
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
# policy-services.yaml — what the sidecar is allowed to do
services:
  - name: github-api
    host: api.github.com
    auth:
      type: bearer
      token: GITHUB_READ_TOKEN
  # no git-receive-pack here
```

Minted agent: `filter-policy-<hash>`, **proxy on `policy` only**.

| Who | Request | Vault / creds |
|---|---|---|
| coding agent push | receive-pack → sidecar | no creds yet |
| sidecar protection lookup | `api.github.com` as filter-agent | `policy` / `GITHUB_READ_TOKEN` |
| sidecar allow | new request with continuation ticket, same method/host/path (body from sidecar) | skip filter, inject **`dev` / `GITHUB_TOKEN`**, GitHub |
| stolen filter token tries to push | no receive-pack service in `policy` | cannot attach the write PAT |

Retarget (GitLab → GitHub) is not this YAML. Continuation cannot change host. That path is “complete as the filter-agent against a service that lives in `filter.vault`.”

Layout A is the straw man. Layout B is the same shape with `vault:` set.

A local HTTP smoke of Layout A lives in-tree as `TestSmoke_FilterLayoutA` (`make test-smoke`; `//go:build smoke`). It is not real git / GitHub.

---

## Implementation seam (expected)

Small, localized:

- `broker.Service`: `Filter` struct; JSON omitempty; validation (`url` http(s)); strip secrets on public/admin marshal as needed.
- `proposal.MergeServices`: preserve `filter` when omitted; never take `filter` from proposals.
- `mitm/forward.go` (+ WS): after match, if filter → reverse-proxy; else existing Inject path.
- `brokercore`: match split from Inject or match-then-maybe-filter-then-Inject; HMAC ticket in `ResolveForProxy`; broker-scoped header names; filter hop transport.
- Store: mint/reuse/revoke filter-agent; persist wrapped token; no agents.`kind` migration.
- CLI: none beyond YAML parse/print. Docs: substitutions-style “file only”; `set`/`clear` wipe warning.
- Tests: merge preserve; hop headers overwrite; skip loop; 502 on dead sidecar; WS unfiltered unchanged; prefix reserved on create.

---

## Locked decisions (checklist)

1. Reverse-proxy to sidecar (not chained forward-proxy, not in-process).
2. Per matched service only.
3. No inject of origin creds before the hop; no inbound agent token to the sidecar.
4. Mint-at-config filter-agent; share by (`url`, `vault`); prefix `filter-`; visible; proxy on `filter.vault`; no `kind`.
5. HMAC continuation ticket for “new request on the same route, inbound vault creds”; vault B token for side channel / self-complete. Ticket does not store or resume the original body.
6. Skip filter for that agent and for a valid ticket.
7. `filter.vault` optional, default same vault, unconstrained contents.
8. Fail closed on hop failure and on agent revoke (until re-apply).
9. `X-Agent-Vault-*` headers; existing JSON error envelope; 502/504.
10. Any http(s) URL including loopback; IMDS still blocked; dedicated dialer.
11. Proxy WebSocket to the sidecar when the service has a filter.
12. Hidden from `/discover` / skill / proposals.
13. Preserve on proposals and `service add` omit; wipe on `set`/`clear`.
14. YAML only (substitutions precedent).
15. Reuse origin timeouts.
16. No RFC 9457 in this change.

---

## Upstream issue

https://github.com/Infisical/agent-vault/issues/407 — `RFC: per-service MITM request filter (out-of-process sidecar)`
