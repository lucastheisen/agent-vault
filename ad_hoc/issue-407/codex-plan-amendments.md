# Proposed amendments after Cursor's plan review

This document incorporates the substantive concerns in `cursor-reviews-codex.md` on `origin/issue-407-cursor` into a revised direction for the Codex policy-filter plan.

It is a design amendment, not an implementation claim. The current `issue-407-codex` implementation does not yet provide every item below.

## Decision

Keep the Codex capability architecture:

- match without decrypting destination credentials;
- exact, single-use continuations;
- original-match retention across configuration changes;
- no durable filter-agent credential;
- advertised callback address and CA for remote filters;
- administrator-only configuration and proposal protection.

Adopt the Cursor plan's product requirements where they do not weaken those boundaries: same-vault policy lookups, filtered WebSockets, sidecar-container reachability, explicit operator lifecycle semantics, and a concrete long-stream contract.

The critical new requirement is that capabilities must be shared across Agent Vault replicas. A process-local map is acceptable only for an explicitly single-instance development mode, not as the production design.

---

## 1. Policy-vault modes

`filter.policy_vault` has three explicit modes:

| Configuration | Policy capability | Intended use |
|---|---|---|
| omitted | none | A filter that makes its decision solely from the intercepted request. |
| source vault name | A short-lived capability scoped to the source vault | The simple “logic in front of the same PAT” deployment. |
| different vault name | A short-lived capability scoped to that vault | Recommended split-vault deployment for least privilege. |

The configuration remains administrator-only. A different policy vault requires the configuring actor to be an administrator of both vaults. Using the source vault requires only its existing administrator check.

The security boundary is preserved in both modes:

- the filter receives no durable agent token;
- the capability is short-lived and constrained to the configured vault;
- a policy capability cannot invoke any filtered service, including the originating service;
- the continuation is the only authority that can attach the originating request's matched destination credential.

Same-vault mode is intentionally less isolated: a stolen capability can call any *unfiltered* source-vault service for its brief lifetime. Documentation must say so and recommend a separate policy vault for a filter that needs only read-side credentials.

## 2. Filtered WebSockets

Filtered WebSocket upgrades are in scope for v1.

The initial upgrade is reverse-proxied to the filter before destination credentials are resolved. The filter either returns an ordinary rejection response or opens a new WebSocket through the exact continuation capability and bridges its own filter-side stream to that continuation.

The continuation retains the normal exact method/scheme/authority/path/query binding. Once the continuation is consumed at the successful upgrade, the bridged stream may run under the existing WebSocket idle timeout; the capability TTL does not terminate an established stream.

Unfiltered WebSockets keep their existing direct origin path. Filtered-WebSocket tests must cover denial, successful bridge, modified-target rejection, continuation replay, idle timeout, and reserved-header stripping.

## 3. Filter transport and sidecar-container HTTP

HTTPS remains the default and the only permitted remote transport unless an administrator explicitly opts into private cleartext HTTP for a local sidecar deployment.

Proposed service configuration:

```yaml
filter:
  url: http://policy:12345/gitlab-push
  allow_insecure_private_http: true
```

Without that explicit flag, HTTP remains valid only for a literal loopback IP. With the flag, every resolved dial address must be loopback or RFC1918 private space; public, link-local, and metadata-service addresses remain forbidden. Redirects are disabled for filter hops. The dedicated filter dialer must re-check the resolved address on each connection and always block cloud metadata endpoints.

This is an intentional operator tradeoff: capabilities cross a cleartext private network. Documentation must recommend HTTPS whenever the sidecar can leave the same trusted network boundary and describe the opt-in as weaker than HTTPS, not as equivalent protection.

## 4. Capability delivery and lifetime

Replace bearer URLs with a base proxy address plus dedicated headers:

| Header | Meaning |
|---|---|
| `X-Agent-Vault-Continuation-Proxy` | Reachable proxy base URL without credentials. |
| `X-Agent-Vault-Continuation-Token` | Opaque single-use continuation bearer capability. |
| `X-Agent-Vault-Policy-Proxy` | Optional proxy base URL without credentials. |
| `X-Agent-Vault-Policy-Token` | Optional short-lived policy bearer capability. |
| `X-Agent-Vault-CA` | MITM root certificate for a filter continuing HTTPS traffic. |
| `X-Agent-Vault-Target-URL` | Exact original target URL. |

The filter supplies these tokens as `Proxy-Authorization` when using the corresponding proxy URL. Keeping secrets out of URLs reduces accidental request-line and access-log exposure; the headers still require redaction.

Thirty seconds is the deadline to claim a continuation and the lifetime of a policy capability. It is not a wall-clock timeout for a request body or established HTTP/WebSocket stream. Once a continuation is atomically consumed by an exact request, normal origin and WebSocket timeouts apply.

## 5. Multi-instance capability state

Production continuations and policy capabilities must use shared, TTL-backed state rather than a process-local map.

Store a random-token hash, expiry, kind, issuance/claim/consumed state, initiating actor, vault scope, immutable non-secret service match, and exact request binding. An atomic conditional update claims and consumes the continuation exactly once. No credential value is stored in this state.

The existing database is the initial shared implementation. It permits a filter callback to reach any healthy Agent Vault replica while retaining single-use behavior. Expired rows are swept opportunistically and by scheduled cleanup. A single-instance in-memory backend may remain available only as a development optimization with the same semantics.

This per-filtered-request write is acceptable: filters are the deliberate policy-sensitive path, and correctness under HA is more important than avoiding the write.

## 6. Service mutation and proposal semantics

Document and test these rules:

| Operation | Filter behavior |
|---|---|
| Agent proposal: add or update | A supplied filter is rejected; an existing administrator-configured filter is preserved. |
| Agent proposal: delete filtered service | Rejected; the policy cannot be removed by an agent. |
| Admin upsert with filter omitted | Preserve the existing filter. |
| Admin upsert with `filter: null` | Explicitly clear the filter. |
| Admin full `set` / replace list | The submitted filter blocks are authoritative; list output must include them so an admin round trip does not silently remove one. |
| Admin delete service | Allowed and explicit. |

The public discovery and proposal surfaces continue to omit filters.

## 7. Operational contract and runbook

Add the following to the main plan and operator documentation:

- Filter-hop TLS/dial/connection-reset failures return `502`; filter response-header timeout returns `504`; neither path resolves destination credentials.
- Filter hops use origin-compatible body and response-header budgets; WebSocket streams use the existing idle timeout after upgrade.
- A Git example must show both same-vault and split-vault layouts, the unfiltered protection-API rule, clone/fetch non-matches, and the short-lived capability tradeoff.
- Reserved request and response headers are stripped at both Agent Vault trust boundaries.
- Remote filters require the advertised callback address and CA header; private HTTP requires explicit acknowledgement.

## Resulting v1 shape

```text
Agent
  -> Agent Vault: authenticate, rate limit, non-secret match
  -> Filter: original request + short-lived continuation/policy capabilities
       -> Agent Vault: policy calls with scoped capability
       -> Agent Vault: one exact continuation, then credential resolution
  -> Destination
```

This keeps the property that made the Codex plan preferable—no destination secret is read before policy permits it—while restoring the important product cases identified by Cursor: same-vault convenience, container sidecars, and filtered WebSockets. Shared capability state makes the result viable in a multi-replica deployment rather than only on a single proxy process.
