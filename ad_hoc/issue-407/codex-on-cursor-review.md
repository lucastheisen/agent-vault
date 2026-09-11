# Codex response to Cursor's plan review

Cursor's review correctly concludes that the original Codex plan is the stronger credential-broker security model, while identifying product and deployment gaps that would make the feature too narrow if left unchanged.

This document records the review of that review and the resulting updated plan. It supersedes the earlier Codex plan where they conflict. It is a local design document, not upstream documentation.

## Review of Cursor's review

### Findings accepted

Cursor correctly identified these strengths of the original Codex design:

- Matching must be separate from credential resolution so denial and filter-hop failure cause no destination credential read or decryption.
- A continuation must be single-use, short-lived, bound to the exact request, and retain the original match so a configuration edit cannot swap the credential during the continuation window.
- A durable configuration-time filter agent is a poor default. In particular, a filter token granted proxy access to the source vault can directly use its write credential.
- Cross-vault policy delegation requires administration of both vaults, and audit/rate-limit attribution should remain with the initiating actor.
- A remote filter needs both a reachable callback proxy address and the Agent Vault CA; a token alone is not a complete remote protocol.
- Proposals must not be able to remove a filtered service as an indirect way to bypass policy.

Cursor also correctly identified several gaps in the original Codex plan:

- It excluded filtered WebSockets even though a general service filter may need to govern upgraded traffic.
- Literal-loopback-only HTTP does not serve ordinary Docker Compose or Kubernetes sidecars.
- The plan lacked Cursor's useful service-mutation rules, concrete failure behavior, and operator runbook.
- Thirty seconds was not clearly stated as a capability-claim deadline rather than a duration limit on an established stream.
- A process-local capability map cannot support a multi-replica Agent Vault deployment, because a callback can arrive at another replica.

### Refinements to Cursor's proposed hybrid

The hybrid is the right direction, with three safety refinements:

1. **Same-vault capability is explicit, not implicit.**
   Omitted `policy_vault` means no policy capability. Naming the source vault opts into the convenience mode. This avoids silently granting a filter access to all unfiltered source-vault services.

2. **Private HTTP is explicit and narrowly scoped.**
   HTTPS remains the default. An administrator must acknowledge `allow_insecure_private_http: true`; then every resolved address must be loopback or RFC1918 private, redirects are disabled, and metadata/link-local/public addresses remain blocked. This supports container sidecars without presenting cleartext transport as equivalent to TLS.

3. **HA uses shared capability state, not a durable filter agent.**
   The existing database stores TTL-bound, non-secret capability state and supports atomic claim/consume. This preserves exact single use across replicas without adding a permanent principal or credential.

## Updated plan

### Goal

Provide a per-service out-of-process policy filter after non-secret service matching but before destination credential resolution:

```text
Agent -> Agent Vault -> filter -> Agent Vault -> destination
```

The filter may return any final HTTP response or make one exact continuation request. It may also make bounded policy API calls through an optional scoped capability.

### Core security invariants

1. Agent Vault does not read or decrypt the matched destination credential until an exact continuation is consumed.
2. A continuation is random, opaque, single-use, and valid for 30 seconds to be claimed.
3. It binds the original method, scheme, authority, escaped path, query, initiating actor, source vault, and immutable non-secret service match.
4. Once a continuation is consumed, normal origin body, response-header, and WebSocket idle limits apply. The 30-second capability deadline does not terminate an established stream.
5. Capabilities never carry credential values, and reserved `X-Agent-Vault-*` headers are stripped before origin and before the agent response.
6. Filter failures fail closed before credential resolution.

### Service configuration

```yaml
services:
  - name: gitlab-push
    host: gitlab.example.com/group/project.git/git-receive-pack
    auth:
      type: basic
      username: GITLAB_USERNAME
      password: GITLAB_PUSH_TOKEN
    filter:
      url: https://policy.example.com/gitlab-push
      policy_vault: gitlab-push-policy
```

`policy_vault` has these semantics:

| Value | Capability |
|---|---|
| omitted | None; the filter decides using the intercepted request only. |
| source vault name | Short-lived capability scoped to the source vault. This is convenience mode. |
| different vault name | Short-lived capability scoped to the named policy vault. This is recommended least-privilege mode. |

Different-vault configuration requires the caller to administer both vaults. Same-vault convenience remains bounded because the policy capability cannot invoke any filtered service, including the origin service. It can still call unfiltered source-vault services for 30 seconds, so documentation must describe the tradeoff and recommend a dedicated read-only policy vault where appropriate.

For a Compose or Kubernetes sidecar without practical TLS, an administrator may opt in explicitly:

```yaml
filter:
  url: http://policy:12345/gitlab-push
  allow_insecure_private_http: true
```

Without this flag, HTTP is allowed only to a literal loopback IP. With it, the dedicated filter dialer permits only loopback or RFC1918 targets, disables redirects, rechecks each resolved dial address, and blocks public, link-local, and metadata-service addresses. HTTPS remains the recommended deployment.

### Filter protocol

Agent Vault reverse-proxies the original method, ordinary headers, and streaming body to the filter before resolving destination credentials. It overwrites client-supplied control headers and adds:

| Header | Meaning |
|---|---|
| `X-Agent-Vault-Target-URL` | Exact original target URL. |
| `X-Agent-Vault-Continuation-Proxy` | Reachable proxy base URL without credentials. |
| `X-Agent-Vault-Continuation-Token` | 30-second single-use continuation token. |
| `X-Agent-Vault-Policy-Proxy` | Optional reachable policy proxy base URL. |
| `X-Agent-Vault-Policy-Token` | Optional 30-second policy capability token. |
| `X-Agent-Vault-CA` | Base64-encoded MITM root certificate for HTTPS continuation traffic. |

The filter supplies a token as `Proxy-Authorization` when using the corresponding base proxy URL. Tokens must be redacted from logs and never persisted by the filter. Separating bearer material from the URL reduces accidental access-log leakage.

The filter can return any response directly. To allow the request, it uses the continuation capability to make a new request to the original target. It may change headers or body, but any method, scheme, authority, escaped path, or query change rejects the continuation. The retained non-secret match is resolved only after this exact check.

### Policy calls and recursion

Policy capability requests retain the initiating actor for audit and rate-limit attribution but use the selected vault scope. They cannot invoke filtered services. This prevents recursive filter chains and prevents a same-vault policy capability from bypassing the originating filter.

### Filtered WebSockets

Filtered WebSocket upgrades are supported. The original upgrade is reverse-proxied to the filter. The filter either returns an ordinary rejection or opens a new WebSocket via the exact continuation and bridges its filter-side stream to that continuation. The continuation is consumed at the successful upgrade; the existing WebSocket idle timeout governs the bridge afterward.

Unfiltered WebSockets retain their existing origin path.

### Shared capability state

Production capability state is shared and TTL-backed. The database stores only a hash of the random token, expiry, capability kind, atomic issued/claimed/consumed state, actor, vault scope, immutable non-secret service match, and exact request binding. Atomic conditional updates claim and consume continuations once across replicas.

Expired state is swept opportunistically and by scheduled cleanup. A process-local backend may exist only as a single-instance development optimization with identical semantics.

### Configuration lifecycle

| Operation | Filter behavior |
|---|---|
| Agent proposal add/update | A supplied filter is rejected; an existing filter is preserved. |
| Agent proposal delete filtered service | Rejected. |
| Admin upsert omitting filter | Preserve existing filter. |
| Admin upsert with `filter: null` | Explicitly clear filter. |
| Admin full `set`/replace | Submitted filter blocks are authoritative; list output includes them for safe round trips. |
| Admin delete service | Allowed as an explicit policy removal. |

Filters remain hidden from discovery and agent-proposal surfaces.

### Failure and verification

Filter dial, TLS, reset, policy-capability, and shared-state errors return `502`; filter response-header timeout returns `504`. Neither path resolves the destination credential. Filtered requests use origin-compatible streaming and response budgets; successful WebSockets use the existing idle timeout.

Tests must cover no-preresolution denial, exact continuation consumption and replay, configuration TOCTOU, cross-vault admin checks, same-vault recursion prevention, remote callback and CA delivery, private-HTTP opt-in address checks, filtered WebSocket bridging, proposal lifecycle semantics, reserved-header stripping, and multi-replica atomic capability use.

## Conclusion

This amended design keeps the original Codex boundary—no destination secret use before policy approval—while covering the product cases Cursor correctly called out. It avoids the Cursor plan's durable source-vault filter principal and replayable HMAC continuation, and it replaces the original Codex plan's process-local capability limitation with a replica-safe shared-state design.
