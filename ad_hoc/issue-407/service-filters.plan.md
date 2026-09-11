# Per-service HTTPS policy filters

Working design for an out-of-process HTTPS policy hop on the MITM proxy: after a service matches, Agent Vault sends the live request to an operator-configured filter before resolving the destination credential. The filter may return a final response or use a narrowly scoped continuation to allow the original request to proceed.

This file is a local working specification, not upstream documentation. Do not include `ad_hoc/` in a pull request. Operator-facing behavior belongs in `docs/learn/services.mdx` and the environment-variable reference.

Status: implemented on this branch; this plan describes that implementation for comparison with the Cursor design.

---

## Problem

Service matching today authorizes a destination and injects its credential as one operation. Some requests need policy logic before secrets are read: for example, a git-push guard must inspect the target ref and consult a protected-branches API before allowing `git-receive-pack`.

The policy logic must remain outside Agent Vault and must not receive either the destination credential or the initiating agent's long-lived proxy session. The required seam is:

```text
Agent -> Agent Vault -> policy filter -> Agent Vault -> destination
```

The filter needs two independent, short-lived authorities:

- an exact, single-use continuation for the one already-authorized destination request; and
- when configured, a separate policy-vault capability for API calls needed to decide.

## Non-goals (v1)

- In-process plugins, Go `.so` loading, WASM, or a rules language.
- Dynamic per-filter agents or permanent filter credentials.
- Agent proposals, discovery, agent skills, dashboard UI, or CLI flags that expose filters.
- Arbitrary remote cleartext HTTP; it is permitted only on a literal loopback IP.
- A new TLS listener in Agent Vault. Remote filters return through an existing HTTPS TLS terminator.
- Binding the continuation to request-body bytes or replaying consumed bodies.
- WebSocket upgrades on filtered services.

## Placement in the proxy pipeline

Today, in simplified form:

```text
authenticate -> rate limit -> match and resolve credentials -> substitutions -> origin
```

For an unfiltered service, this remains unchanged. For a filtered match:

```text
authenticate -> rate limit -> match (non-secret) -> filter -> exact continuation -> resolve -> origin
```

The `CredentialProvider` therefore splits matching from resolution. A `CredentialMatch` carries the matched service metadata and a private reference to the service, but no decrypted credential material. `Resolve` is called only after a valid continuation, or immediately for an unfiltered request.

This gives an explicit invariant: a denied or unreachable filter causes zero reads or decryptions of the destination credential.

## Operator configuration

`broker.Service` has an optional `filter` block:

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

| Field | Required | Meaning |
|---|---|---|
| `url` | yes | HTTP policy endpoint. Remote endpoints must be HTTPS; literal-loopback HTTP is allowed for a local sidecar. |
| `policy_vault` | no | Separate vault from which the filter receives a short-lived policy capability. |

The source-vault admin configuring `policy_vault` must also be a vault admin of that policy vault. The policy vault must be distinct from the source vault. This prevents a source-vault administrator from turning a separate vault into a credential oracle.

Filters are administrator-only configuration. Agent proposals reject a filter field. When a proposal updates an already-filtered service, merge preserves the existing filter; a proposal cannot delete a filtered service. These rules prevent agent-controlled configuration from weakening the policy boundary.

## Filter invocation

Agent Vault reverse-proxies the original method, ordinary headers, and streaming body to `filter.url` without resolving the destination credential. It strips client-supplied broker headers and sets these internal headers itself:

| Header | Purpose |
|---|---|
| `X-Agent-Vault-Target-URL` | Exact original destination URL. |
| `X-Agent-Vault-Continuation-Proxy` | Proxy URL containing a 30-second, single-use continuation capability. |
| `X-Agent-Vault-Policy-Proxy` | Optional 30-second policy-vault proxy capability. |
| `X-Agent-Vault-CA` | Base64-encoded Agent Vault MITM root certificate for HTTPS continuation clients. |

The filter may return any HTTP response, including a denial, directly to the agent. To allow the request, it sends a request through `X-Agent-Vault-Continuation-Proxy` to `X-Agent-Vault-Target-URL` and returns that response.

The filter may alter headers and body, but the continuation is bound to the original method, scheme, authority, escaped path, and query. It is claimed at proxy authentication and consumed by the first exact matching request, including inside CONNECT; modified requests and replay fail closed.

Agent Vault strips every `X-Agent-Vault-*` header before a request reaches a destination and before a response reaches the agent. The capability URLs are bearer secrets and must not be logged or persisted.

## Policy-vault capability

When `policy_vault` is set, Agent Vault resolves it only after verifying that the original session actor is authorized for the source vault and that the configuring administrator was authorized for both vaults. The resulting capability retains the initiating actor for audit and rate-limit attribution but changes its scope to the policy vault.

Policy capabilities are reusable only during their 30-second lifetime. They cannot invoke another filter, preventing recursive policy hops and capability-minting cycles. They are distinct from the destination continuation: a policy capability cannot spend the original request's credential authority.

## Transport and deployment

Filter URLs accept `https` and literal-loopback `http`. HTTPS uses the host trust store. Plain HTTP for a DNS name, hostname, private address, or public address is rejected.

For a local filter and no advertised callback address, Agent Vault creates the continuation URL from its loopback listener. A remote filter requires `AGENT_VAULT_FILTER_PROXY_URL`, which is an HTTPS forward-proxy address reachable by the filter. HTTP for that address is permitted only for a literal loopback IP. Deployments normally terminate TLS in front of Agent Vault's native HTTP proxy listener.

Bodies stream on both hops. A filter that reads a non-replayable body is responsible for buffering or spooling it before continuing. Filtered WebSocket upgrades are rejected; unfiltered WebSockets retain their existing path.

## Failure behavior

Filter parsing, policy-vault lookup, capability creation, and filter transport failures fail closed. Agent Vault returns a broker error and never resolves or attaches the destination credential. The filter's own HTTP response is returned unchanged except for hop-by-hop and reserved broker headers.

## Implementation seam

- `broker.Service`: optional `Filter` with URL and policy-vault validation.
- `brokercore`: split `Match` from `Resolve`; retain an immutable non-secret match in a continuation.
- `mitm`: create opaque in-memory capability tokens, proxy to the filter, enforce exact continuation consumption, and strip reserved headers in both directions.
- `server`: resolve policy-vault scopes and require admin rights on both vaults for filter configuration.
- `proposal`: reject new filters and preserve existing administrator-configured filters during agent proposal merges.
- `cmd/server`: parse `AGENT_VAULT_FILTER_PROXY_URL`.
- Docs and tests: describe the trust boundary; cover no-preresolution denial, request mutation/replay, TLS restrictions, cross-vault authorization, proposal preservation, and reserved header stripping.

## Locked decisions

1. Out-of-process reverse-proxy filter, not an in-process plugin or chained forward proxy.
2. Match before filter; decrypt or resolve destination credentials only after continuation.
3. Continuation is random, 30 seconds, single-use, and exact-request-bound.
4. Continuation retains the original match object, so a service reconfiguration cannot change the credential during the continuation window.
5. Policy lookups use an optional, separate vault capability; policy-vault services cannot filter recursively.
6. Admin rights are required on both source and policy vaults; the two vaults must differ.
7. Agents cannot propose, delete, replace, or strip filters.
8. HTTPS is required for remote filters and advertised remote proxy callbacks; cleartext HTTP is loopback-only.
9. All reserved broker headers are stripped at both trust boundaries.
10. Request bodies stream; filtered WebSockets are out of scope.

## Verification

- Unit tests verify that matching does not fetch credentials and that denied filters produce no credential reads.
- Proxy tests cover exact method/target matching, single-use continuations, CONNECT claiming, replay rejection, and retained-match behavior after configuration changes.
- Filter tests cover HTTPS delivery, loopback-only HTTP validation, policy-vault scoping, cross-vault authorization, recursion prevention, and header stripping in both directions.
- Proposal and server tests cover rejection/preservation of administrator-configured filters.
- Run `go test ./... -count=1`, `go vet ./...`, and `git diff --check`.

## Upstream issue

https://github.com/Infisical/agent-vault/issues/407 — RFC: per-service MITM request filter (out-of-process sidecar)
