# Per-service request filters

This file is the implementation contract for per-service MITM request filters.
After a service matches, Agent Vault reverse-proxies the live request to an operator-configured URL without resolving destination credentials.
The sidecar may return any HTTP response, or continue through Agent Vault with short-lived JWTs.

This is a local working spec, not upstream docs.
Canonical issue: [RFC: per-service MITM request filter](https://github.com/Infisical/agent-vault/issues/407).
Do not include `ad_hoc/` in the pull request.

## The seam

This is the design.
Later sections specify tokens, validation, and tests.
They do not add a second access-control plane.

Rows 1 and 2 are today's broker.
Rows 3 and 4 are the hop.
Rows 5 and 6 are the continuation.

A continuation is minted on the hop (rows 3 and 4).
It records two things.
Neither is the destination secret or the request body.

**Bind.** The identity of the request the sidecar saw: method, scheme, authority, escaped path, and raw query.
Rows 5 and 6 compare the inbound request to that bind, byte for byte.
The sidecar may send a new body.
It may not change the URL.
A changed path is row 6, not a rewrite to the old path.

**Frozen match.** Which service won, and the non-secret inject shape (auth type, key names, substitutions).
Row 5 uses that to Resolve.
It does not run Match again.

| | When | What happens |
| --- | --- | --- |
| 1 | No service matches | Honor the vault's `unmatched_host_policy`. Same for an agent token or a policy token. |
| 2 | Match, no `filter` | Inject the destination credential and forward. Same for an agent token or a policy token. |
| 3 | Match, `filter` set, `policy_vault` omitted | Do not Resolve. Mint a continuation. Reverse-proxy the live request to `filter.url` with that continuation, the callback proxy URL, and the CA. No policy token. |
| 4 | Match, `filter` set, `policy_vault` set | Do not Resolve. Mint a continuation. Mint a policy token for the vault that field names. Reverse-proxy the live request with both tokens, the callback proxy URL, and the CA. |
| 5 | Continuation, bind still holds | Skip the sidecar. Resolve the frozen match. Inject onto this inbound request. Forward. |
| 6 | Continuation, bind does not hold | Do not rewrite the URL, inject, or forward. Respond 403 (or 400), not 500. The JWT stays valid until `exp`. |

A disabled service is today's deny.
That is not a hop.

## Problem

Today a service is: this host, path, and port get this credential.
That is all the matcher can do.

Some policies need to look at the actual request first, while the destination secret is still locked.
Examples: read a git push body to see the branch, call GitHub's protection API, send the call to a different host, or change an OpenAI model name.

Agent Vault cannot ship a rules engine complete enough for those cases.
A filter might need the first 100 bytes of the body, or an external API call whose URL comes from a query param.
That is the consumer's policy, not the broker's.

Agent Vault's job is to keep credential management, and to offer a seam so a downstream consumer can run that logic anyway.
A Java servlet-style request filter is that seam:

1. Match the service (no decrypt).
2. Hop the live request to the sidecar.
3. The sidecar decides: reject, rewrite, or continue.

The straw man (not the only consumer) is HTTPS `git push`.
The sidecar sees `git-receive-pack`, checks whether the branch is protected, and either returns 403 (secret never used) or continues so Agent Vault can attach the PAT and talk to GitHub.

## Non-goals

- In-process plugins, WASM, Go `.so`, or a new rules language.
- A second client-facing proxy.
  Clients keep talking to Agent Vault.
  How the vault calls the sidecar, and whether the sidecar calls back, is specified in [section 4](#4-continuation-and-policy-tokens) and [section 7](#7-the-reverse-proxy-hop).
- The sidecar is not an Agent Vault agent and does not get a long-lived token.
  How it may call back is specified in [section 4](#4-continuation-and-policy-tokens).
- RFC 9457 Problem Details.
  A nicer error shape, but not how Agent Vault reports proxy errors today.
  This change does not adopt it.
  The existing envelope is specified in [section 7](#7-the-reverse-proxy-hop).
- A dashboard, `--filter-*` flags, or a `vault service filter` subcommand.
  Admin YAML is enough for v1.
- Changing global matcher semantics.
  Which service wins a request stays as it is today.
  How proposals may not shadow a filtered service is specified in [section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher).
- Changing how ordinary unfiltered CONNECT tunnels are revoked.
  `agent revoke` still takes effect on the next CONNECT, not an already-open one.
  Hop JWTs are not a denylist either.
  That is specified in [section 4](#4-continuation-and-policy-tokens).
- A TTL flag or env override.
  Hop tokens last 30 seconds, specified in [section 4](#4-continuation-and-policy-tokens).
  Making that configurable is out of this change.

## 1. Placement in the pipeline

The request path is [The seam](#the-seam).
This section only states when the destination secret is opened.

Today every proxied request does this:

authenticate -> rate limit -> Inject (match the service and decrypt the dest secret) -> maybe substitutions -> origin (or a WebSocket).

Unfiltered services stay on that path (seam row 2).
No sidecar, no hop JWT.
If the filter machinery is down, ordinary proxying must still work.

Filtered services split Inject in two (seam rows 3 and 4):

authenticate -> rate limit -> Match (which service? no decrypt) -> hop the live request to `filter.url` -> whatever the sidecar returns is what the client sees.

Decrypt (Resolve) happens only later, if the continuation bind holds (seam row 5), or immediately on the unfiltered path as today.

If the sidecar says no, times out, or cannot be reached, Agent Vault must not have opened the dest secret at all.
A 403 that still decrypted the PAT in the background is a failed design.

A disabled service or no match is unchanged (seam rows 1 and today's deny).
Do not call the sidecar.

Fail-closed errors, required Match/Resolve interfaces, and how tests prove the no-decrypt invariant are specified in [section 5](#5-enforcement-is-mandatory) and [section 10](#10-tests).

## 2. Config

`filter` is an optional block on `broker.Service`.
Operators write it in service YAML, the same way they write substitutions.
There is no dashboard, flag, or `vault service filter` subcommand.

```yaml
services:
  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: https://policy.example.com/github-push
      policy_vault: policy
```

| Field | Required | Meaning |
| --- | --- | --- |
| `url` | yes if `filter` present | Sidecar origin. `https` normally. Literal-loopback `http` is allowed without a flag. Non-loopback `http` requires `allow_insecure_private_http: true`. |
| `policy_vault` | no | Vault the policy token is scoped to. Omitted means none. Why you would name the source vault or another vault is explained in [section 2.1](#21-choosing-policy_vault). |
| `allow_insecure_private_http` | no | Opt-in for cleartext HTTP to a private sidecar that is not a literal loopback IP. Literal loopback HTTP does not need it. Weaker than TLS. Document it as such. |
| `ca` | no | PEM certificate(s) used as the only TLS roots for this hop. Omit it when `https` uses a public CA. Pin it when the sidecar is a compose or other private name with a self-signed cert. |

The named policy vault is an ordinary vault.
Agent Vault does not constrain which services live there.

Clear the block with `filter: null` on `vault service add`.
Who may set or clear it, and how YAML `null` survives JSON, is specified in [section 3](#3-who-may-change-a-filter).

A Compose sidecar on the same Docker network is not loopback.
Prefer HTTPS and pin the sidecar CA.
YAML anchors may repeat that PEM across many filters in the operator file.
Agent Vault stores an expanded copy on each service and does not provide a named CA catalog.
`vault service list` prints the expanded PEM.

```yaml
services:
  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: https://filter:12345
      policy_vault: dev
      ca: &sidecar_ca |
        -----BEGIN CERTIFICATE-----
        (sidecar CA PEM)
        -----END CERTIFICATE-----
  - name: openai
    host: api.openai.com
    auth:
      type: bearer
      token: OPENAI_KEY
    filter:
      url: https://filter:12345
      policy_vault: dev
      ca: *sidecar_ca
```

Cleartext HTTP on that network remains available with `allow_insecure_private_http: true` and no `ca`.

### 2.1 Choosing `policy_vault`

Omit it for a body-or-headers hop (seam row 3).
Set it to mint a 30-second policy token for that vault (seam row 4).
The hop does not change based on which name you write.
The choice is what that token can reach.
Worked YAML is in [section 8](#8-layouts).

**Name the source vault** when the sidecar should call other services in the same vault (the GitHub protection API next to the push row).
Write the name explicitly.
Omit is not this.

**Name a different vault** when you want that extra access on a smaller vault (read API only).
The person writing the config must be vault admin of both.

A holder of the policy token can use the named vault the way the agent can, until the hop ends or 30 seconds.
Pick the smaller vault if that residual is too wide.

### 2.2 `filter.url` and `ca`

The URL must be absolute `http` or `https` and must include a host.
A path prefix is allowed.
The original request path and query are appended after that prefix.

Reject:

- userinfo (it would smuggle sidecar credentials past `allow_insecure_private_http`, and secrets are not in URLs)
- a fragment
- a configured query or `ForceQuery` (the hop replaces the query with the original request query, so leftover query is unused and can hide secrets in config and logs)
- any scheme other than `http` or `https`
- non-loopback `http` without `allow_insecure_private_http: true`
- `ca` on an `http` URL
- empty, non-PEM, or private-key material in `ca`

When `ca` is set, the value must parse as at least one `CERTIFICATE` PEM.
The hop verifies using only those roots, not the system pool.
The URL hostname must match the certificate.
There is no `ca_file`, `tls_server_name`, or skip-verify flag.

### 2.3 `AGENT_VAULT_MITM_ADDR`

This is the MITM analogue of `AGENT_VAULT_ADDR`.
It does not bind a listener and is not checked against `--host` or `--mitm-port` at startup.
It is the URL advertised for the proxy door: hop headers, and `vault run`'s `HTTPS_PROXY` when set.
The hostname is a SAN on MITM leaf certs when clients TLS-verify the proxy's own name (same role `AGENT_VAULT_ADDR` has today).
It is not filter-specific except that hop headers carry it.

It must be a base URL: scheme `http` (the MITM is a plain HTTP proxy), host, optional port, no userinfo, path, query, or fragment.
An explicit invalid value is fatal at startup so hops never advertise junk.
A mismatch with `--host` is not fatal.
Clients that trust the advertised URL fail to connect, same as a wrong `AGENT_VAULT_ADDR`.

Unset: hostname from `AGENT_VAULT_ADDR`, port from the MITM listener, scheme `http`, matching `vault run` today.
If `AGENT_VAULT_ADDR` is unset, or its host is missing or a wildcard (`0.0.0.0`, `::`), advertise loopback.
Compose with only `AGENT_VAULT_ADDR=http://agent-vault:14321` still yields `http://agent-vault:14322`.
Set `AGENT_VAULT_MITM_ADDR` when the proxy must be advertised under a different name than the control plane (public UI vs docker DNS).

Document in [`.env.example`](../../.env.example), [environment variables](../../docs/self-hosting/environment-variables.mdx), and the env table in [CLI reference](../../docs/reference/cli.mdx), next to `AGENT_VAULT_ADDR`.

## 3. Who may change a filter

| Actor | Action | Outcome |
| --- | --- | --- |
| Agent | Proposal that sets or clears `filter` (object or `null`) | Reject 400 |
| Agent | Proposal that deletes a filtered service | Reject at create and apply |
| Agent | Proposal whose effective `set` matcher can win or tie an existing filtered matcher | Reject 400 at create, 409 at apply ([section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher)) |
| Agent | Proposal that updates auth or host of a filtered service and keeps that service's filter | Preserve `filter` |
| Agent | Proposal with `enabled: false` on a filtered service | Allow |
| Admin | `vault service add` / POST upsert, `filter` omitted | Preserve |
| Admin | `vault service add` with `filter:` or `filter: null` | Set or clear |
| Admin | `vault credential set` | Does not touch services |
| Admin | `vault service set` (replace list) / `clear` | Not preserved. Document this. |
| Admin | Interactive `service set` "Replace all" | Same as `set` (wipe). No wizard prompt for filter in v1. |
| Admin | Delete service | Allowed |
| Admin | YAML or upsert of an overlapping unfiltered exception | Allowed |

An explicit `filter` key in proposal JSON, including `filter: null`, is 400.
Silently dropping the unknown key is not enough.
The agent would believe it had configured a policy hop.

`enabled: false` on a filtered service is fail-closed denial (`ErrServiceDisabled`), not a bypass.
Delete is rejected because it can drop the request to unmatched-host passthrough.
Disable does not.
Document that asymmetry.

`vault service add` with omitted vs explicit-null both decode to a nil pointer in ordinary JSON.
Key presence must survive YAML -> JSON -> API (`FilterOp`).

Admin `vault service list` must include `url`, `policy_vault`, `allow_insecure_private_http`, and `ca` when set.
A list-then-set round trip must not silently strip a filter.
Never print hop JWTs.

The filter block is operator-only.
`/discover` and the agent skill omit it.
Proxy-role callers read services without the filter block, matching `/discover`.

### 3.1 Proposals cannot shadow a filtered matcher

`MatchScore.Better` ranks host tier, then port specificity, then path literal length.
It ignores declaration order.

An agent can propose unfiltered `github.com/acme/app.git/git-receive-pack` over an admin's filtered `github.com/*/git-receive-pack`, reference a PAT already in the vault, and win the match.
The filter never runs.
The human approving the proposal sees "add a service".

Rule: at proposal create, and again at apply against then-current config, reject a proposed effective service that is unfiltered and whose matcher can win or tie an existing filtered service for any request.
Create returns 400.
A conflict introduced between create and apply returns 409 and the proposal is not applied.
The error names both the proposed and the filtered service.

The comparison runs on the effective merge.
Updating a filtered service in a way that preserves its filter is not rejected.
Normalize inline host, path, and port forms first.

Implement a reusable overlap helper using real matching semantics:

- Host languages overlap for equal exact hosts, equal one-label wildcards, or an exact host matched by the other's one-label wildcard.
- Port languages overlap when explicit ports agree or either side omits a port.
- Path languages overlap per the existing `*` glob language.
  Use an exact intersection (DP or NFA), not a string-prefix approximation.
- On a shared witness request, compare the real priority tuple (host tier, port specificity, literal path-prefix length).
  Reject when the proposed tuple is better or equal.

Equal priority is rejected so safety does not depend on declaration order or later serialization.

This restriction is proposal-only.
A vault admin may still author an overlapping unfiltered exception through YAML or direct upsert.
Do not change `MatchScore` so that any overlapping filtered matcher always hops.
That would remove deliberate admin exceptions and change semantics for unfiltered traffic.

## 4. Continuation and policy tokens

A filtered hop may mint two JWTs: a continuation, and if `policy_vault` is set, a policy token.

They are compact JWS (`HS256`).
The wire form is a prefix plus that compact serialization, following `av_sess_` / `av_agt_`:

- `av_cont_`: continuation
- `av_pol_`: policy token

Distinct prefixes let ingress dispatch without "try a session, then a JWT".
They also give log redaction a stable match.

Sign with an HMAC key derived from the in-memory DEK (HKDF, info `agent-vault hop jwt v1`).
Every replica that shares the DEK can verify.
Do not persist that HMAC key.
Do not add a hop-token table, denylist, or FSM.

No credential values in claims.
No raw agent or session tokens in claims.

Audit and rate-limit attribution stay with the initiating actor, not the sidecar.
Minting happens only on the filtered path.

Every filtered hop also receives a random, non-authorizing `invocation_id` claim.
The continuation and optional policy JWT share it.
It is correlation metadata for logs.
It is never a bearer.

Hop JWTs authorize the MITM data plane only.
They are accepted only as proxy credentials.
They are never bearer sessions on `/discover`, proposals, vault administration, or any other control-plane endpoint.
Their effective vault role is always `proxy`.
Never copy an initiating actor's `member`, `admin`, or instance-level authority into hop-JWT scope.

### 4.1 Continuation

Bound in claims to `{method, scheme, authority, escaped path, raw query}` plus the frozen match.
Escaped path and raw query are compared verbatim.
Two different wire requests can decode to the same path.
Only one of them is the request the filter saw.

The sidecar opens a new MITM request to that exact target.
It sends `Proxy-Authorization` set to the continuation JWT against `X-Agent-Vault-Continuation-Proxy`.
Agent Vault verifies signature and `exp`, checks the bind, skips this service's filter, Resolves the frozen match, injects those destination credentials, and forwards whatever body the sidecar sent.

A continuation cannot retarget the host.
Retargeting (GitLab to GitHub) is a new request with the policy token (seam rows 1 through 4).

`exp` is 30 seconds from mint.
After a successful bind, ordinary origin body, first-header, and WebSocket idle budgets apply.
The 30-second deadline does not kill the established stream.

The JWT stays valid until `exp`.
A failed bind rejects that request and does not invalidate the token.
A second matching request in the window also succeeds.
That is the JWT tradeoff versus a single-use row.

### 4.2 Bind check at admission

On CONNECT, verify signature, `exp`, kind, and bound authority before hijack, leaf mint, or tunnel setup, so a real HTTP status can still be written.
On absolute-form HTTP, verify the full bind before processing that request.

Without the authority check, a stolen continuation admits a tunnel to any host.
Agent Vault would mint a leaf certificate before the method and path bind is compared.
That is a cert-minting and tunnel-resource oracle, even though the inner request still fails before an origin dial or credential attachment.

Wrong authority: 403 (or 400), no hijack.
Wrong method, scheme, escaped path, or raw query on the inner request: 403 (or 400), no inject, no origin.

Resolve is permitted only after the full bind holds.

### 4.3 Policy token

Exists only when `policy_vault` is set.
Claims carry that vault's immutable id.
Retain the name only for display and audit.
A rename does not retarget it.
A deleted vault fails closed at verify (lookup by id).

Used for side-channel calls and for a new request to a different service.
That new request follows [The seam](#the-seam) in the named vault, including a filtered hop.

It cannot spend the originating continuation's destination credential by itself.
It cannot outlive 30s.

A policy token is a short lease of the initiating actor on the named vault.
It honors that vault's `unmatched_host_policy`.
It is not a second access-control plane.

Policy CONNECT uses the same pre-hijack rules as an agent session in that vault.
Continuation CONNECT still binds authority before hijack ([section 4.2](#42-bind-check-at-admission)).

A holder of the policy token can use the named vault the way the agent can, until `exp`.
Naming a smaller vault shrinks that.
See [section 2.1](#21-choosing-policy_vault).

`agent revoke`, session expiry, user deactivation, and grant removal do not cut an already-minted hop JWT.
Wait out `exp`.
Do not add a denylist in this change.

### 4.4 Lifetime

Thirty seconds is the lifetime.

There is no hop-token row to revoke.
There is no denylist.
Source session expiry, agent revoke, user deactivation, and grant removal do not invalidate already-minted hop JWTs.

That is weaker than a DB FSM, and the same class of window as waiting out 30s after a leak.
It is also the same class of window as an unfiltered CONNECT that is already open: `agent revoke` takes effect on the next CONNECT, not inside an established tunnel.
Do not widen ordinary CONNECT revocation in this change.
Do not make hop JWTs stricter by adding a denylist.

### 4.5 Claims and signing

Compact JWS, `HS256`.
Wire form: `av_cont_` or `av_pol_` concatenated with the compact serialization.

| Claim | Notes |
| --- | --- |
| Kind | Continuation or policy. |
| `iat`, `exp` | `exp` is `iat` plus 30 seconds. |
| `invocation_id` | Random, non-authorizing, shared by the pair. Logs only. Never a bearer. |
| Source vault id | |
| Initiating actor id | Audit. Not used to re-check sessions on each spend. |
| Exact request bind | Continuation only: method, scheme, authority, escaped path, raw query. |
| Frozen match envelope | Continuation only. See [section 4.6](#46-frozen-match). |
| Policy vault id | Policy only. Immutable id. |

Do not put credential values, raw tokens, or `Filter` in claims.

Verify: prefix, HMAC, `exp`, kind, then bind or policy-vault lookup.
Unknown envelope version, malformed claims, or a vault id that no longer exists fails closed before any credential-store read.

The signing key is derived from the DEK already in memory after unlock.
Do not store hop JWTs.
Do not hash them into the sessions table.

### 4.6 Frozen match

The match travels as a versioned, non-secret projection inside the continuation JWT.
Agent Vault reconstructs an immutable match at verify time.
It must not re-run service matching against current mutable config.
It must not include `Filter`.
A continuation must never re-enter the hop.

Do not serialize raw `broker.Service` JSON if that would include `Filter`.
Use a dedicated projection.

Contents are everything Resolve needs, and nothing used only to decide whether to enter the filter:

| Field | Notes |
| --- | --- |
| Envelope format version | Read and validated first, before the payload is decoded. |
| Canonical matched service | name, host, path, port |
| Complete non-secret auth shape | `type`, header name, prefix, and the whole `custom.headers` template map. Credential references stay key names. |
| Complete substitution shape | each `key`, `placeholder`, and `in` surfaces |

Decode in two stages: validate the envelope version, then decode that version's typed payload.
Unknown version, unknown required semantics, malformed or incomplete data, credential-key disagreement, or invalid service config all fail closed before any credential-store read.
Bump the version whenever a field that affects injection is added.
`encoding/json` drops unknown fields silently, so a mixed-version token would otherwise resolve a subtly different request.

Operator-authored `custom.headers` templates are arbitrary text and may contain literals, exactly as they already may in `broker_config.services_json`.
Claims are not a secret store.
Do not claim a JWT can prove such literals are non-secret.
Never put credential values in claims.

If the credential provider cannot Resolve from a frozen snapshot, fail closed.
No fallback to live Inject or re-match.

| Admin change during the window | Continuation |
| --- | --- |
| Host, path, name, auth key, or substitutions | Frozen. Cannot retarget the slot. |
| Credential value (`vault credential set KEY=...`) | Not frozen. Resolve uses the current value for the frozen key. |
| Filter block | Irrelevant. Continuation does not re-enter the filter. |
| Key deleted from the vault | Fail closed, no origin. |

### 4.7 Minting

Resolve the policy-vault scope first (immutable id, existence).
Mint both JWTs in memory with the same `invocation_id`.
No database transaction.
No rows.

If the sidecar is unreachable, times out, rejects without using the continuation, fails its WebSocket upgrade, or the filtered stream ends, leftover JWTs expire unused.
There is nothing to `DELETE`.

The sidecar contract is synchronous.
Returning its final response means the decision is complete.
The sidecar must not keep using a policy token for asynchronous work afterwards.
Agent Vault cannot enforce that without a denylist.
`exp` is the bound.

### 4.8 Rate limits and request logs

The initiating filtered request is charged once under the initiating actor and source vault.
Each continuation MITM admission is also charged.
A leaked continuation must not become a 30-second rate-limit bypass.
Policy-token calls are new outbound requests.
They are rate-limited normally under the initiating actor and policy vault.

Logging follows the same distinction:

- The initial filter-hop row records matched service identity but no credential keys, because no credential was resolved.
- The continuation origin row is attributed to the initiator and records the frozen service and key names that were actually resolved, correlated through the non-secret `invocation_id`.
- Policy calls are attributed to the initiator in the policy vault and record their own matched service and key names.
- Raw session tokens, hop JWTs, and credential values never enter logs, spans, metrics labels, or error text.

## 5. Enforcement is mandatory

Match, frozen-match resolution, hop-JWT mint and verify, and policy-vault lookup are required.
Never guard them with an optional type assertion that means "skip the check when absent".
Test doubles must implement the same Match/Resolve surface as production.

Any error from Match, JWT mint or verify, snapshot decode, or policy-vault resolution fails closed.
A Match error must never fall through to ordinary Inject.
A continuation must never fall back to a live re-match if frozen resolution is unavailable.

A service configured with a filter, on a proxy with no filter engine, returns `502 filter_misconfigured`.
"Cannot run the policy" must never resolve to "skip the policy".

## 6. Skip or deny on the way back

This is [The seam](#the-seam) rows 3 through 6.

- Continuation, bind holds: skip this service's filter, Resolve the frozen match, inject onto this request, forward.
- Continuation, bind does not hold: 403 (or 400), no inject, no forward.
  The JWT stays valid until `exp`.
- Filtered match, not a holding continuation: hop (agent session or policy token).

## 7. The reverse-proxy hop

Agent Vault calls the sidecar as an origin, the way a servlet container calls a filter.
That is an ordinary HTTP request to `filter.url`, not CONNECT or absolute-form proxy language to the sidecar.

The sidecar is not required to call back through Agent Vault.
It may short-circuit or use its own credentials.
If it wants vault-managed secrets, it may use Agent Vault's existing MITM as a client ([section 4](#4-continuation-and-policy-tokens)).

Treat `filter.url` as an origin.
Preserve method, path (joined with any `filter.url` path prefix), original request query, streaming body, and the original `Host`.
Overwrite hop headers.
Never trust client copies of those headers.
Secrets are not in URLs.

### 7.1 Hop headers

Ordering is strip-then-set.

Before the sidecar request, delete untrusted headers ([section 7.2](#72-destination-credential-header-slots)), then set:

| Header | Purpose |
| --- | --- |
| `X-Agent-Vault-Original-URL` | Exact original destination URL. |
| `X-Agent-Vault-Continuation-Proxy` | Reachable MITM proxy base URL, no credentials. |
| `X-Agent-Vault-Continuation-Token` | 30s continuation JWT (`av_cont_...`). |
| `X-Agent-Vault-Policy-Proxy` | Optional policy proxy base URL, no credentials. |
| `X-Agent-Vault-Policy-Token` | Optional 30s policy JWT (`av_pol_...`). |
| `X-Agent-Vault-CA` | Agent Vault MITM root, base64. The sidecar is not `vault run`. |
| `X-Agent-Vault-Service` | Matched service name. |

The sidecar sends the matching token as `Proxy-Authorization` when using that proxy URL.
Tokens must not be logged or persisted.

On the sidecar response, strip its reserved namespace first, then set Agent Vault's own `X-Agent-Vault-Proxy-Error` on hop-failure envelopes.
Otherwise the strip rule eats its own header.

On the continuation request to origin, strip `X-Agent-Vault-*` again.
That request is assembled by a sidecar that was just handed hop-JWT headers.

### 7.2 Destination credential header slots

Before sending to `filter.url`, derive the header names the frozen service would overwrite during Resolve.
This is computable with no credential read:

- bearer / basic -> `Authorization`
- api-key -> the configured `header`, or `Authorization` by default
- custom -> every configured output header name
- passthrough -> none

Delete exactly those client-supplied headers, along with `Proxy-Authorization`, `X-Vault`, hop-by-hop headers, and the reserved `X-Agent-Vault-*` namespace.

Do not unconditionally strip `Authorization`.
When the service authenticates through a different slot, `Authorization` is ordinary application data that the continuation must preserve and deliver to the origin.
Stripping it blindly loses that data and still leaks the slot that actually matters.

Continuation resolution still writes each injected header with `Set`, not `Add`, so injected values win over client-supplied duplicates.

### 7.3 WebSocket

Reverse-proxy the upgrade and byte stream to the sidecar, preserving `Upgrade` / `Connection` on this hop.
The sidecar either rejects, or opens a new WebSocket via the exact continuation and bridges.

Agent Vault verifies the continuation bind, then Resolve and the origin dial.
An origin rejection does not invalidate the JWT.
A denied sidecar upgrade yields zero Resolve.

After a successful origin upgrade, the existing 10-minute WS idle budget governs the bridge.
Unfiltered services keep today's direct origin WS path.

### 7.4 Dial policy

A dedicated per-service transport.
It does not consult `AGENT_VAULT_ALLOW_PRIVATE_RANGES`.
Where an origin may live has no bearing on where a policy sidecar may live.

- `https` without `ca`: normal TLS verification against system roots, public allowed, metadata endpoints blocked.
- `https` with `ca`: verify against that PEM pool only, not the system store.
  The URL hostname must match the certificate.
  Metadata endpoints stay blocked.
  A verify failure fails the hop.
  Do not fall back to system roots or skip verify.
- `http` to a literal loopback IP: allowed.
  A name that resolves to loopback (`localhost`) is not.
  Resolution is not part of the config.
- `http` to anything else: requires `allow_insecure_private_http: true`.
  Then every resolved address must be loopback or RFC1918 (or the IPv6 equivalents).
  Dial the validated IP so a rebind cannot slip between check and connect.
  Public, link-local, CGN, and metadata addresses stay blocked.

Redirects are not followed.
Implement the property, do not merely assert it.
`http.Transport.RoundTrip` (and `httputil.ReverseProxy` over it) does not follow redirects, which satisfies the requirement.
An `http.Client` must set `CheckRedirect` to return `http.ErrUseLastResponse`.
State in the code which mechanism provides it.

### 7.5 Failure and success

| Failure | Response |
| --- | --- |
| Dial, TLS, reset, or JWT mint failure | `502` `filter_unreachable` (or `filter_misconfigured` for state or config) |
| No response headers before the budget expires | `504` `filter_timeout` |

Envelope: `Content-Type: application/json`, `{"error":"<code>","message":"..."}`, `X-Agent-Vault-Proxy-Error: true`.
None of these resolves a credential or reaches the origin.
Leftover JWTs expire unused.

Success: copy status, headers (minus hop-by-hop, reserved broker headers, the reserved namespace, and `Set-Cookie` under the existing proxy response policy), and body to the client, at whatever status the sidecar chose.
Agent Vault does not map "deny" to a fixed 403.
Bodies stream.
A filter that consumes a non-replayable body must buffer before claiming the continuation.

Request-log rows for a filter hop carry the matched service identity and no credential keys.

## 8. Layouts

The sidecar listens on `:12345`.
It is not a vault object and not an agent.
Policy lives in the sidecar.

`git-upload-pack` (clone and fetch) never matches the push row.
The protection API is a different, unfiltered service.

The operator never types agent names, tokens, or `--filter-*` flags.

### 8.1 Same-vault layout

`policy_vault` names the source vault.
Omitting it would mean no side channel (the filter cannot call `api.github.com`).

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

Loopback HTTP needs no `allow_insecure_private_http`.
A Compose sidecar should use `https://filter:12345` plus `ca` ([section 2](#2-config)).
Cleartext `url: http://filter:12345` with `allow_insecure_private_http: true` remains available.

| Who | Request | What happens |
| --- | --- | --- |
| coding agent | `POST https://github.com/acme/app.git/git-receive-pack` | Match, no PAT decrypt, hop to sidecar. |
| sidecar, policy token | `GET https://api.github.com/repos/.../protection` | Unfiltered, inject `GITHUB_TOKEN`. |
| sidecar, allowed | new receive-pack via continuation | Verify JWT and bind, Resolve frozen match, inject, GitHub. |
| sidecar, protected | 403 (or any status) on the client hop | No dest decrypt, no origin. Leftover JWTs expire unused. |
| stolen policy token -> `git-receive-pack` | filtered service | Hop (seam row 3 or 4). Sidecar may still deny. |
| stolen policy token -> unmatched public host | vault unmatched policy | Same as the agent (seam row 1). |
| stolen policy token -> other service in `dev` | residual until `exp` | Same seam as the agent. Prefer the split-vault layout if that residual is unacceptable. |

### 8.2 Split-vault layout

`policy_vault: policy`, holding only the read API, unfiltered.
The configuring admin must be admin of both vaults.
A stolen policy token cannot attach the write PAT.
Allowed push is still continuation to the frozen `dev` match.

Retargeting (GitLab to GitHub) uses the policy token against a GitHub write service in `policy_vault`.
If that service is filtered, that is another hop.

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

`TestSmoke_FilterSameVault` (`make test-smoke`) must use `store.Open` (real SQLite) for vault state, the JWT hop (no filter-agent row, no hop-token table), and both directions:

- denial reaches neither origin nor credential store
- allow reaches origin with the injected destination credential

## 9. Implementation seam

- `broker.Service`: `Filter {url, policy_vault, allow_insecure_private_http, ca}`, validation per [section 2.2](#22-filterurl-and-ca), no `agent_id`, a presence tri-state so `filter: null` survives the CLI -> API hop.
- `proposal`: preserve `filter`, reject an explicit `filter` key, reject delete of a filtered service, reject shadowing matchers at create and apply ([section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher)).
- `brokercore`: Match vs Resolve as required interface members, frozen match freeze and thaw with a version envelope, no dest decrypt on the filter path, compact JWS hop JWTs (`av_cont_` / `av_pol_`, `HS256` from the DEK), policy token follows [The seam](#the-seam) in the named vault.
- `store`: no hop-token table, no FSM, no sweeper for hop JWTs.
- `mitm`: reverse-proxy to `filter.url`, admission-time bind check on both ingress shapes, token vs proxy-URL headers, strip-then-set both directions, dedicated per-service dialer, filtered WS reverse-proxy plus continuation bridge, hop JWTs accepted on the data plane only.
- `server` / `cmd`: dual-admin when `policy_vault` differs, omitted `policy_vault` mints nothing, `AGENT_VAULT_MITM_ADDR` per [section 2.3](#23-agent_vault_mitm_addr).
- CLI: none beyond YAML parse and print.
- Docs: `docs/learn/services.mdx`, `docs/reference/cli.mdx`, `docs/self-hosting/environment-variables.mdx`, `.env.example`, `README.md`, `CLAUDE.md`, and `cmd/skill_cli.md`.
  Skill docs cover filter error codes.
  A filter denial is the operator's policy and is relayed, not worked around.

## 10. Tests

### Blocking

1. Proposal adding an unfiltered exact or longer-path matcher over a filtered wildcard or path matcher is rejected at create.
   When introduced between create and apply, apply is 409 with no mutation.
   Include disjoint host, path, and port cases proving the overlap helper does not reject harmless services.
   Admin YAML writing the same exception is allowed.
2. Policy token plus unmatched host honors the vault's `unmatched_host_policy`, same as an agent session (seam row 1).
   Passthrough forwards with no inject.
   Deny does not contact origin.
3. Policy CONNECT uses the same pre-hijack rules as an agent session in that vault.
   Continuation CONNECT to the wrong authority is 403 before hijack and leaf mint ([section 4.2](#42-bind-check-at-admission)).
   A continuation path mismatch after an otherwise eligible CONNECT also fails closed.
   The JWT stays valid until `exp`.

### Hop JWTs

4. Tampered or wrong-HMAC JWT is rejected.
   Expired JWT is rejected.
   Unknown envelope version fails before any credential read.
5. Wrong CONNECT authority is 403 before hijack and leaf mint.
   The same JWT still succeeds on a later correct bind before `exp`.
   Wrong inner bind is 403, no inject, no origin.
   After `exp`, reject, no credential read or origin contact.
6. Concurrent matching continuation requests with the same JWT all succeed.
   Hop JWTs are not single-use.
7. This change adds no hop-token table, FSM, or denylist.
   Hop-JWT verify does not look up the source session.
8. `agent revoke` after mint does not reject the hop JWT before `exp`.
   `invocation_id` in a request cannot authenticate.

### Frozen match, interfaces, no-read invariant

9. YAML matcher and auth-key edits do not retarget.
   A value update of the frozen key is used.
   Deletion fails closed.
   Custom auth templates and all substitution fields round-trip.
10. Unknown envelope version and malformed or incomplete payload fail before any credential read.
    Compile-time interface assertions for Match and Resolve on production and test stores.
    A Match error never falls through to Inject.
11. A filtered service with no filter engine returns `502 filter_misconfigured` with zero origin and zero credential reads.
12. The no-read invariant on the denied path is asserted by counting credential-store calls, not by status code.

### Headers, URLs, WebSocket, smoke

13. Client values in destination injection header slots do not reach the sidecar.
    An unrelated `Authorization` on a service using a different auth slot is preserved.
    A sidecar cannot spoof Agent Vault's own error header or set a client cookie.
14. `filter.url` with userinfo, fragment, or query is rejected.
    `ca` on `http`, or malformed `ca`, is rejected.
    The advertised hop proxy URL is `AGENT_VAULT_MITM_ADDR` when set, otherwise `http://{AGENT_VAULT_ADDR host}:{mitm-port}`, with no userinfo.
    A missing or wildcard ADDR host falls back to loopback.
    An invalid explicit `AGENT_VAULT_MITM_ADDR` is fatal at startup.
    Redirects are returned, not followed.
15. Full filtered WebSocket bridge: sidecar callback through the continuation, bidirectional frames, origin receives the injected credential, Resolve runs exactly once on that callback.
    An origin rejection does not invalidate the JWT.
    A denied sidecar upgrade yields zero Resolve.
    Unfiltered WS is unchanged.
16. Dial policy: loopback HTTP allowed, RFC1918 HTTP requires the flag, public HTTP denied, metadata and link-local blocked, and `AGENT_VAULT_ALLOW_PRIVATE_RANGES` has no effect on any of it.
    HTTPS with pinned `ca` succeeds against that cert, fails against the system pool or the wrong CA, and never skip-verifies.
17. `TestSmoke_FilterSameVault` uses `store.Open` with real SQLite, not a mock, and asserts both directions.
    Denial reaches neither origin nor credential.
    Allow reaches the origin carrying the injected destination credential.
    No filter-agent row exists.
    No hop-token table exists.
18. Omitted `policy_vault` mints no policy headers and no policy JWT.
19. Hop-JWT prefixes presented as Bearer credentials to control-plane endpoints are rejected.
    A hop-JWT scope is always proxy-only.
20. One filtered request consumes one proxy rate-limit unit.
    Each continuation admission consumes its own unit.
    Policy calls consume their own units.
    Request logs have initiator, vault, service, and key-name attribution as specified in [section 4.8](#48-rate-limits-and-request-logs), with no raw tokens or credential values.
21. Escaped path and raw query are preserved on the sidecar hop and compared byte-for-byte on continuation, including encoded slashes and repeated query keys.

## 11. Out of scope

- Changing global matcher semantics so any overlapping filtered matcher always hops.
  [Section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher) is proposal-only.
- Widening revocation to ordinary established unfiltered CONNECT tunnels.
- A hop-token table, FSM, denylist, or single-use consume.
  Invalidating hop JWTs on `agent revoke` is the same class of work.
- Rewriting the frozen projection as raw `broker.Service` JSON, or including `Filter` in it.
- A TTL flag or env override.
- RFC 9457, filter-agents, or in-process plugins.
- Hiding filtered services from `/discover`.
  Hiding the filter block and hop JWTs is the requirement.
- Changing the Match/Resolve split, adding filter-agents, or treating omitted `policy_vault` as a token on the source vault.
- A named `ca.<name>` catalog.
  YAML anchors are the DRY mechanism. Each stored service keeps its own PEM.

## 12. Locked decisions

1. Reverse-proxy to the sidecar, not a chained forward-proxy, not in-process.
2. Per matched service only.
3. Match without destination decrypt.
   Resolve only after a continuation bind holds, or on the unfiltered path.
   Frozen match in the continuation JWT.
   Match and Resolve are required interface members.
4. No filter-agent.
   Optional 30s policy JWT plus a continuation JWT, minted together with one `invocation_id`.
5. Continuation binds exact method, scheme, authority, escaped path, and raw query.
   Bind is checked at admission, including CONNECT authority before hijack.
   After a successful bind, the stream runs on origin budgets.
   Body comes from the sidecar.
   It cannot retarget the host.
   The JWT stays valid until `exp`.
   A failed bind does not invalidate it.
   A second matching request in the window succeeds.
6. `policy_vault` omitted means no policy token.
   Set means a 30s JWT for that vault.
   Naming a vault other than the source requires admin of both.
7. A policy token cannot spend the originating continuation's destination credential by itself.
   It follows [The seam](#the-seam) in the named vault: unmatched policy, unfiltered inject, filtered hop.
   Hop JWTs are data-plane-only, proxy-role authority.
   Audit as the initiator.
8. Fail closed on hop, JWT mint or verify, Match, snapshot, or missing-engine failure.
   502/504 with the existing JSON envelope.
   A configured filter that cannot be run is never a bypass.
9. Reserved headers as listed in [section 7](#7-the-reverse-proxy-hop), per-kind token prefixes (`av_cont_`, `av_pol_`), strip-then-set in both directions, tokens never in URLs.
10. `filter.url` and `filter.ca` validated per [section 2.2](#22-filterurl-and-ca).
    `AGENT_VAULT_MITM_ADDR` per [section 2.3](#23-agent_vault_mitm_addr): advertise only, not a bind.
    An invalid explicit value is fatal at startup.
    Dedicated dialer per [section 7.4](#74-dial-policy), including pinned `ca` roots and no skip-verify.
    Redirects implemented as not-followed.
11. Filtered WebSocket upgrades hop to the sidecar.
    Agent Vault verifies the continuation bind, then Resolve and origin dial.
    An origin rejection does not invalidate the JWT.
12. Hidden from `/discover` and the skill topology.
    Proposals cannot set, clear, or delete filters or filtered services, and an explicit `filter` key is rejected rather than ignored.
    `enabled: false` remains allowed.
    Proxy-role service reads omit the filter block.
13. Preserve on `service add` omit.
    Wipe on `set`/`clear`.
    Admin list prints `filter`.
14. YAML only, following the substitutions precedent.
    `FilterOp` omit, set, or clear so `filter: null` survives encoding.
15. Hop tokens are compact JWS (`HS256`), prefixed `av_cont_` / `av_pol_`.
    HMAC key derived from the in-memory DEK.
    Bind and frozen match live in claims.
    No hop-token table, denylist, or FSM.
    No hop-JWT mint on the unfiltered path.
16. Thirty seconds is the lifetime.
    `agent revoke` does not invalidate already-minted hop JWTs ([section 4.4](#44-lifetime)).
    Do not add a denylist in this change.
    Do not widen ordinary CONNECT revocation.
17. The frozen projection carries matcher identity and complete non-secret auth and substitution shape, never credential values, and excludes `Filter`.
    Do not re-run the matcher.
    Resolve current values for frozen key names.
    Version-first decode.
    Unknown version fails closed before any credential read.
18. No RFC 9457 in this change.
19. Proposals may not introduce a matcher that wins or ties an existing filtered service, checked at create and apply with exact matcher-language overlap ([section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher)).
    Proposal-only.
    Admin YAML may author exceptions.
20. A policy token is a short lease of the initiating actor on the named vault and follows [The seam](#the-seam).
    Policy CONNECT uses the same pre-hijack rules as an agent session in that vault ([section 4.3](#43-policy-token)).
21. Continuations check bound authority at admission, before hijack ([section 4.2](#42-bind-check-at-admission)).
    Wrong bind is 403 (or 400) for that request.
    The JWT is not burned.
22. Claims may carry actor and vault ids for audit.
    They are not used to re-check the source session on each spend ([section 4.5](#45-claims-and-signing)).
23. Security enforcement is mandatory, and every error on the filter path fails closed.
    No optional type assertions, no fall-through to Inject ([section 5](#5-enforcement-is-mandatory)).
24. Destination credential header slots, derived from the frozen auth configuration without reading values, are removed before the sidecar.
    `Authorization` is not stripped unconditionally ([section 7.2](#72-destination-credential-header-slots)).
25. A continuation and its optional policy JWT are minted in memory with one non-authorizing `invocation_id`.
    The sidecar contract is synchronous ([section 4.7](#47-minting)).
26. Filtered ingress is rate-limited once.
    Each continuation admission is charged.
    Every policy request is charged.
    Logs retain initiator, service, and key-name attribution without raw tokens or values ([section 4.8](#48-rate-limits-and-request-logs)).
