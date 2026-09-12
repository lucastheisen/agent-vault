# Claude reviews the settled Codex/Cursor filter plan

Reviewed: `ad_hoc/issue-407/service-filters.plan.md` as settled between `issue-407-codex`
and `origin/issue-407-cursor`, together with the five discussion documents that produced it
(`codex-reviews-cursor.md`, `cursor-reviews-codex.md`, `cursor-on-codex-review.md`,
`codex-plan-amendments.md`, `codex-on-cursor-review.md`).

This is a **plan review against the code at the common base commit `f0cdfac`**, not a review of
either branch's implementation. Line references are to that commit.

Local working document. Do not include `ad_hoc/` in the pull request.

---

## Provenance

Both branches fork from `f0cdfac`. The two copies of `service-filters.plan.md` differ by exactly
one line (line 350, a status note about the Layout A smoke test), so the design really is settled.
`issue-407-claude` is branched from `f0cdfac` and carries the Codex copy byte-identical.

Two lines in that file describe *branch implementation state* rather than the spec, and are stale
on a fresh base branch:

- line 7 — `Status:` … "the implementation on `issue-407-cursor` still matches the *original*
  mint-at-config agent spec"
- line 350 — which branch's smoke test exists and in what form

They are left verbatim rather than silently edited. They should be neutralised to requirement
language before this plan is used as the implementation contract.

## What holds up

Spot-checked against the base commit, the plan's factual claims about the codebase are accurate:

| Plan claim | Code |
|---|---|
| existing 10 min WebSocket idle budget | `wsIdleTimeout = 10 * time.Minute` — `internal/mitm/websocket.go:155` |
| existing `{error, message}` + `X-Agent-Vault-Proxy-Error` envelope | `ProxyErrorHeader` — `internal/brokercore/brokercore.go:28` |
| revoking an agent kills its tokens | `RevokeAgent` cascades a `DELETE FROM sessions` — `internal/store/sql_store.go:3044` |
| substitutions are the YAML-only precedent for `filter` | `Service.Substitutions` — `internal/broker/broker.go:37` |

The core architecture is right and I would not relitigate it: Match split from Resolve, no
destination DEK read before an exact continuation is consumed, no durable filter principal,
shared TTL capability rows with an atomic consume, a versioned frozen match, and
`policy_vault` omitted meaning *no* policy capability.

Six substantive issues follow. **Findings 1 and 2 are blocking**; they are credential-exposure
and egress holes that the settled plan does not close. The rest are correctness, accuracy, or
implementability gaps that will cost more to fix after code exists than to write down now.

---

## 1. BLOCKING — an agent proposal can shadow a filtered service and get the credential injected unfiltered

Locked decision #12 says proposals cannot set, clear, or delete filters or filtered services.
Nothing stops a proposal from **adding a different service that wins the match**.

`MatchScore.Better` (`internal/broker/broker.go:521`) ranks candidates by host tier, then port
specificity, then path literal length — and **ignores `DeclOrder` entirely**:

```go
func (s MatchScore) Better(other MatchScore) bool {
	if s.HostTier != other.HostTier {
		return s.HostTier > other.HostTier
	}
	if s.PortSpecific != other.PortSpecific {
		return s.PortSpecific
	}
	return s.PathLiteralLen > other.PathLiteralLen
}
```

`MergeServices` appends a newly proposed service at the end of the list
(`internal/proposal/merge.go:65`), but appending does not help, because declaration order is not
a tiebreak against a *better* score.

Concrete bypass against the plan's own straw man:

| | |
|---|---|
| admin-configured, filtered | `github.com/*/git-receive-pack`, `auth: bearer GITHUB_TOKEN`, `filter: {...}` |
| agent proposal, unfiltered | `github.com/acme/app.git/git-receive-pack`, `auth: bearer GITHUB_TOKEN` |

The proposed service has a longer literal path on the same exact host, so it wins. The filter
never runs and the PAT is injected. The same move works with an exact host beating a filtered
wildcard host (`api.github.com/...` over `*.github.com/...`).

The agent needs no new credential — it references a key that is already in the vault, which
proposals are explicitly allowed to do. The human approving the proposal sees
"add service github-push-v2" with no visible signal that it defeats a policy filter attached to a
*different* service.

**Fixes** (either closes it; I recommend the second for v1):

- *Structural* — at match time, if the request also matches any **filtered** service's pattern,
  the filter hop runs regardless of which service won the score. Most specific filtered match
  supplies the filter. This makes the preserve/no-delete rules defence in depth rather than
  load-bearing, but it removes an admin's ability to author a deliberate unfiltered exception.
- *Narrow* — reject any proposal whose service matcher is equal to, or more specific than, an
  existing filtered service's matcher (host-pattern overlap plus path-prefix containment).
  Preserves admin-authored exceptions; document that exceptions must be admin YAML.

Add to the locked list, and add a test: a proposal adding a longer-literal-path unfiltered
service over a filtered matcher is rejected (or, under the structural fix, still traverses
the filter).

## 2. BLOCKING — a policy capability plus the default unmatched-host policy is a 30-second open forward proxy

The plan bounds the policy capability to "unfiltered services in that vault" and reasons about
the residual blast radius on that basis. The code is more generous than that.

`readUnmatchedHostPolicy` defaults to `PolicyPassthrough` when the vault setting is absent or
unparseable (`internal/server/handle_vaults.go:44`), and `Inject` then forwards **any** unmatched
host (`internal/brokercore/credential.go:149`):

```go
policy, err := p.Store.UnmatchedHostPolicy(ctx, vaultID)
if err != nil || policy == PolicyDeny {
	return nil, ErrServiceNotFound
}
return &InjectResult{Passthrough: true}, nil
```

So a stolen policy capability does not merely reach the unfiltered services in `policy_vault`;
for 30 seconds it reaches **the entire internet** through Agent Vault, attributed in the request
log to the initiating actor. Layout B does not remove this — passthrough is a per-vault setting,
not a property of the service list, so a "read-only policy vault" with one service still has
passthrough on by default.

**Fix:** policy-capability requests must force `PolicyDeny` semantics — the request must match a
configured service in `policy_vault` or fail closed. Do not read the vault's
`unmatched_host_policy` setting on the capability path at all. Add to the locked list and to the
test list.

## 3. Bind the continuation's authority at CONNECT, not only at the tunnelled request

The plan says the continuation is "consumed by the **first exact matching** request, including
inside CONNECT." That is correct about *consumption* and silent about *admission*.

`handleConnect` authenticates once, before the hijack, and at that point only `r.Host` is known —
no method, no path, no query (`internal/mitm/connect.go:83`). Under the plan as written, a stolen
continuation token can open a tunnel to **any** host: Agent Vault mints a leaf certificate for
that host and dials it over TLS before the method/path/query bind ever gets a chance to fail
closed. No destination credential leaks, but a capability-holder gets an SSRF primitive and a
leaf-minting oracle for arbitrary names.

**Fix:** add an explicit CONNECT-time gate, evaluated pre-hijack so a real HTTP status can still
be written — token exists, unconsumed, unexpired, source authority still live, **and**
`host:port` equals the capability's bound authority. Consumption still happens on the tunnelled
request. Policy capabilities need the analogous host check, which falls out of finding 2.

## 4. The revocation rationale is factually wrong about this codebase

Section 3 of the plan justifies per-request revalidation with:

> This is the same operator expectation as ordinary `agent revoke`: authority is gone now, not
> in ≤30s.

That expectation does not currently hold. `handleConnect` resolves the session once and captures
the resulting `scope` into the tunnel's handler for its entire life
(`internal/mitm/connect.go:135`):

```go
srv := &http.Server{
	Handler: p.forwardHandler(target, host, port, scope),
	...
	WriteTimeout:      30 * time.Minute,
	IdleTimeout:       2 * time.Minute,
}
```

Revoking an agent today does **not** cut an already-established CONNECT tunnel; it takes effect
on the next CONNECT.

Keep the requirement — per-request revalidation is cheap on a path that already writes a
capability row, and it is the correct behaviour. But fix the justification, and state the
base-path gap explicitly in the plan. Otherwise the first reviewer asks why the filter path is
stricter than the ordinary proxy path, and the discrepancy stays undocumented in a security
design that is otherwise careful about exactly this class of claim.

## 5. "Record the source session id" has a live footgun that will get implemented wrong

The plan requires the capability row to record "source session and/or agent identity". Two facts
make the obvious implementation wrong:

- `store.GetSession` takes the **raw token**, hashes it to find the row, and then sets
  `sess.ID = rawToken` on the way out (`internal/store/sql_store.go:1711` and `:1734`). The DB
  primary key is `hashSessionToken(rawToken)`, not what `Session.ID` holds.
- `brokercore.ProxyScope` carries no session identifier at all
  (`internal/brokercore/session.go:23`) — only `AgentID`, `UserID`, and vault fields.

So the natural implementation (add `SessionID: sess.ID` to `ProxyScope`, persist it on the
capability row) writes the **agent's raw bearer token into a database row** — a durable credential
copy, which is precisely the property this entire design exists to avoid.

**The plan must say:** store the session token *hash* (the value of `sessions.id`), add a
lookup-by-hash store method — **none exists today**, every current accessor goes through the raw
token — and thread that hash through `ProxyScope`. Add a test asserting no capability row value
equals any live raw session token.

Worth stating in the same place, so nobody invents a parallel mechanism: because `RevokeAgent`
cascades the session delete, a single check covers agent revoke, session revoke, expiry, and
grant removal —

1. session row still present for the stored hash,
2. `!sess.IsExpired(now)` (this is also what picks up user-session sliding idle expiry), and
3. `GetVaultRole(actorID, sourceVaultID) != ""`.

## 6. Freeze the marshalled `broker.Service`, not a parallel snapshot struct

The plan's snapshot record lists "non-secret auth + substitution snapshot — credential **key
names** only". That is not sufficient to reproduce injection. Resolve also needs `auth.type`, the
`header` name, the `prefix`, the entire `custom.headers` template map, and each substitution's
`placeholder` and `in` surfaces. A snapshot of key names alone cannot rebuild the headers.

Persisting the matched `broker.Service` JSON **verbatim** is simpler and adds no new exposure —
that exact shape is already stored unencrypted in `broker_config.services_json`.

Keep the explicit `format_version`, and check it **before** unmarshal: `encoding/json` silently
ignores unknown fields, so a mixed-version replica pair would otherwise drop a newly added,
injection-affecting `Service` field with no error. Bump the version whenever `Service` gains a
field that changes injection.

One wording fix belongs here too. `custom` auth headers are free text — validation only constrains
the `{{ KEY }}` placeholders inside them (`internal/broker/broker.go:101`) — so an operator *can*
hardcode a literal secret in one, and it would be copied into the capability row. The row's
"never values" claim is true of credential *references* but not absolutely true of the auth block.
It is already plaintext in `broker_config`, so this is a documentation qualification, not a new
risk. State it rather than overclaiming.

---

## Smaller points

- **Strip ordering.** Namespace-wide stripping of `X-Agent-Vault-*` from the sidecar's response is
  right, but Agent Vault's own 502/504 envelope sets `X-Agent-Vault-Proxy-Error`
  (`internal/brokercore/brokercore.go:28`). Specify strip-then-set, or the rule eats its own header.
- **Token namespace.** Capability tokens ride the same `Proxy-Authorization` slot as session
  tokens, and `ParseProxyAuth` returns an opaque string either way
  (`internal/brokercore/proxyauth.go:31`). Give capabilities a distinct prefix (`avc_`
  continuation, `avp_` policy) so the resolver dispatches deterministically instead of
  "try session, fall back to capability", and so log redaction can match on the prefix.
- **Proposal `enabled: false`.** Disabling a filtered service is the same "agent removes the
  policed route" move the plan rejects for delete. It is fail-*closed* today — a disabled match
  returns `ErrServiceDisabled` rather than falling through to passthrough
  (`internal/brokercore/credential.go:156`) — so it is denial of service, not bypass. Either
  reject it alongside delete for symmetry, or say explicitly why it is allowed.
- **Sweeper.** Nothing in this codebase sweeps expired rows today; sessions are only ever checked,
  never deleted. The capability table would be the first. `runTouchCachePruner`
  (`internal/server/server.go:1376`) is the ticker-until-ctx-cancelled pattern to mirror.
- **`filter.url` validation** should reject URL userinfo and non-empty fragments and pin the
  scheme set to `http`/`https`. Otherwise `allow_insecure_private_http` gates only part of the
  surface it appears to gate.
- **30s claim TTL** is tight for the git straw man: ref parse, then a full CONNECT + TLS handshake
  + round trip to the protection API, then a second CONNECT for the continuation. Probably fine,
  but make it a named constant with a config override rather than a literal.

---

## Suggested additions to the locked checklist

19. A request that matches a filtered service's matcher cannot be served by a competing unfiltered
    service (finding 1). Proposals may not introduce a matcher equal to or more specific than a
    filtered one.
20. Policy-capability requests never consult the vault's `unmatched_host_policy`; no match in
    `policy_vault` means fail closed (finding 2).
21. CONNECT admission for a capability validates the bound authority pre-hijack; consumption still
    happens on the exact tunnelled request (finding 3).
22. Capability rows store the session token **hash**, never the raw token (finding 5).

## Suggested additions to the test list

- Proposal adding a longer-literal-path unfiltered service over a filtered matcher is rejected
  (or still traverses the filter).
- Policy capability against an unmatched host fails closed even when the vault's
  `unmatched_host_policy` is `passthrough`.
- Continuation token CONNECTing to a host other than its bound authority is refused before the
  hijack, with no leaf minted and no upstream dial.
- No capability row column equals any live raw session token.
- An unknown `format_version` fails closed before any credential read; a `Service` field added
  after issuance does not silently vanish from a snapshot round trip.
