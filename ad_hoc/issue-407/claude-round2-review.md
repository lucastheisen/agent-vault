# Claude reviews the Codex and Cursor implementations

Round 2, Phase 1, task 1. Written on `issue-407-claude` @ `8cb1897`.

Compared:

| Branch | Head | State |
|---|---|---|
| `origin/issue-407-codex` | `a0dd71b` | implementation complete |
| `origin/issue-407-cursor` | `3acf4e4` (impl at `a79e069`) | implementation complete |
| `issue-407-claude` | `8cb1897` | implementation complete |

All three fork from `f0cdfac` and implement the same settled
`service-filters.plan.md`.

This reviews **implementations**, not plans. Local working document; do not
include `ad_hoc/` in the pull request.

---

## Method

I did not take anyone's self-assessment on trust, including Cursor's
`cursor-morning-review.md`, which is a good document and mostly correct. Both
branches were checked out into worktrees and independently exercised:

```
go test ./...                                  both: pass
go test -tags smoke ... -run '^TestSmoke_'     both: pass
golangci-lint run ./... --new-from-rev=f0cdfac codex: 0 issues
                                               cursor: 1 (gosec G306, test file)
```

Everything below that says "confirmed" means I read the code path or ran it,
not that someone claimed it.

### Shape of each branch

| | Codex | Cursor | Claude |
|---|---|---|---|
| Non-test LOC added | 1,869 | 1,646 | 2,180 |
| Test LOC added | 2,004 | 1,344 | 3,699 |
| Filter-related test funcs | 42 | 29 | 79 |
| `go test ./...` | pass | pass | pass |
| Smoke | pass | pass | pass |
| Lint (new code) | clean | 1 finding | clean |
| Smoke uses real SQLite | **yes** | **no — mock store** | yes |

---

## Codex — the strongest of the three on the capability state machine

### Done well

**1. Two-phase capability FSM, and it is the best idea on any branch.**
`issued → claimed → consumed` (`internal/store/filter_capabilities.go:88`).
`ResolveFilterCapability` claims the continuation **at CONNECT**, against the
CONNECT authority, inside a transaction. `ConsumeFilterContinuation` then
requires `state == claimed`. Confirmed called from both ingress shapes
(`connect.go:83`, `forward.go:137`), so the plain-HTTP path is not left behind.

This is strictly tighter than what I built. I validate the CONNECT authority but
do not transition state, so a stolen continuation can open arbitrarily many
tunnels to the *correct* authority before one request spends it. Codex admits
exactly one. **I am adopting this into the round-2 plan.**

**2. Burn-on-mismatch.** A continuation presented for the wrong authority, or
consumed with a wrong binding, is moved to `consumed` and the transaction is
*committed on the error path* (`filter_capabilities.go:250-257`) so a mistargeted
token cannot be followed by a corrected replay. I deliberately do the opposite —
my store test asserts a rejected attempt leaves the capability spendable. Having
now seen both, I think Codex is right and I was wrong; see round-2 plan §3.

**3. `ParseFilterProxyURL`** (`internal/mitm/filter.go:88`) — validates the
advertised callback. Cursor has none. I have an equivalent.

**4. Source revalidation happens inside the same transaction** as the state
transition, so there is no window between "session still live" and "capability
spent". Mine checks authority, then consumes, as two statements. Codex's is
better.

**5. Test quality is genuinely high** — 8-contender concurrency test on the
claim path (`filter_capabilities_test.go:179`), freeze/restore key-rotation,
dial policy, admin lifecycle. Second only to mine by volume, and the store tests
are arguably better than mine.

### Done less well

**1. Single token prefix for both kinds.** `av_fcap_` for continuation *and*
policy (`internal/store/filter_capabilities.go:14`). Cursor and I both use distinct prefixes
(`av_cont_` / `av_pol_`). One prefix means the kind can only be learned by a
store round trip, and log redaction cannot tell an omnipotent-in-vault policy
token from a single-use continuation. Minor, but Cursor's choice is better and
I would standardise on it.

**2. Filtered WebSocket has code but no test.** `isWebSocketUpgrade` appears in
`filter.go`; `filter_test.go` contains zero WebSocket assertions. This is the
one place where an untested path is load-bearing — a filtered service whose WS
upgrade silently bypassed the hop would be a clean policy bypass.

**3. `FOR UPDATE` is a no-op on the default backend.** `SQLiteDialect.
ForUpdateClause()` returns `""` (`dialect.go:136`). The safety on SQLite comes
entirely from the conditional `UPDATE ... WHERE state = 'issued'` and its
`RowsAffected` check, which *is* sound — but the code reads as though row
locking is doing the work. Worth a comment, and worth the concurrency test being
understood as the thing that actually proves it (it does run on SQLite, so the
property is genuinely verified).

---

## Cursor — the weakest on fail-closed discipline

Cursor's own `cursor-morning-review.md` is honest and catches most of its gaps.
I found two it did not frame as severely as I would.

### Done well

**1. Distinct token prefixes** `av_cont_` / `av_pol_`. Best of the three.

**2. `FilterOp` + CLI YAML→JSON tri-state** so `filter: null` survives
`encoding/json` omitempty. Same problem I solved with `FilterExplicit`; theirs
is a reasonable alternative shape and they had it first.

**3. Filtered WebSocket has a test** where Codex does not
(`filter_test.go`, 9 WS assertions) — though it is sidecar-echo only, with no
continuation→origin bridge, which their own review admits.

**4. `httputil.ReverseProxy` for the hop** is less code than either of the
hand-rolled versions. Legitimately simpler.

### Done less well

**1. Two fail-open optional type assertions.** This is the serious one, and it
is the same anti-pattern twice:

```go
// internal/mitm/filter.go:35
matcher, ok := p.creds.(serviceMatcher)
if !ok {
    return false        // filtering silently disabled
}
matched, err := matcher.Match(...)
if err != nil || matched == nil || !matched.HasActiveFilter() {
    return false        // a Match *error* also means "do not filter"
}
```

```go
// internal/server/filter.go:40
if lookup, ok := s.store.(interface {
    GetSessionByTokenHash(context.Context, string) (*store.Session, error)
}); ok {
    ...                 // revocation checked
}                       // ...and silently skipped if the store lacks the method
```

In both cases a *missing capability* degrades to *no enforcement*. The second
one silently no-ops locked decision 16 (immediate revocation), and Cursor
confirms their own mock store does not implement the method — so every
server-level test runs with the revocation check switched off. That is why they
have no revoke tests: the check is not reachable in their harness.

A security control behind an optional interface assertion is not a control. Both
should be compile-time requirements on the interface, and a `Match` error must
fail closed, not fall through to `Inject`.

**2. Smoke test does not use the real store.** `newTestServer(withStore(ms))` —
the mock. The plan specifies "the real SQLite-backed shared capability store",
and the whole point of that clause is to exercise atomic consume and shared
state. Real CA, real MITM, real sidecar, real origin, mock capability store.
Codex and I both use `store.Open(...)`.

**3. No `AGENT_VAULT_FILTER_PROXY_URL` validation.** The env value is passed
through and advertised to every sidecar. A typo'd `http://` host is a cleartext
capability delivery address.

**4. Continuation falls back to a live re-match.** If the provider does not
implement `InjectFrozen`, `forward.go` calls `p.creds.Inject(...)` — re-running
the matcher against current config, which is exactly the TOCTOU the frozen
snapshot exists to prevent. Another optional-assertion fallback.

---

## What all three got wrong

These are shared and belong in the round-2 plan regardless of whose code wins.

**1. Policy capability + default unmatched-host passthrough.** Confirmed in all
three. Codex: `Match` returns `Passthrough` and the guard only checks
`match.Filter != nil` (`forward.go:290`). Cursor: policy requests go through
`Inject`, which honours the vault policy. Mine: same, left in deliberately per
instruction. A stolen policy token is a 30-second open forward proxy attributed
to the initiating actor. This is Claude finding #2 and it is real in every
branch.

**2. Proposal can shadow a filtered matcher.** Nobody implemented a guard.
Claude finding #1.

**3. The client's own `Authorization` header reaches the sidecar.** Confirmed in
all three — every implementation strips hop-by-hop and broker-scoped headers
(`Proxy-Authorization`, `X-Vault`) but not `Authorization`. On a filtered
service that header is going to be overwritten by injection anyway, so
forwarding it to a third party leaks a client-supplied secret for no benefit.
None of us noticed; Cursor listed it against itself only.

**4. Postgres is compile-checked, never executed.** No branch has a PG harness.
All three shipped dual-dialect SQL that has only ever run on SQLite.

---

## Honest placement of my own branch

**Ahead on:** test coverage (79 filter tests vs 42 and 29; 3,699 test LOC),
filtered-WebSocket coverage including a real continuation→origin bridge,
fail-closed defaults (`Match`/`ResolveMatch` are compile-time interface members;
a missing filter engine is a 502, never a bypass), and the
`HashSessionToken`/`GetSessionByHash` pair that makes recording a session
identity safe by construction.

**Behind on:** Codex's two-phase FSM and burn-on-mismatch are better than my
single-statement consume, and Codex's in-transaction source revalidation closes
a window mine leaves open. I am adopting all three.

**Level with:** both blockers I raised are unfixed in my branch too — by
instruction, but unfixed is unfixed.

---

## Recommended composition for Phase 3

Not "pick a branch". The best implementation is:

- **Codex's** store: two-phase FSM, in-transaction revalidation, burn-on-mismatch.
- **Cursor's** token prefixes and CLI tri-state shape.
- **My** interface discipline (no optional assertions for security controls),
  fail-closed defaults, WebSocket bridge coverage, and session-hash handling.
- **Plus** the four shared fixes above, which no branch has.
