# Per-service request filters — round 2 supplement

**This is a supplement, not a replacement.** It is read *on top of*
`service-filters.plan.md` and only states what that document changes, adds, or
got wrong. Anything the original settles and this file does not mention stands
unchanged.

Source material: three independent implementations of the original plan
(`issue-407-codex` @ `a0dd71b`, `issue-407-cursor` @ `a79e069`,
`issue-407-claude` @ `8cb1897`), all green on their own suites; the six findings
in `claude_reviews_codex_and_cursor_combined.md`; Cursor's
`cursor-morning-review.md`; and my own `claude-round2-review.md`.

Local working spec. Do not include `ad_hoc/` in the pull request.

---

## 0. Corrections to the original plan's own text

These are not design changes. The original file says things that are false.

| Original | Correction |
|---|---|
| Line 7 `Status:` — describes `issue-407-cursor`'s implementation state | Delete. All three implementations now exist; the line was stale the moment it was written and invites reading branch state as contract. |
| Line 350 — "A final-protocol Layout A HTTP smoke … exists" | Restate as a **requirement**, not a status: the smoke test MUST use the real SQLite-backed store (see §6.1). One branch shipped it against a mock and still read the line as satisfied. |
| §3 "This is the same operator expectation as ordinary `agent revoke`" | False about the codebase. `handleConnect` resolves the session once and captures the scope for the tunnel's life, so ordinary `agent revoke` does **not** cut an established tunnel. Keep the requirement; restate the rationale as "capabilities are held to a **stricter** standard than the unfiltered path, because a capability row already exists to re-check." Do not widen unfiltered CONNECT revocation in this change. |
| §4 frozen snapshot "Credential **key names** only — never values" | Under-specified and, read literally, wrong. The snapshot must also carry the auth *shape* — `auth.type`, header name, prefix, and the whole `custom.headers` template map — plus each substitution's `placeholder` and `in`, or Resolve cannot rebuild the same headers. Restate as: "the matched service's non-secret configuration, referencing credentials by key name." Note explicitly that `custom.headers` templates are operator-written free text and may contain literals, exactly as they already do in `broker_config.services_json`; the row is *not* a secret store, but "contains no secrets" is not an absolute the code can enforce. |

---

## 1. New locked decisions

Numbered continuing from the original's 18.

**19. A proposal may not introduce a matcher that shadows a filtered service.**
Reject at create (400) and re-check at apply (409) if any proposed `set`
matcher is equal to, or strictly more specific than, an existing **filtered**
service's matcher — same host tier with a path literal at least as long, or an
exact host beating a filtered wildcard.

Rationale: `MatchScore.Better` ranks host tier → port specificity → path literal
length and **ignores declaration order**, so an appended service with a longer
literal path outranks a filtered one. An agent can propose
`github.com/acme/app.git/git-receive-pack` over a filtered
`github.com/*/git-receive-pack`, reference the PAT already in the vault, and a
human reviewing "add a service" sees nothing unusual.

Explicitly **not** the structural alternative ("any request matching a filtered
matcher always hops"). That removes an admin's ability to author a deliberate
unfiltered exception and changes match semantics for unfiltered traffic. Admin
YAML and direct upsert may still write an overlapping matcher; only proposals
are constrained.

**20. Policy-capability requests never consult `unmatched_host_policy`.**
No service match in the policy vault means fail closed. Do not read the vault
setting on that path at all.

Rationale: the setting defaults to `passthrough`, so as specified in round 1 a
stolen policy capability is a 30-second **open forward proxy** — arbitrary
internet egress through Agent Vault, attributed in the request log to the
initiating actor. Layout B does not help: passthrough is a per-vault setting,
not a property of the service list. All three round-1 implementations have this
hole.

**21. A continuation is claimed at ingress admission, against the bound
authority, before any tunnel is established.**

Concretely, the capability is a three-state machine — `issued → claimed →
consumed`:

- **`issued → claimed`** happens when the capability is first presented, on
  either ingress shape: at CONNECT before the hijack, or on the absolute-form
  forward-proxy request. The presented authority must equal the bound authority.
- **`claimed → consumed`** happens when the exact bound request arrives.
- Consumption requires state `claimed`, so a continuation that was never
  admitted cannot be spent.

Rationale: without the authority check a stolen continuation opens a tunnel to
any host, and Agent Vault mints a leaf certificate for that name and dials it
before the method/path bind is ever compared — an SSRF primitive and a
cert-minting oracle even though no credential is attached. Without the *claim*,
the authority check alone still admits unboundedly many concurrent tunnels to
the correct authority.

**22. Capability rows store the session token hash, never the raw token.**
`store.GetSession` takes a raw token and returns it back as `Session.ID`, so the
obvious implementation writes a live bearer token into a database row. The store
must expose a hash-based lookup, and `ProxyScope` may carry only the hash.

**23. Every security control on the filter path is a compile-time obligation,
never an optional interface assertion.**

Matching, frozen-match resolution, source-authority re-validation, and the
capability store are all *required* members of their interfaces. A type
assertion that fails must not degrade to "skip the check" — and equally, an
*error* from one of these calls must fail closed rather than falling through to
the ordinary inject path.

Rationale: this is the single most common way the round-1 implementations lost a
property they believed they had. One branch gates revocation behind
`if lookup, ok := s.store.(interface{ GetSessionByTokenHash(...) }); ok`, and
its own mock store does not implement the method — so decision 16 is silently
unenforced across its entire server test suite. The same branch skips filtering
entirely if the credential provider does not assert to a `serviceMatcher`, and
treats a `Match` error as "do not filter."

**24. A configured filter that cannot be run fails closed.**
If a service carries a `filter` block and the proxy has no filter engine, or the
capability cannot be minted, or the frozen snapshot cannot be read, the request
returns `502 filter_misconfigured`. "Cannot run the policy" must never resolve
to "skip the policy."

**25. The client's own `Authorization` header is stripped on the hop to the
sidecar.**
All three implementations forward it. On a filtered service that header is
overwritten by injection on the origin hop anyway, so passing it to the sidecar
leaks a client-supplied secret to a third party for no functional benefit. Strip
it alongside `Proxy-Authorization` and `X-Vault`.

---

## 2. Amendments to existing locked decisions

**Amends 5 and 15 — burn on mismatch.** A continuation presented with the wrong
authority at admission, or the wrong binding at consume, is moved to `consumed`
and that transition is **committed**, not rolled back.

I argued the opposite in round 1 (my store test asserts a rejected attempt
leaves the capability spendable) and I was wrong. The reasoning that changed my
mind: an attacker holding the token can spend it correctly anyway, so declining
to burn buys the legitimate sidecar nothing; whereas burning converts a
mistargeted use into an immediate, visible, single failure instead of leaving a
live token for the remainder of its TTL. The DoS objection is weak — anyone able
to burn it already had the token.

**Amends 15 — source revalidation happens inside the consume transaction.**
Checking "is the source session still live" and then separately consuming leaves
a window where the session is revoked between the two. One transaction.

**Amends 9 — one prefix per capability kind.** `av_cont_` for continuations,
`av_pol_` for policy capabilities, following the existing `av_sess_` / `av_agt_`
convention. A single shared prefix forces a store round trip to learn the kind
and prevents log redaction from distinguishing a single-use continuation from a
vault-scoped policy token.

**Amends 9 — strip the reserved namespace before origin as well.** The original
says "both directions" but only the sidecar-facing direction is obvious. The
continuation request is *assembled by the sidecar*, which was just handed
capability headers; nothing it sends may carry `X-Agent-Vault-*` onward to the
destination.

**Amends 10 — `AGENT_VAULT_FILTER_PROXY_URL` is validated at startup.**
It is the address sidecars are told to send capabilities to, so the same
transport rule as `filter.url` applies: `https`, or `http` only to a literal
loopback IP. Reject userinfo. An invalid value is ignored with a logged warning
and the loopback listener advertised instead — never advertised as given.

**Amends 10 — `filter.url` rejects userinfo and non-`http(s)` schemes.**
Consistent with the plan's own "secrets are not in URLs".

---

## 3. Clarifications the round-1 plan left ambiguous

**3.1 Redirects.** The plan says "redirects disabled on the filter hop". This is
free when the hop uses `http.Transport.RoundTrip` directly (transports do not
follow redirects; only `http.Client` does). If an implementation uses
`http.Client`, it must set `CheckRedirect` to return
`http.ErrUseLastResponse`. State which mechanism is in use rather than asserting
the property — one branch documented "redirects disabled" with neither.

**3.2 Proposal `enabled: false` on a filtered service is allowed.** A disabled
service returns `ErrServiceDisabled`, which is fail-*closed*, so disabling is
denial of service and not a policy bypass. Delete is rejected because it drops
the request to the unmatched-host policy; disable does not. Document the
asymmetry so it does not read as an oversight.

**3.3 Attribution on the capability path.** Audit and rate-limit attribution
follow the *initiating actor* recorded on the capability row, not the sidecar.
Request-log rows for a filter hop carry the matched service identity and no
credential keys — no credential was resolved, and the log should say so by
omission rather than by inheriting the previous request's fields.

**3.4 What "no capability write on unfiltered Inject" means.** It is a
performance and blast-radius statement, not a correctness one: the unfiltered
path must not touch the capability table at all, so a filter-path outage cannot
degrade ordinary proxying.

---

## 4. Implementation requirements drawn from the three attempts

These are not new product decisions; they are the shapes that worked and the
shapes that did not.

**4.1 The capability store is a state machine, expressed in SQL.**
Transitions are conditional `UPDATE`s guarded on the current state with a
`RowsAffected == 1` check. That check — not row locking — is what makes the
transition atomic on SQLite, where `SELECT ... FOR UPDATE` is a no-op. If a
`FOR UPDATE` clause is emitted for Postgres, say in a comment that SQLite relies
on the conditional update, so a future reader does not assume locking is doing
the work.

**4.2 Concurrency must be tested, not asserted.** N contenders racing a single
capability, exactly one success, on the real SQLite store. Two of three branches
have this; it is the only evidence that single-use holds under the multi-replica
deployment the shared store exists for.

**4.3 Match/Resolve is an interface split, not a convention.** `Match` (no
decrypt) and `Resolve` (decrypt) are both required members. The no-read
invariant should be tested by *counting* credential-store calls on the denied
path, not by asserting the response status — a status assertion passes even if
the DEK was opened and the result discarded.

**4.4 Filtered WebSocket needs a bridged test, not just a rejection test.**
One branch has the code and no test; another has a sidecar-echo test with no
continuation. The property worth pinning is the full path: upgrade reverse-
proxied to the sidecar, sidecar opens its own WebSocket through the
continuation, frames flow both ways, origin sees the injected credential, and
`Resolve` ran exactly once.

**4.5 Postgres is unverified across all three branches.** Dual-dialect SQL has
only ever executed on SQLite. Either add a Postgres harness gated on an env var,
or state plainly in the PR that the Postgres path is compile-checked only. Do
not let it read as tested.

---

## 5. Explicitly out of scope for this change

Recorded so they are not re-litigated:

- Structural "any overlapping filtered matcher always hops" (see 19).
- Killing ordinary unfiltered CONNECT tunnels on `agent revoke` (see §0).
- Rewriting the frozen-match snapshot into raw `Service` JSON. The format needs
  the clarification in §0, not a redesign. `Filter` itself must stay *out* of the
  snapshot — a continuation never re-enters the filter.
- A TTL flag or env override. 30s stays a named constant unless a real sidecar
  misses the window.
- RFC 9457 problem details.
- Hiding filtered *services* from `/discover`; hiding the `filter` *block* is
  the requirement.

---

## 6. Test matrix — additions to the original §"Tests"

**6.1 Smoke.** `TestSmoke_FilterLayoutA` MUST run against the real SQLite store
(`store.Open`), not a mock, and must assert both directions: a denial reaches
neither the origin nor the credential, and an allow reaches the origin carrying
the injected destination credential.

**6.2 New cases required by decisions 19-25:**

| Decision | Test |
|---|---|
| 19 | Proposal adding a longer-literal-path unfiltered service over a filtered matcher is rejected at create and at apply. |
| 20 | Policy capability + unmatched host + vault `unmatched_host_policy=passthrough` → fail closed; origin never contacted. |
| 21 | Continuation presented at CONNECT for an unbound authority is refused pre-hijack, with no leaf minted and no upstream dial; a second CONNECT with an already-claimed continuation is refused. |
| 22 | No capability row column equals any live raw session token. |
| 23 | A capability store or authority checker that is absent is a compile error, not a runtime skip — assert by construction (interface membership), plus a test that a `Match` error fails closed rather than falling through to inject. |
| 24 | A filtered service on a proxy with no filter engine returns 502 and never reaches the origin. |
| 25 | The client's `Authorization` header does not reach the sidecar. |

**6.3 Carried from round 1, still required, and only partially present across the
three branches:** revoke source agent/session rejects both capability kinds;
a revoked capability cannot be revived by opening a new CONNECT; a YAML or
key-name edit mid-window does not retarget the frozen slot; value rotation of
the frozen key *does* attach the new secret; unknown snapshot version fails
closed with no credential read; dial policy — loopback http, flagged RFC1918
http, public https, blocked metadata.

---

## 7. Round-2 checklist

19. Proposals may not shadow a filtered matcher (narrow: proposals only).
20. Policy capabilities never consult `unmatched_host_policy`; no match fails closed.
21. Continuations are claimed at admission against the bound authority; consume requires `claimed`.
22. Capability rows store the session token hash, never the raw token.
23. Filter-path security controls are compile-time obligations; errors fail closed.
24. A configured-but-unrunnable filter returns 502; never a bypass.
25. The client's `Authorization` is stripped on the sidecar hop.

Amended: 5 and 15 (burn on mismatch; revalidate inside the consume
transaction), 9 (per-kind token prefixes; strip the namespace before origin),
10 (validate the advertised callback URL; reject userinfo in `filter.url`).

Corrected: original lines 7 and 350, the §3 revocation rationale, and the §4
snapshot description.
