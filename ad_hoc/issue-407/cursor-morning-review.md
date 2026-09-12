# Morning review — Cursor impl vs Codex vs Claude’s plan notes

Written overnight on `issue-407-cursor` @ `a79e069`. Compared to:

- agreed plan: `ad_hoc/issue-407/service-filters.plan.md`
- Codex impl: `issue-407-codex` @ `a0dd71b`
- Claude’s plan review: `issue-407-claude` @ `2cbd659` (`ad_hoc/issue-407/claude_reviews_codex_and_cursor_combined.md`)

This is a **local working document**. Do not include `ad_hoc/` in the upstream PR.

---

## Bottom line

Our implementation is a real Layout A hop: no filter-agents, Match-then-sidecar, continuation/policy tokens, SQL capability rows, dual-admin, and the straw-man smoke test is green.

It is **not** yet the stronger of the two codebases, and Claude found two plan holes that **neither** branch closes. I would not send this to Infisical until we land the items marked **do before PR**.

Recommended order:

1. Adopt Claude #2 (policy cap never passthrough) and #3 (CONNECT authority gate) — both are real, cheap, and Codex already has #3.
2. Steal a short list from Codex (store FSM tests, frozen-key rotation test, `ParseFilterProxyURL`, proposal `filter: null` reject).
3. Adopt Claude #1 as a **proposal reject** (narrow), not a matcher rewrite.
4. Leave Claude #4–6 and the smaller notes as plan/docs/test work, not blockers.

---

## 1. Cursor implementation vs the plan

### What we got right

- Reverse-proxy hop, not a chained forward-proxy.
- No dest decrypt until continuation (`Match` on the hop; `InjectFrozen` after consume).
- No minted `filter-` agents. Reserved-name checks removed.
- Continuation: `av_cont_`, 30s, single-use, exact method/scheme/authority/path/query.
- `policy_vault` omitted → no policy token. Same-vault name = Layout A. Other vault = dual-admin at write.
- Policy cap cannot invoke a filtered service (`maybeForwardFilter` fail-closed).
- Hop headers are proxy-URL + token (not token-in-URL). `X-Agent-Vault-*` stripped on the hop and on the sidecar response.
- Dedicated filter dialer (not `AGENT_VAULT_ALLOW_PRIVATE_RANGES`). Loopback HTTP allowed; flagged RFC1918 HTTP; IMDS/link-local blocked.
- Filter preserved on upsert omit; wiped on set/clear; list prints filter fields.
- Proposals cannot delete a filtered service.
- Layout A smoke (`TestSmoke_FilterLayoutA`) rewritten for the new headers/tokens.
- `go test ./...` and the smoke tag both passed at `a79e069`.

### Gaps vs the locked plan (ours)

| Gap | Severity | Where |
|---|---|---|
| Policy cap uses normal `Inject`, so unmatched hosts follow vault **passthrough** (default on) | **Blocking** | `mitm/forward.go` → `creds.Inject`; `brokercore/credential.go` unmatched-host branch. Claude #2. |
| Continuation CONNECT is admitted before bind. Stolen `av_cont_` can open a tunnel to any host, mint a leaf, then fail on the first request | **Blocking** | `mitm/connect.go` — no authority check pre-hijack. Claude #3. Codex already gates this. |
| `AGENT_VAULT_FILTER_PROXY_URL` is advertised with no validation | Medium | `cmd/server.go` |
| Session revoke check is skipped unless the store implements `GetSessionByTokenHash` (mock does not; no revoke tests) | Medium | `server/filter.go:checkCapabilitySource` |
| Continuation present + non-`InjectFrozen` provider falls back to live `Inject` (re-match) | Medium for custom providers | `mitm/forward.go` |
| Client `Authorization` is not stripped on the sidecar hop | Medium | `stripFilterHopHeaders` only strips broker-scoped / `X-Agent-Vault-*` |
| Filtered WS is reverse-proxied to the sidecar; we do not implement an in-proxy continuation→origin bridge (sidecar must callback). Plan wording is slightly stronger than our test | Low | `filter_test.go` WS test is sidecar-echo only |
| Proposals **ignore** a `filter` field (no JSON key) rather than **reject** explicit `filter: null` | Low | Codex has `FilterSpecified()` |
| SQL consume then `Check` — token is burned even if source revalidation fails | Low (fail-closed) | `capability.go` / `capability_sql.go` |
| No scheduled sweeper; expired rows deleted opportunistically on insert | Low | Codex has `runFilterCapabilityPruner` |
| Test matrix incomplete: no revoke tests, no dial-policy tests, no omitted-`policy_vault` hop test, no frozen-key value-rotation test, no SQL atomic-consume test | Test | see Codex list below |

Locks that are solid: 1–8, 13–14, 17–18. Locks that are partial: 9, 10, 11, 12, 15, 16.

---

## 2. Cursor vs Codex

Codex’s branch is also a complete hop, and in several places it is **stricter and better tested**. We should not merge by copying Codex wholesale — our `FilterOp` / YAML→JSON / smoke wiring is the one we just made green — but we should steal the items below.

### Codex is ahead

1. **CONNECT authority claim** — `SQLStore.ResolveFilterCapability(ctx, token, connectAuthority, now)` refuses (and burns) a continuation presented for the wrong `host:port` **before hijack**. We only bind on the tunneled request. Steal this.
2. **Store FSM** — issued → claimed → consumed, `FOR UPDATE`, burn-on-mismatch, source revalidation inside the tx, cascade-aware session delete tests (`internal/store/filter_capabilities.go` + `*_test.go`, ~800 lines). Ours is a thinner hash+UPDATE. Fine for v1 if we add revoke + consume tests; Codex’s tests are the ones to port.
3. **Frozen-match tests** — `TestCredentialMatchFreezeRestoreUsesFrozenCredentialKey` (YAML/key-name edit does not retarget; `credential set` on the frozen key attaches the new value). We have unknown-version fail-closed only.
4. **`ParseFilterProxyURL`** — https or loopback http; reject userinfo/path/query. We pass the env string through.
5. **Proposal `filter: null`** — `FilterSpecified()` rejects explicit filter writes. We silently drop unknown JSON.
6. **Dial-policy unit tests** — `TestFilterPrivateDialPolicy`.
7. **Richer admin lifecycle tests** — dual-admin, omit/null, set/clear wipe, list round-trip of `allow_insecure_private_http`.
8. **Burn-on-wrong-bind** — a mismatched continuation is destroyed, not left replayable against the correct URL. We fail the request but leave the token live until TTL (HTTP consume happens only after bind match — good — but a CONNECT to the wrong host does not burn).

### We are ahead (keep)

1. **Layout A smoke is capability-native and green** on this branch (Codex also has one; ours matches the headers we ship).
2. **Filtered WebSocket hop test** (`TestMITMFilterWebSocketHopsToSidecar`) — Codex has the code path, no test.
3. **`FilterOp` + CLI YAML→JSON** so `filter: null` survives encoding/json omitempty — operational lifecycle we already had.
4. **Capability token prefixes `av_cont_` / `av_pol_`** — Claude asked for a distinct namespace. Codex used `av_fcap_` for both kinds. Ours is easier to dispatch and redact.
5. **Simpler hop** — `httputil.ReverseProxy` + dedicated dialer. Codex’s custom `forwardToFilter` is more complete (RawPath join, size caps) but heavier.

### Both miss (do not treat Codex as “done”)

- Claude #1: proposal can add a more-specific **unfiltered** service and steal the match.
- Claude #2: policy cap + default unmatched-host passthrough = 30s open proxy.
- Filter-hop **redirects**: plan says disabled. `http.Transport.RoundTrip` does not follow redirects (only `http.Client` does). Codex docs claim “redirects disabled” without a `CheckRedirect`; we are actually fine on ReverseProxy/RoundTrip. No change needed if we keep using Transport directly — **document that**, don’t add a fake CheckRedirect.

---

## 3. Claude’s findings — what should change

Claude reviewed the **plan against `f0cdfac`**, not our code. I re-checked each finding against `a79e069` and Codex.

### 1. BLOCKING — proposal shadows a filtered matcher — **adopt, narrow fix**

**Claude is right.** `MatchScore.Better` ignores declaration order. An agent can propose `github.com/acme/app.git/git-receive-pack` unfiltered over admin `github.com/*/git-receive-pack` + filter, reference the existing PAT, and the human sees “add a service,” not “defeat a filter.”

**Do not** take the structural fix (“any overlapping filtered matcher always hops”). That removes admin-authored unfiltered exceptions and changes match semantics for everyone.

**Do** reject at proposal create/apply: if a proposed `set` matcher is equal to or strictly more specific than an existing **filtered** service (same host-tier overlap + longer or equal path literal, or exact-host beating filtered wildcard), 400/409. Admin YAML/upsert may still write exceptions. Add the test Claude specified.

Add locked decision 19 as Claude wrote it, with the narrow wording.

### 2. BLOCKING — policy cap + unmatched-host passthrough — **adopt**

**Claude is right, and we have this bug.** Policy requests go through `Inject`, which honors `UnmatchedHostPolicy` (default passthrough). A stolen `av_pol_` is a 30s world-open forward proxy attributed to the initiator. Layout B does not save you.

**Fix:** on `scope.IsPolicy`, never passthrough. No match → fail closed (`ErrServiceNotFound`). Do not read `unmatched_host_policy`. Same for Codex’s `Match` path.

This is the single highest-value code change. One branch in `forward.go` / `Inject` (or a `Inject` flag / `MatchStrict`). Test: policy token + unmatched host + vault passthrough → 403, origin never contacted.

Add locked decision 20.

### 3. CONNECT bind authority pre-hijack — **adopt (steal from Codex)**

**Claude is right, and we have this bug.** `handleConnect` authenticates, hijacks, mints a leaf, then the tunneled request checks the bind. Stolen continuation = SSRF + leaf-minting oracle. No dest cred leak, still unacceptable.

Codex already claims the continuation at CONNECT against `connectAuthority` and burns mismatches.

**Fix:** before hijack, if the token is `av_cont_`, `Authenticate` and require `authority` == CONNECT `host:port` (same `hostHeaderForScheme` rules). Do not consume yet. Policy CONNECT: after #2, unmatched/public hosts fail at the first request; still worth refusing obviously unbound hosts if we later bind policy (we should not bind policy to one host).

Add locked decision 21.

### 4. Revoke rationale vs ordinary CONNECT — **docs only**

**Claude is right about the fact, wrong that it blocks.** Ordinary `agent revoke` does not kill an established CONNECT (`scope` captured for the tunnel life). We should say that in the plan: filter capabilities re-check **because we already have a row**, and we are **stricter than** the unfiltered path, not “the same as today.”

Keep per-request policy re-auth and continuation consume checks. Do not widen unfiltered CONNECT revoke in this PR.

### 5. Session id vs raw token — **already mostly done; tighten tests**

**Claude’s footgun is real; we avoided the worst of it.** We store `store.HashSessionToken(raw)` as `SourceSessID` and look up via `GetSessionByTokenHash`. We do **not** persist `sess.ID` (the raw token).

Remaining holes:

- Mock store has no `GetSessionByTokenHash`, so `checkCapabilitySource` **skips** the session row check in server tests.
- No test that a capability row never equals a live raw token.
- Agent-only smoke path is covered in production SQL; user-session revoke is undertested.

**Fix:** implement the hash lookup on the mock; add Claude’s “no row equals raw token” test; treat a missing session row as fail-closed when `SourceSessID` is set (don’t skip the type-assert).

Add locked decision 22 as documentation of what we already intended.

### 6. Freeze `broker.Service` JSON, not a parallel snapshot — **defer, not blocking**

**Half right.** Our `MatchSnapshot` already embeds `broker.Auth` + `[]Substitution` (type, header, prefix, custom templates, placeholder, `in`) — not “key names only.” Claude overstated the snapshot emptiness.

Persisting the whole `Service` including `Filter` would be wrong (continuation must not re-enter the filter). A `Service` minus `Filter` is almost what we have.

**Do:** keep the version byte; add Codex’s freeze/restore + key-rotation tests. **Don’t** rewrite the snapshot format in this PR unless a field is actually missing (`enabled` is unused at resolve; filter must stay out). Qualify the plan: “never credential *values*; custom auth templates can contain operator-written literals, same as `broker_config`.”

### Smaller Claude notes

| Note | Suggestion |
|---|---|
| Strip-then-set `X-Agent-Vault-Proxy-Error` | Already OK: we write errors ourselves; sidecar responses strip the namespace. One-line comment in `WriteProxyError` / `ModifyResponse` is enough. |
| Distinct token prefixes | **Already done** (`av_cont_` / `av_pol_`). Keep. Prefer ours over Codex’s single `av_fcap_`. |
| Proposal `enabled: false` on a filtered service | **Allow.** It is fail-closed DoS, not a bypass. Document why delete is rejected and disable is not. |
| Sweeper | Nice-to-have. Opportunistic delete on insert is enough for v1; steal Codex’s pruner if we have time. |
| `filter.url` reject userinfo/fragments | **Yes, cheap.** Add to `ValidateFilter`. |
| 30s TTL as named constant + optional override | Constant is already `capabilityTTL`. **No new env/flag in v1** unless the smoke or a real sidecar misses the window. |

---

## 4. Suggested change set (when you’re back)

**Do before PR (security):**

1. Policy path: no unmatched-host passthrough (Claude #2).
2. Continuation CONNECT: bind authority pre-hijack; burn or reject mismatch (Claude #3 / Codex `ResolveFilterCapability`).
3. Validate `AGENT_VAULT_FILTER_PROXY_URL` (Codex `ParseFilterProxyURL`).
4. Fail closed if `SourceSessID` is set and session hash lookup is unavailable or missing.
5. Strip client `Authorization` on the sidecar hop (or document that the sidecar must not be less trusted than the client).
6. Proposal: reject more-specific unfiltered matcher over a filtered service (Claude #1, narrow).
7. Tests: #2, #3, revoke agent/session, omitted `policy_vault` mints no policy header, frozen key rotation, `filter.url` userinfo rejected.

**Steal from Codex without changing product:**

- Store revoke / consume / burn tests (adapt to our table).
- `TestCredentialMatchFreezeRestoreUsesFrozenCredentialKey`.
- Proposal explicit `filter` reject.
- Dial-policy unit tests.

**Do not do in this PR:**

- Structural “always hop if any filtered matcher overlaps.”
- Killing ordinary (unfiltered) CONNECT on `agent revoke`.
- Snapshot format rewrite to raw `Service` JSON.
- New TTL flag / RFC 9457 / discover hiding of filtered *services* (hiding the filter *block* is enough).
- In-process WS origin bridge (sidecar callback via continuation is the contract).

---

## 5. Plan checklist amendments I would add

Copy Claude’s 19–22 with these tweaks:

19. Proposals may not add a matcher equal to or more specific than an existing filtered service. Admin YAML may. (Narrow. Not a matcher-engine change.)
20. Policy-capability requests never consult `unmatched_host_policy`; no match → fail closed.
21. Continuation CONNECT validates bound authority pre-hijack; consume still happens on the tunneled request. Wrong authority fails closed (prefer burn).
22. Capability rows store the session token **hash** (`sessions.id`), never the raw token. `ProxyScope` may carry that hash only.

Neutralize plan status lines 7 and 350 (implementation-state notes) before anyone treats the file as the contract — Claude is right that those are stale.
