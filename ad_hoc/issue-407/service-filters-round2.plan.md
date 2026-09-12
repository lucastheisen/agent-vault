# Per-service request filters — Round 2 supplemental plan

Adds to `ad_hoc/issue-407/service-filters.plan.md`. Combined, the two files are the implementation contract. This file does **not** restate the original. It only records modifications and new locks learned from:

- Claude’s plan review (`issue-407-claude`: `claude_reviews_codex_and_cursor_combined.md`) — findings 1 and 2 are blocking; 3–6 adopted or refined below
- Codex’s complete hop (`issue-407-codex` @ `a0dd71b`)
- Cursor’s complete hop (`issue-407-cursor` @ `a79e069`)
- Cursor’s comparison notes (`cursor-round2-review.md`)

Local working spec. Do not include `ad_hoc/` in the upstream PR.

---

## Neutralize stale status lines in the original

These describe branch state, not the contract. Treat them as non-normative until rewritten:

- Original line 7 (`Status:` … mint-at-config still on Cursor)
- Original line 350 (which branch’s Layout A smoke exists)

Replacement requirement: `TestSmoke_FilterLayoutA` (`make test-smoke`) must exercise the **capability** hop (no filter-agents). Both Cursor and Codex already have this.

---

## Modifications to original locks

| Original | Change |
|---|---|
| Lock 12 — proposals cannot set, clear, or delete filters/filtered services | Still true. **Add:** proposals also cannot introduce a matcher that equals or beats an existing **filtered** matcher (new lock 19). Admin YAML/upsert may still write unfiltered exceptions. |
| Lock 16 — revoke rationale “same as ordinary `agent revoke`” | Keep the **behavior** (re-check source on policy auth, continuation consume, each CONNECT policy request). **Correct the justification:** ordinary CONNECT captures `scope` for the tunnel life (`handleConnect`). Filter capabilities are **stricter than** the unfiltered path because a capability row already exists. Do not widen unfiltered CONNECT revoke in this feature. |
| Lock 17 — snapshot is “key names and matcher identity” | Snapshot must also carry non-secret **auth shape** (`type`, header, prefix, custom header *templates*) and each substitution’s `placeholder` / `in`. Cursor’s `MatchSnapshot` already does this. Do **not** persist `Filter` on the snapshot (continuation must not re-enter the hop). Custom auth templates may contain operator-written literals — same exposure as `broker_config.services_json`; never persist credential *values*. |
| §3 “same operator expectation as ordinary agent revoke” | Replace with the lock-16 correction above. |

Redirects on the filter hop: `http.Transport.RoundTrip` (and `httputil.ReverseProxy` using it) does **not** follow redirects. That satisfies “redirects disabled.” Do not add a dummy `CheckRedirect`; document the Transport property.

---

## New locked decisions

19. **No competing unfiltered matcher via proposal (Claude #1, narrow).** A request that an admin filtered service would match must not be served by a proposal-introduced unfiltered service. At proposal **create and apply**, reject a `set` whose matcher is equal to or strictly more specific than an existing filtered service (host-pattern overlap + longer or equal path literal, or exact-host beating a filtered wildcard). HTTP 400/409. Admin `vault service add` / YAML may still author an unfiltered exception. **Do not** change `MatchScore` so “any overlapping filtered matcher always hops” — that removes deliberate admin exceptions.

20. **Policy capability never passthrough (Claude #2).** Requests authenticated with a policy capability never consult `unmatched_host_policy`. No configured service match in the capability’s vault → fail closed (`ErrServiceNotFound` / 403). Do not open an unmatched-host forward path. Layout B does not remove this hole if passthrough stays the vault default.

21. **Continuation CONNECT binds authority pre-hijack (Claude #3).** Before hijack (so a real HTTP status can still be written): continuation token exists, unconsumed, unexpired, source authority live, **and** CONNECT `host:port` equals the capability’s bound authority (same `hostHeaderForScheme` rules). Consume still happens on the tunneled request (exact method/scheme/authority/path/query). Wrong authority **fails closed and burns** the continuation (Codex `ResolveFilterCapability` / `burnFilterCapabilityTx`). No leaf minted, no upstream dial. Policy CONNECT is covered by lock 20 (unmatched/public hosts fail closed); do not bind policy to one host.

22. **Capability rows store the session token hash, never the raw token (Claude #5).** Persist `sessions.id` (SHA-256 of the bearer), never `sess.ID` after `GetSession` (that field is overwritten to the raw token). `ProxyScope` may carry that hash only. Look up via `GetSessionByTokenHash`. If `SourceSessID` is set and the lookup is unavailable or the row is missing/expired → **fail closed** (do not skip the type-assert). Test: no capability row column equals any live raw session token.

23. **`AGENT_VAULT_FILTER_PROXY_URL` is validated** the same class of rules as `filter.url` for a *callback proxy*: absolute `https`, or literal-loopback `http`; reject userinfo, path, query, fragment (Codex `ParseFilterProxyURL`). Invalid env → server refuses to start (or refuses to advertise a usable hop), not a silently trusted string.

24. **`filter.url` rejects userinfo and fragments.** Scheme remains `http`/`https` only. Userinfo would smuggle sidecar credentials past `allow_insecure_private_http`.

25. **Continuation consume uses the frozen snapshot only.** If the credential provider does not implement `InjectFrozen` (or Codex `RestoreCredentialMatch` + `Resolve`), fail closed. Do not fall back to live `Inject` / re-match.

26. **Sidecar hop does not forward the client `Authorization` header.** Strip it with the existing broker-scoped / `X-Agent-Vault-*` strip. The sidecar is not the origin and must not see the initiator’s bearer. Destination credentials are still attached only after continuation.

27. **Capability token prefixes stay split:** `av_cont_` continuation, `av_pol_` policy. Do not collapse to Codex’s single `av_fcap_`. Distinct prefixes dispatch without “try session, then capability” and give log redaction a stable match.

28. **Proposal `filter` field is rejected, not ignored.** Explicit `filter` object or `filter: null` → 400 (`FilterSpecified()`). Unknown-JSON drop is not enough.

29. **Proposal `enabled: false` on a filtered service is allowed.** It is fail-closed DoS (`ErrServiceDisabled`), not a bypass. Delete stays rejected. Document the asymmetry.

30. **Keep Cursor’s operator/MITM surface; steal Codex’s store/CONNECT strictness.** Production still uses shared DB TTL rows. Prefer Codex issued→claimed→consumed + burn-on-mismatch + in-tx source revalidation, or an equivalent that meets locks 16, 21, and 22. Keep Cursor `FilterOp` / YAML→JSON, per-service `filter_dial.go`, and `httputil.ReverseProxy` hop. Scheduled sweeper is optional for v1 if insert-time opportunistic delete exists; port Codex’s pruner if cheap.

---

## Claude findings 3–6 (non-blocking) — explicit disposition

| # | Adopt? | What changes |
|---|---|---|
| 3 CONNECT bind | **Yes** — lock 21 | Code. Steal Codex claim/burn. |
| 4 Revoke vs ordinary CONNECT | **Wording only** | Lock 16 correction. Keep per-request capability re-check. Do not kill unfiltered CONNECT on `agent revoke` in this PR. |
| 5 Session hash | **Yes** — lock 22 | Already the intent on both hops; make skip-on-missing-interface illegal; add the “no raw token in row” test. |
| 6 Freeze whole `Service` JSON | **No rewrite** | Lock 17 modification. Keep versioned `MatchSnapshot` (or Codex `CredentialMatchSnapshot`) with Auth + substitutions, **minus Filter**. Bump `format_version` when an injection-affecting field is added; unknown version fails closed **before** unmarshal of unknown fields is relied on. Add Codex’s freeze/restore + key-rotation tests. |

Smaller Claude notes not promoted to locks: strip-then-set `X-Agent-Vault-Proxy-Error` (already true if we write the envelope after stripping sidecar headers); 30s remains the named constant `capabilityTTL` — **no new env/flag in v1**.

---

## Tests this supplement requires

These are **in addition to** the original test list.

- Proposal adding `github.com/acme/app.git/git-receive-pack` unfiltered over filtered `github.com/*/git-receive-pack` is **rejected**. Admin YAML writing the same exception is **allowed**.
- Policy capability + unmatched host + vault `unmatched_host_policy=passthrough` → 403, origin never contacted.
- Continuation CONNECT to a host other than bound authority is refused **before hijack**; no leaf minted; no upstream dial; token burned.
- No capability row value equals any live raw session token.
- Source agent revoke and source session revoke each reject subsequent policy auth and continuation consume; a revoked cap cannot open a new CONNECT.
- Omitted `policy_vault` mints no Policy-Proxy / Policy-Token headers.
- Unknown / malformed snapshot `format_version` fails closed with no dest decrypt.
- After issuance, changing the service’s auth **key name** does not retarget the continuation; `credential set` on the **frozen** key attaches the new value.
- `filter.url` with userinfo or fragment is rejected; `AGENT_VAULT_FILTER_PROXY_URL` with userinfo/path/query is rejected.
- Dial policy: loopback HTTP allowed; RFC1918 HTTP requires the flag; public HTTP denied; IMDS/link-local blocked.
- SQL consume is atomic (two concurrent consumes → one success).
- Client `Authorization` does not appear on the sidecar hop.
- Proposal body with `filter: {}` or `filter: null` is 400.

---

## Out of scope (still)

- Structural “always hop if any filtered matcher overlaps.”
- Widening ordinary (unfiltered) CONNECT revoke.
- Rewriting the snapshot as raw `broker.Service` JSON including `Filter`.
- New TTL flag, RFC 9457, `/discover` hiding of filtered *services* (hiding the filter *block* remains enough).
- In-process WebSocket origin bridge (sidecar callbacks via continuation).
- Relitigating Match/Resolve, no filter-agents, omitted `policy_vault` = no cap, or Layout A same-vault mode.
