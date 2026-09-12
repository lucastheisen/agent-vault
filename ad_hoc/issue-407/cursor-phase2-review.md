# Cursor Phase 2 — three-way review of the round-2 supplements

Compared the three pushed supplements:

| Branch | Tip | Supplement |
|---|---|---|
| `issue-407-cursor` | `1f84adc` | `service-filters-round2.plan.md` |
| `origin/issue-407-codex` | `81cd313` | same path |
| `origin/issue-407-claude` | `49d0ac5` | same path |

Claude now has a complete hop (`8cb1897`); Phase 1 on this branch reviewed an older Claude tip that was plan-only. That does not change the blockers. It does change who to steal tests from.

This file is the review. The resolved contract is `service-filters-final.plan.md`.

---

## Where all three already agree — take as settled

- Claude #1 narrow: proposals cannot shadow a filtered matcher; admin YAML may. Not a matcher-engine rewrite.
- Claude #2: policy capability never reads `unmatched_host_policy`; no match → fail closed.
- Continuation is `issued → claimed → consumed`. Claim at CONNECT (pre-hijack) or absolute-form admission; consume on the exact request. Wrong authority/bind **burns**.
- Source revalidation lives in the same transaction as each state transition.
- Session **hash** only (`sessions.id`), never `sess.ID` / raw token.
- Distinct prefixes `av_cont_` / `av_pol_`.
- Explicit proposal `filter` / `filter: null` → 400. `enabled: false` on a filtered service is allowed.
- Snapshot is the non-secret Resolve shape (auth type/header/prefix/custom templates + substitution placeholder/`in`), **minus `Filter`**. Version checked before typed decode.
- Revoke rationale: capabilities are **stricter than** ordinary CONNECT. Do not widen unfiltered revoke.
- Filter-path security controls are required interfaces; optional type-assert skip is illegal. Match error / missing engine → fail closed (`502 filter_misconfigured`).
- Real-SQLite `TestSmoke_FilterLayoutA`. Postgres is compile-checked unless a live DSN harness runs.
- Out of scope unchanged: structural always-hop, TTL flag, RFC 9457, hide filtered *services* from `/discover`, no filter-agents.

---

## Deltas I resolved for the final plan

| Topic | Cursor r2 | Claude r2 | Codex r2 | Final |
|---|---|---|---|---|
| Shadow overlap definition | Informal (longer path / exact vs wildcard) | Same informal | Exact matcher-language intersection; reject **equal** priority so we do not depend on declaration order | **Codex.** Informal “longer path” misses glob ties and port overlap. |
| Policy CONNECT | Covered by unmatched deny on first request | Same | Extra pre-hijack gate: authority must be covered by ≥1 enabled **unfiltered** configured service | **Codex.** Otherwise a stolen `av_pol_` is still a leaf-minting oracle for arbitrary names. |
| Sidecar `Authorization` | Always strip | Always strip | Strip **destination injection header slots** only (bearer/basic → `Authorization`; api-key → that header; custom → those names; passthrough → none) | **Codex.** Always-strip loses a client `Authorization` that is application data when dest auth is `x-api-key`. |
| Invalid `AGENT_VAULT_FILTER_PROXY_URL` | Fail start (or refuse to advertise) | Warn + advertise loopback | Fail start | **Fail start.** Operator set a security endpoint; silent fallback is surprising. |
| `filter.url` query | Userinfo + fragment | Userinfo | Userinfo + fragment + configured query/`ForceQuery` | **Codex.** Hop replaces query with the original request; leftover query is unused and can hide secrets. |
| Invocation pair mint/retire | Not locked | Cleanup mentioned, not a lock | Mint continuation+policy in one tx; retire leftovers when the hop ends; sidecar must not keep the policy cap after its response | **Codex.** 30s leftover policy tokens after a 403 hop are unnecessary residual. |
| Second CONNECT to the *correct* authority | Claim at CONNECT, consume later (one tunnel still possible before consume) | Adopt Codex: claim means a second CONNECT is refused | Second admission fails once `claimed` | **Codex/Claude.** Claim is admission, not a hint. |
| Frozen snapshot form | `MatchSnapshot` minus Filter | Clarified wording; do not rewrite to raw `Service` | Versioned projection, version-first decode | Same idea. Final: versioned projection, not whole `Service` JSON. |
| WS test | Sidecar-echo is not enough | Full continuation→origin bridge, Resolve once | Same requirement | **Claude’s test.** |
| Sweeper | Optional if opportunistic delete exists | Implied | Required ticker; correctness never depends on it | **Required ticker** (cheap, already a server pattern). |
| Composition | Cursor hop + Codex store | Codex store + Cursor prefixes + Claude interfaces/WS | Codex FSM + Cursor prefixes/`FilterOp` + Claude WS/hash API | Same composition. |

---

## What I would not take

- Claude’s “invalid callback URL → warn and advertise loopback.”
- Cursor’s “always strip `Authorization`.”
- Cursor’s informal shadow check as the only spec (keep it as the straw-man example; implement Codex’s helper).
- Freezing `broker.Service` including `Filter` (Claude’s impl; Claude’s own r2 already backs off).
- Relitigating Match/Resolve, omitted `policy_vault`, Layout A, or in-process WS origin bridging.

---

## Phase 3 starting composition (unchanged recommendation)

- **Store / CONNECT FSM:** Codex (`issued → claimed → consumed`, burn, in-tx source check, pair mint).
- **Prefixes + FilterOp + per-service dial + ReverseProxy hop:** Cursor.
- **Required interfaces, session-hash API, bridged WS test, fail-closed missing engine:** Claude.
- **Nobody has yet:** locks 19, 20 (strict policy match + policy CONNECT gate), dest-auth slot strip, invocation retire-on-hop-end.
