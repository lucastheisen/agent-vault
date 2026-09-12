# Cursor round-2 review — Codex and Claude vs this branch

Reviewed after all three `issue-407-*` branches were supposed to hold a complete hop. Local working document. Do not include `ad_hoc/` in the upstream PR.

| Branch | Tip used | What is actually there |
|---|---|---|
| `issue-407-cursor` | `a79e069` (impl) + later docs | Complete capability hop + Layout A smoke |
| `issue-407-codex` | `a0dd71b` | Complete capability hop + Layout A smoke |
| `issue-407-claude` | `2cbd659` | **No implementation.** Plan copy + `claude_reviews_codex_and_cursor_combined.md` |

---

## Claude — synopsis

Claude arrived after Cursor/Codex settled the hybrid plan and reviewed that plan against base `f0cdfac`, not against either hop.

**Did well**

- Found the two holes neither implementation closed: (1) a proposal can add a more-specific **unfiltered** matcher and steal the match; (2) a policy capability plus default unmatched-host **passthrough** is a 30s open forward proxy.
- Finding 3 (bind continuation authority at CONNECT, pre-hijack) is also right. Codex already implemented it; we did not.
- Finding 5 named the `sess.ID = rawToken` footgun precisely. Both hops already store a hash; the plan still needs to say so.
- Suggested locked decisions 19–22 are the right additions. We adopt them with the **narrow** wording of #1 (proposal reject, not a matcher rewrite).

**Did not do well (compared to an implementation review)**

- There is no Claude hop to compare. Findings 4 and 6 are plan-accuracy notes, not code defects on this branch.
- Finding 6 overstates our snapshot emptiness: `MatchSnapshot` already carries `broker.Auth` + substitutions, not key names alone.
- Finding 4 is correct about ordinary CONNECT (`scope` captured for the tunnel life) but is **docs**, not a reason to widen unfiltered revoke in this feature.

**Disposition of the six findings:** 1, 2, 3 adopted as code locks. 4 adopted as a wording fix. 5 adopted as an explicit hash lock + fail-closed lookup. 6 refined (keep current snapshot shape; add freeze/restore tests; qualify custom-auth literals). Smaller notes: keep `av_cont_` / `av_pol_`; reject `filter.url` userinfo/fragments; allow proposal `enabled: false`; sweeper optional.

---

## Codex — synopsis

Codex shipped a complete hop on the same settled plan. It is the **stronger store and CONNECT** implementation. Ours is the **stronger MITM / operator surface**.

**Did well (steal)**

- Shared-store FSM: issued → claimed → consumed, `SELECT … FOR UPDATE`, burn-on-wrong-authority/bind (`internal/store/filter_capabilities.go`: `ResolveFilterCapability`, `ConsumeFilterContinuation`, `burnFilterCapabilityTx`).
- Continuation CONNECT is gated **pre-hijack** against bound `host:port`. Stolen `av_fcap_` cannot mint a leaf for an arbitrary name. We only bind on the tunneled request.
- Source revocation is checked **inside** the store transaction and burns the row. Ours is a post-consume `Check` that the mock store can skip.
- `ParseFilterProxyURL` validates `AGENT_VAULT_FILTER_PROXY_URL`. We pass the env string through.
- `proposal.FilterSpecified()` rejects explicit `filter` / `filter: null`. We silently drop unknown JSON.
- Freeze/restore tests, including `TestCredentialMatchFreezeRestoreUsesFrozenCredentialKey` (YAML/key-name edit does not retarget; `credential set` on the frozen key attaches the new value).
- Dial-policy unit tests and a scheduled capability pruner.

**Did not do well (keep ours / both still open)**

- Single token prefix `av_fcap_` for both kinds. Ours `av_cont_` / `av_pol_` dispatch and redact cleanly; Claude asked for a distinct namespace.
- Filter hop is a custom `forwardToFilter` rather than `httputil.ReverseProxy`. Heavier, no filtered-WS hop test. We have `TestMITMFilterWebSocketHopsToSidecar` and hop-header overwrite tests.
- HTTP sidecar dial is a process-wide private transport, not per-service `allow_insecure_private_http` (`filter_dial.go`).
- Same two Claude blockers we have: policy `Match` still honors unmatched-host passthrough; proposals can shadow a filtered matcher with a tighter unfiltered `set`.
- Store tests freeze a non-canonical snapshot JSON in places — FSM is proven, restore-at-store-layer is not.

**Do not copy wholesale.** Start from this branch’s hop (`FilterOp`, prefixes, dedicated dialer, ReverseProxy, smoke). Port Codex’s CONNECT claim, store burn/revoke tests, `ParseFilterProxyURL`, `FilterSpecified`, and freeze/restore tests.

---

## Combined picture

Neither hop is PR-ready. The settled plan is still the product. Round 2 adds the holes Claude found, the CONNECT/store strictness Codex already wrote, and a short list of Cursor gaps (advertised proxy URL, fail-closed `InjectFrozen`, strip client `Authorization` on the sidecar hop, `filter.url` userinfo).

The supplemental contract is `service-filters-round2.plan.md`.
