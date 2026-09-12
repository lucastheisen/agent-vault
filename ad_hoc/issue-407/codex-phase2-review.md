# Codex Phase 2 reconciliation

Reviewed:

- `issue-407-codex`: `codex-round2-review.md` and
  `service-filters-round2.plan.md` at `81cd313`;
- `origin/issue-407-cursor`: `cursor-round2-review.md` and
  `service-filters-round2.plan.md` at `1f84adc`;
- `origin/issue-407-claude`: `claude-round2-review.md` and
  `service-filters-round2.plan.md` at `49d0ac5`;
- Claude's local consolidated Phase 2 draft at `980a111`.

Local working document. Do not include `ad_hoc/` in the upstream pull request.

## Outcome

The three supplements concur on the core result. There is no remaining product
architecture dispute that requires user selection:

- both blocking findings are accepted: proposals cannot shadow filtered
  matchers, and policy capabilities never inherit unmatched-host passthrough;
- proposal protection is narrow and proposal-only; global matcher semantics do
  not change;
- continuation authority uses the Codex three-state, admission-claim,
  burn-on-mismatch state machine with source revalidation in the transaction;
- capability tokens use Cursor/Claude's distinct `av_cont_` and `av_pol_`
  prefixes;
- frozen matches contain every Resolve-affecting field but exclude `Filter`;
- all security operations are required interfaces and every error fails closed;
- the final WebSocket requirement is Claude's full continuation-to-origin
  bridge test;
- operator tri-state behavior preserves omitted versus explicit-null filter
  writes;
- production state is shared SQL, and the Layout A smoke uses real SQLite.

## Resolved differences

### Sidecar request headers

Cursor and Claude initially proposed stripping `Authorization` unconditionally.
Codex's narrower rule wins: derive every destination injection header from the
frozen auth config without resolving values, and strip those exact slots. If an
api-key service injects `X-API-Key`, an unrelated client `Authorization` value
is application data that must survive; stripping only `Authorization` would
both lose that data and leak `X-API-Key`, the slot that actually matters.

### Policy CONNECT

The inner-request strict matcher is necessary but not sufficient. Codex's
pre-hijack authority eligibility gate is retained so a policy token cannot mint
leaves or establish tunnels for wholly unconfigured authorities. It does not
bind a reusable policy capability to one host; it checks that each CONNECT
authority has at least one eligible configured unfiltered service, then checks
the path on every inner request.

### Matcher-shadow detection

Cursor's host/path-prefix approximation can reject harmless disjoint globs and
can miss matcher-language edge cases. The final contract uses an exact
intersection helper for the existing one-label host wildcard, optional port,
and `*` path language, then compares the actual MatchScore tuple on a shared
witness. Equal priority is rejected to avoid relying on declaration order.

### Callback misconfiguration

An explicitly set invalid `AGENT_VAULT_FILTER_PROXY_URL` is fatal at startup.
Warning and falling back to loopback is safe from exfiltration but silently
advertises an address different from what the operator configured.

### Capability cleanup

Codex's invocation lifecycle is retained: continuation plus optional policy row
are committed together and remaining authority is retired when the synchronous
sidecar interaction ends. This prevents a failed second insert or failed hop
from leaving usable partial authority until TTL.

## Final-review refinements

Claude's consolidated draft accurately incorporated the three Phase 1 plans and
is used as the base for `service-filters-final.plan.md`. This review adds five
clarifications that were still implicit:

1. Claim **and consume** must occur before the 30-second expiry; claim alone
   cannot pin an unused continuation indefinitely.
2. A WebSocket continuation is consumed before credential Resolve and origin
   dial. An origin that does not return 101 does not restore the token.
3. Capabilities are accepted on the MITM data plane only and always carry fixed
   proxy-role authority; they are never control-plane bearer sessions.
4. The original filtered request is charged once, its continuation does not
   double-charge it, and every policy call is independently rate-limited and
   logged as the initiating actor.
5. Sidecar responses retain the existing `Set-Cookie` stripping policy, and
   encoded path/raw-query preservation is explicitly tested.

With those changes, the final plan is self-contained and no unresolved
security or product choice remains for Phase 3.
