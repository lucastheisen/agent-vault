# Codex review: policy-filter plans

This is a plan-only comparison between:

- `service-filters.plan.md`: the current HTTPS policy-filter design; and
- the Cursor branch's `ad_hoc/issue-407/service-filters.plan.md` at `origin/issue-407-cursor`.

It does not assess code quality or test results. Both plans start from the same base commit, `f0cdfac`.

## Conclusion

The current plan should produce the stronger security design and is the better starting point for an upstream v1. It has a smaller surface area, keeps destination credentials unresolved until an exact continuation succeeds, and avoids creating durable filter credentials.

The Cursor plan is more complete as an operational specification. Its configuration-lifecycle rules, timeout/error behavior, and discussion of WebSocket support are useful ideas. Those details should be incorporated without adopting its long-lived filter-agent model.

## Comparison

| Topic | Current plan | Cursor plan | Assessment |
|---|---|---|---|
| Destination credentials | Matching is separate from resolution; a denial or failed filter hop performs no credential read or decrypt. | Filter runs before injection. | Equivalent intended boundary; the current plan states and tests the no-read invariant more explicitly. |
| Filter authority | An optional policy-vault capability is opaque, scoped, and valid only for 30 seconds. | A configuration-time filter agent has a recoverable, encrypted, long-lived token. | Current plan is materially safer. A durable token is a larger theft and rotation target. |
| Vault separation | Policy vault must be separate, and the configuring actor must administer both vaults. | `filter.vault` defaults to the source vault; split vaults are optional. | Current plan is better least privilege. The Cursor plan documents that a stolen same-vault filter token can push, but accepts that risk for its smallest layout. |
| Continuation binding | Single-use continuation binds method, scheme, authority, escaped path, query, and the original non-secret match. | HMAC ticket binds method, host, path, and expiry. | Current plan is stronger: it prevents query/scheme changes and keeps a configuration change during the 30-second window from selecting another credential. |
| Continuation storage | Opaque random capabilities, held only in process and removed when consumed or expired. | Stateless HMAC ticket; in-flight tickets die when the process restarts. | Both fail closed on restart. The Cursor approach is lighter; the current approach buys exact single-use and preserved-match semantics. |
| Filter transport | Remote filters and advertised return paths require HTTPS; cleartext HTTP is allowed only on a literal loopback address. | Permits any HTTP(S) filter URL, including private and public cleartext endpoints. | Current plan is better. Policy decisions and continuation capabilities should not traverse a remote cleartext hop. |
| Header boundary | All `X-Agent-Vault-*` request and response headers are stripped at the destination boundary. | Defines per-hop headers and broker-scoped stripping. | Both recognize the trust boundary; the current plan's namespace-wide response stripping is clearer protection against a policy API spoofing control headers. |
| Filter recursion | Policy-vault capabilities cannot invoke another filter. | Skip occurs for a continuation or the matching filter agent. | Current plan is simpler and fail-closed. Cursor supports a broader self-complete model, but that breadth increases capability exposure. |
| WebSockets | Deliberately deferred for filtered services. | Proxies filtered WebSocket upgrades to the sidecar. | Cursor is more capable. The current plan is the better v1 boundary unless a concrete filtered-WebSocket use case is required. |
| Request bodies | Streams bodies; a filter that consumes one must replay it. | Same. | Equivalent. |
| Configuration lifecycle | Admin-only filter configuration and proposal preservation/rejection. | Detailed `add`, `set`, `clear`, list-round-trip, sharing, revocation, and remint semantics. | Cursor has the stronger operational specification. The current plan should add explicit mutation semantics, even though it intentionally has no filter-agent lifecycle. |
| Failure and timeout behavior | Fail closed before credential resolution; documents transport and capability failures at a high level. | Names 502/504 behavior, error envelopes, timeout budgets, and IMDS/dialer policy. | Cursor is more concrete. The current plan should add this operational detail. |
| Scope and implementation size | Builds on matching/resolution split, proxy capabilities, and existing vault session machinery. | Adds persistent filter-agent creation, encrypted token storage, sharing/revocation lifecycle, and filter-specific server APIs. | Current plan is a smaller, lower-risk upstream change. |

## Recommendation

Keep the current plan's core decisions:

1. No destination credential resolution before a filter allows continuation.
2. Short-lived, exact, single-use continuations carrying the original match.
3. A separate policy vault with a short-lived policy capability, not a durable filter agent.
4. Cross-vault admin authorization and no agent-proposal control of filters.
5. HTTPS for every remote filter or callback hop.
6. No filtered WebSockets in v1.

Adopt these Cursor-plan improvements:

1. Define exactly how service upsert, full replacement, and clearing interact with an existing filter, and ensure list-to-set round trips retain the block when intended.
2. Specify filter-hop timeout budgets, status codes, structured error behavior, and dial restrictions.
3. Retain the explicit non-goals and operator-focused examples from the Cursor plan.
4. Document the deferred filtered-WebSocket decision prominently, including the path for a later extension.

## Final assessment

The Cursor plan is a useful, detailed prototype specification, especially for operational lifecycle concerns. Its mint-at-configuration filter-agent model, however, gives the filter a durable bearer credential and can deliberately place that credential in the source vault containing write authority. That is a poor default for a feature intended to enforce policy before credential use.

The current plan preserves the desired `Agent -> Vault -> Filter -> Vault -> destination` seam while treating both the policy path and the destination continuation as narrowly scoped, expiring capabilities. That produces a safer and more reviewable first implementation. The recommended Cursor improvements improve its specification quality without changing that security model.
