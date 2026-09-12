# Codex review of the Cursor and Claude implementations

Round 2, Phase 1. Reviewed from `issue-407-codex` at `a0dd71b` against:

| Branch | Reviewed head | Implementation commit |
|---|---|---|
| `origin/issue-407-cursor` | `3acf4e4` | `a79e069` |
| `origin/issue-407-claude` | `8cb1897` | spread across `dfdfdec`–`bdceea7` |

All three branches fork from `f0cdfac` and implement the same settled
`service-filters.plan.md`. This is an implementation review, not another review
of that original plan.

Local working document. Do not include `ad_hoc/` in the upstream pull request.

---

## Verification

I read the filter, capability-store, Match/Resolve, CONNECT, WebSocket, proposal,
admin lifecycle, and smoke-test paths on both branches. I also exported each
reviewed head into a clean temporary tree and ran:

```text
go test -timeout 5m ./...   Cursor: pass   Claude: pass
make test-smoke             Cursor: pass   Claude: pass
```

Full-tree lint finds the pre-existing insecure-cookie warning on both branches.
Cursor additionally adds a `gosec` G306 warning in `cmd/service_test.go` for a
test fixture written with mode `0644`. Neither affects the comparison below,
but the Cursor warning should be cleaned before a PR.

---

## Executive synopsis

| Area | Best current implementation | Why |
|---|---|---|
| Capability state machine | **Codex** | Atomic `issued -> claimed -> consumed`, authority claim at either ingress, burn on mismatch, and source revalidation in the transition transaction. |
| Token namespace | **Cursor / Claude** | Separate `av_cont_` and `av_pol_` prefixes instead of Codex's shared `av_fcap_`. |
| Fail-closed interface design | **Codex / Claude** | Security-critical Match/Resolve and store operations are required interfaces; Cursor has optional assertions that disable checks. |
| Frozen match | **Codex** | Dedicated projection excludes the filter, validates derived key names, and has value-rotation/key-retarget tests. Claude preserves more automatically by serializing `broker.Service`, but also freezes the filter block unnecessarily. |
| WebSocket verification | **Claude** | Full sidecar -> continuation -> origin bridge with frames and exactly one destination Resolve. Cursor tests only sidecar echo; Codex has the path but no focused WS filter test. |
| Admin/CLI lifecycle | **Cursor / Claude** | Both model omitted/set/clear explicitly; Cursor's `FilterOp` survives YAML-to-JSON cleanly, while Claude has especially complete server behavior and visibility tests. |
| Shared-store schema | **Codex** | Constraints, foreign keys, indexes, state, and transactional source checks are strongest. Claude's store is sound but has a check/consume window; Cursor's schema is the least constrained. |
| Smoke test | **Codex / Claude** | Real SQLite store. Cursor's otherwise useful smoke test substitutes a mock capability store. |
| Overall round-1 implementation | **Codex**, narrowly | Strongest security state machine and store tests. Claude has broader protocol tests and several API refinements that should be adopted. |

No branch is ready as-is. Claude's two blocking plan findings are present in
all three implementations, and all three forward client-supplied destination
auth-header slots to the sidecar.

---

## Cursor

### What Cursor did well

1. **Clear token namespaces.** Continuations use `av_cont_`; policy capabilities
   use `av_pol_`. Dispatch and redaction can distinguish the two without first
   querying the database. This is better than Codex's single prefix.

2. **Practical admin tri-state.** `FilterOpOmit`, `FilterOpSet`, and
   `FilterOpClear`, plus the CLI's YAML-to-JSON path, preserve the difference
   between an omitted field and explicit `filter: null`. This is a good
   operational solution to `encoding/json`'s `omitempty` ambiguity.

3. **Small reverse-proxy hop.** `httputil.ReverseProxy` gives Cursor a compact,
   streaming HTTP implementation. Its direct `Transport.RoundTrip` behavior
   also means redirects are not followed.

4. **Useful WebSocket regression coverage.** Cursor verifies that a filtered
   upgrade reaches the sidecar and an unfiltered upgrade remains direct. That
   catches the easiest upgrade bypass, even though it does not exercise the
   continuation-to-origin half.

5. **Honest self-review.** `cursor-morning-review.md` correctly identifies most
   of the branch's important gaps and distinguishes working behavior from
   unverified intent.

### What Cursor did less well than Codex

1. **Two fail-open optional interfaces.** `maybeForwardFilter` returns “not
   filtered” when the credential provider does not implement `serviceMatcher`
   or when `Match` returns an error. Source-session revalidation is similarly
   skipped when the server store lacks an optional hash lookup. Cursor's own
   mock omits that lookup, so its server suite silently runs without the
   immediate-revocation invariant. A security control cannot be optional by
   type assertion.

2. **No admission claim.** A continuation is consumed only on the tunneled HTTP
   request. Before then it can open tunnels, mint leaves, and remain live after
   a wrong-authority CONNECT. Codex atomically claims it at ingress and burns a
   mismatch.

3. **Frozen-match fallback re-matches live configuration.** If the provider
   lacks `InjectFrozen`, the continuation falls back to ordinary `Inject`.
   That recreates the exact configuration TOCTOU the frozen snapshot is meant
   to eliminate.

4. **The smoke test uses a mock store.** It exercises the protocol, CA, MITM,
   sidecar, and origin, but not the shared SQL capability state whose atomicity
   is one of the central production properties.

5. **The SQL model is thin.** It has no explicit claim state, few schema
   constraints, no source-session foreign key, and much less concurrency and
   revocation coverage than Codex.

6. **Callback URL validation is absent.** An invalid or cleartext remote
   `AGENT_VAULT_FILTER_PROXY_URL` is accepted and advertised.

7. **Proposal JSON does not reject an explicit `filter` key.** Because the
   proposal wire type lacks that field, it is silently discarded. An agent can
   believe it requested a policy change that never occurred.

8. **A new lint finding remains.** The `0644` test fixture is harmless in
   practice, but keeping new-code lint clean avoids hiding future findings.

---

## Claude

### What Claude did well

1. **Best end-to-end WebSocket test.** Claude's bridged test sends the upgrade
   to the sidecar, has the sidecar open a new WebSocket through the exact
   continuation, moves frames in both directions, verifies the origin's
   injected credential, and asserts exactly one Resolve. This is the test the
   final implementation should carry.

2. **Strong fail-closed wiring.** Match and Resolve are required methods;
   missing filter machinery and malformed snapshots return errors rather than
   falling back to ordinary injection. Its `SourceAuthorityChecker` and
   hash-based session lookup are explicit contracts.

3. **Safe session identity by construction.** `HashSessionToken` and
   `GetSessionByHash` document and avoid the `Session.ID` footgun. A capability
   row receives the sessions-table hash, never the live bearer.

4. **Separate capability prefixes.** Like Cursor, Claude uses `av_cont_` and
   `av_pol_`.

5. **Broad verification.** Claude has the largest filter-specific suite,
   including a real-SQLite smoke, full WebSocket continuation, dial policy,
   omitted policy vault, unknown snapshot version, source authority, server
   API behavior, and admin visibility.

6. **Good lifecycle and cleanup details.** It explicitly rejects proposal
   filter keys, preserves filters through proposal updates, checks deletes at
   create and apply, sweeps expired capabilities, and discards capabilities
   after several failed hops.

7. **Complete auth-shape snapshot.** Serializing `broker.Service` ensures
   custom header templates, prefixes, substitution placeholders, and surfaces
   are not accidentally omitted. It correctly recognized that “key names
   only” was insufficient wording in the original plan.

### What Claude did less well than Codex

1. **Single-stage continuation consumption.** Claude checks CONNECT authority
   but does not claim the token there. Multiple tunnels to the correct
   authority can be admitted before one request consumes it. Codex's
   `issued -> claimed -> consumed` FSM is tighter.

2. **Mismatch does not burn.** A wrong exact binding leaves Claude's
   continuation usable against the correct request. Anyone able to present the
   wrong bind already possesses the bearer; preserving it helps the attacker
   more than the legitimate sidecar.

3. **Source check and consume are separate.** Revocation can linearize between
   Claude's authority check and conditional consume. Codex validates the
   source row and grant inside the same transition transaction.

4. **The frozen record includes `Filter`.** Freezing the whole
   `broker.Service` avoids omissions, but retains policy topology that Resolve
   does not need and creates a future re-entry footgun. A versioned projection
   of every Resolve-affecting field, explicitly excluding `Filter`, is safer.

5. **Configured callback errors degrade to a warning.** Claude ignores an
   invalid `AGENT_VAULT_FILTER_PROXY_URL` and advertises loopback. That is safe
   from credential leakage but operationally surprising; an explicitly
   configured invalid security endpoint should fail startup, as Codex does.

6. **URL validation is still incomplete.** `filter.url` rejects userinfo and
   non-HTTP schemes but does not reject fragments or a configured query that
   the hop later replaces. The callback validator also accepts path/query/
   fragment components it does not use.

7. **Store defense is weaker.** Claude has good conditional consume semantics,
   but its schema does not reference the source session and its source check is
   outside the consume statement/transaction. Codex combines schema defense,
   transaction checks, and state transitions.

---

## Findings common to all three

### Blocking: proposal matcher shadowing

All branches preserve a filter when a proposal updates that service and reject
deleting a filtered service. None prevents a proposal from adding a different,
more-specific unfiltered service that wins `MatchScore` over the filtered one.
The proposal can reference a credential already in the vault. This bypasses the
filter without modifying it.

The narrow fix is preferable: reject a shadowing proposal at creation and
re-check it against current configuration at apply. Direct admin configuration
may still define an explicit unfiltered exception.

### Blocking: policy capability follows unmatched-host passthrough

All branches route a policy capability through matching behavior that honors
the vault's `unmatched_host_policy`, whose default is passthrough. A stolen
policy capability is therefore a 30-second open forward proxy to arbitrary
internet hosts. Policy capabilities must use configured-service-only matching;
no configured match means deny without reading the unmatched-host setting.

### Client destination-auth slots reach the sidecar

All branches copy client headers after stripping broker-scoped and reserved
headers, but before destination injection. This can expose a client-supplied
credential to the policy service even though continuation would overwrite that
same slot.

The fix should be narrower than “always strip Authorization”: derive the
header names the matched service would inject without resolving their values
(`Authorization` for bearer/basic, configured/default api-key header, all
custom auth header names), and remove those names on the sidecar hop. Preserve
unrelated `Authorization` on a service whose credential is carried elsewhere,
and preserve all headers for filtered passthrough services.

### SQL portability is not executed

Every branch exercises SQLite only. PostgreSQL SQL is compile-reviewed but not
run. The final plan should make the limitation explicit and provide an opt-in
live PostgreSQL test rather than implying both dialects were verified.

---

## Recommended Phase 3 composition

- Start from Codex's transactional capability FSM and real-SQLite smoke.
- Change to Cursor/Claude's `av_cont_` and `av_pol_` namespaces.
- Port Claude's full bridged WebSocket test and its explicit source-hash API.
- Keep a dedicated frozen projection, but require every Resolve-affecting
  `broker.Service` field and verify the version before typed decoding.
- Keep Cursor's explicit filter omit/set/clear behavior at the CLI/API boundary.
- Add proposal-shadow rejection, strict configured-only policy matching, and
  destination-auth-slot stripping; no current branch contains these fixes.
- Make all security operations required interfaces and remove fallback paths.
- Issue and retire an invocation's capability pair as a unit so partial mint or
  hop failures do not leave otherwise usable tokens alive until TTL.
