# Restored policy-filter conversation

This note restores the active work that was paused when the workspace changed from Condev to this Agent Vault checkout on 2026-09-11.

## Paused request

Read the comparison plan from the `github.com/lucastheisen/agent-vault` fork at `ad_hoc/issue-407`, create `ad_hoc/issue-407/service-filters.plan.md` describing the current solution in the same style, then compare the two solutions and identify the stronger ideas.

## Current implementation state

- Branch: `feat/policy-filter-service`.
- All implementation changes are uncommitted.
- The preceding implementation review reported passing `go test ./... -count=1`, `go vet ./...`, and `git diff --check`.
- The current checkout contains the reviewed implementation, including the untracked `internal/mitm/filter.go` and `internal/mitm/filter_test.go`.

## Agreed design

The feature is an HTTPS service-filter seam:

```text
Agent -> Agent Vault -> filter -> Agent Vault -> destination
```

The filter can deny the request or use a narrowly scoped continuation to let the original request reach its destination. Filter policy calls use a separate policy vault.

Security properties established in the earlier conversation:

- Service filters are admin-configured only; agent proposals cannot add, replace, delete, or silently remove them.
- Configuring a filter requires vault-admin access to both the source vault and policy vault.
- Destination credentials are not resolved until a successful continuation returns.
- Continuations are exact-request, single-use, short-lived (30 seconds), and retain the original matched service to prevent configuration TOCTOU.
- Policy-vault capabilities cannot invoke another filter.
- HTTPS uses normal system trust; HTTP is allowed only for literal loopback filter endpoints.
- `AGENT_VAULT_FILTER_PROXY_URL` is the advertised callback URL for remote filters and must be HTTPS except literal loopback HTTP.
- Reserved `X-Agent-Vault-*` headers are removed on both request and response paths.
- Bodies stay streamed.

## Missing comparison artifact

At restoration time, this checkout has no `ad_hoc/issue-407/` directory, no matching file in local Git history, and no locally available `service-filters.plan.md`. The previous conversation paused before it could inspect the fork plan.
