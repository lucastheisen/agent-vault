# Transition agent published ports when API access changes

Issue: <https://gitlab.mitre.org/mdev/condev/-/work_items/16>

## Context

Agent `publish_ports` normally use the workspace relay, `<workspace>-proxy`.
That relay is reachable on the workspace network and owns the host port binding.

When `agent_api_access` is enabled, the agent moves to the Agent Vault broker's private network.
Its published ports must instead use `<workspace>-agent-proxy`, the existing dual-network relay added for issue 14.
The workspace relay cannot reach the private agent, and the agent relay cannot bind a host port while the workspace relay still owns the same port.

`condev agent up` already removes the agent relay before restoring ordinary forwarding when API access is removed.
It does not remove the ordinary relay's matching port claims before creating the agent relay when API access is enabled.
That one-way transition leaves Docker to reject the second host-port binding.

## Design history

- **Remove the whole workspace relay before creating the agent relay.** Rejected.
  The workspace relay is also shared by alias forwarding, `condev expose`, and primary-container published ports.
  Destroying it would interrupt unrelated forwards and discard their desired-forward label state.
- **Attach the workspace relay to the broker network.** Rejected in issue 14.
  It would make a shared resource depend on the broker lifecycle and broaden the network boundary of unrelated forwarding.
- **Let Docker report the collision and require a manual reset.** Rejected.
  The two relay types are mutually exclusive owners for a configured agent port, so `agent up` has enough lifecycle information to reconcile the transition itself.
- **Remove matching ordinary forwards by target container name.** Rejected.
  The relay's forward reconciliation treats a host port and protocol as the ownership key.
  A matching port currently claimed for a different ordinary target still conflicts with the agent relay and must be released for the declared agent port to take ownership.

## Approach

Add a `RemovePorts` helper beside `EnsurePorts` in `pkg/workspace/expose.go`.
It will remove only the supplied `PortSpec` listen-port/protocol keys from the ordinary workspace relay, preserving every other forward and removing the relay only when no forwards remain.
It will reuse the existing `CurrentForwards`, `removeForwards`, `EnsureProxy`, and `RemoveProxy` behavior rather than duplicating proxy reconciliation.

In `cmd/condev/agent/up/up.go`, when broker-backed API access and agent `publish_ports` are both present:

1. Start the agent on the broker network as today.
2. Write any loopback relay address as today.
3. Call `RemovePorts` for the declared agent port specs on the ordinary workspace relay.
4. Call `EnsureAgentPorts` to claim those ports with the dual-network agent relay.

This ordering releases the conflicting host bindings immediately before the new owner claims them.
It does not alter the agent's network membership and does not expose the agent directly.

The existing no-broker flow remains the reverse transition:

1. Remove `<workspace>-agent-proxy` before normal forwarding is reconciled.
2. Use `EnsurePorts` to claim declared agent ports through the ordinary workspace relay.

## Out of scope

- Reconciling ports removed from configuration while neither relay owns an updated desired set.
- Changing alias or `condev expose` conflict semantics.
- Allowing an agent on the workspace or egress network.
- Changing Agent Vault rules, credentials, or broker policy.
- Automatically adding API-access rules from failed requests.
  That remains a follow-up design concern; any future recommendation must distinguish a missing injected credential from an upstream authorization failure and require user approval for configuration changes.

## Verification

- Add `pkg/workspace` tests showing `RemovePorts` preserves unrelated ordinary forwards and removes the ordinary relay only when the removed port was its last forward.
- Add agent-up tests showing API access removes the ordinary matching port claim before the agent relay is created.
- Preserve and extend the no-API-access test to show the agent relay is removed before ordinary forwarding is restored.
- Add a Docker smoke test that starts an agent with a loopback published port without API access, enables API access, reruns `agent up`, and confirms the callback remains reachable through the agent relay.
- Run `make fmt`, `make -j check test`, and `make build`.
