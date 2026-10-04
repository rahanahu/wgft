# Design specification

The body of the specification is written in Japanese. This index groups current contracts by the questions they answer.
Current main includes changes after release v1.4.1; consult the documentation at a release tag for that release's behavior.
The compatibility contract covers the Linux server and agent, plus the Windows agent within the range verified on Windows 11 hardware. The macOS agent remains outside the contract.

| Reader question | Topic and scope (Japanese body) |
| --- | --- |
| What does wgft forward? | [Overview](overview.md) and [network](network.md): IPv4 L4 forwarding, with TLS terminated at home |
| How do registration and updates work? | [Control plane](control/README.md): registration, stream, state publication, and rule batches |
| How does the VPS forward traffic? | [VPS data plane](vps/README.md): kernel DNAT, TCP proxy, and userspace relays |
| What does the default home mode require? | [Userspace forwarding and resources](userspace/README.md): socket requirements, relays, budgets, and retention limits |
| Can forwarding continue while the agent stops? | [Kernel agent](kernel-agent/README.md): Linux forwarding, reconciliation, and unverified deployments |
| How is declared state reconciled? | [Architecture](architecture/README.md): lifecycle, failures, wire, and package boundaries |
| How do policy and resource refusals differ? | [Admission Policy](policy.md) and [Resource Guard](resource/README.md): communication rules and backend budgets |
| What survives a restart? | [Source IP and stored state](state.md): source visibility, persistence, and ownership |
| How are faults and operational degradation distinguished? | [Diagnosis](diagnosis/README.md): server doctor, agent doctor, status, and Web UI |
| What protects administration and startup? | [Security and configuration](security/README.md): trust boundaries, precedence, startup refusal, and retries |
| How do operation and teardown work? | [Interface](interface.md) and [operations](operations/README.md): CLI/Web UI, logs, and owned-resource removal |
| What remains compatible after an upgrade? | [Compatibility](compatibility.md): names and meanings of public surfaces |
| What remains unsupported or proposed? | [Limitations and proposals](roadmap.md): current limitations, unverified behavior, and unimplemented designs |

## Design history

[Historical plans and revision records](history/README.md) preserve completed migration plans and past reviews. <!-- docs-history -->
[Legacy headings](../design.md) continue to forward to the corresponding specification.

[日本語](README.ja.md) · [All documentation](../README.md)
