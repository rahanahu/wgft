# Documentation

Start with the [setup guide](setup.md). The [design index](design.md) retains the original section numbers and links from older references.

## Guides

| Topic | Document |
| --- | --- |
| Installation | [Linux setup](setup.md), [deployment options](setup-alternatives.md), [Docker](setup-docker.md), [desktop agents](setup-desktop.md), [VPS userspace mode](setup-server-userspace.md) |
| Operation | [Operations guide](operations.md), [CLI reference](cli.md), [socket buffers](socket-buffers.md) |
| Development | [Architecture](architecture.md), [testing](testing.md), [Linux agent kernel mode](agent-kernel.md) |

Japanese versions of the user guides are linked from [the Japanese index](README.ja.md).

## Design specification

| Sections | Document |
| --- | --- |
| Background and 1-5: scope, topology, terms, network, control plane | [Overview and control plane](design-overview.md) |
| 6: VPS data plane | [VPS data plane](design-vps-dataplane.md) |
| 7: home data plane and memory bounds | [Agent data plane](design-agent-dataplane.md) |
| 7a.1-7a.8: internal layers, failure semantics, migration | [Internal architecture](design-internals.md) |
| 7a.9: Admission Policy compiler | [Policy compilation](design-policy.md) |
| 7a.10: Resource Guard | [Resource Guard](design-resource-guard.md) |
| 7a.11: compatibility contract | [Compatibility](design-compatibility.md) |
| 7b: Linux agent kernel mode | [Agent kernel data plane](design-agent-kernel.md) |
| 8-9: source IP and persistent state | [Address and state](design-state.md) |
| 10.1-10.2, 10.3-10.5: interfaces and operations | [Operations interface](design-interface.md) |
| 10.2a: server doctor | [Server diagnostics](design-server-doctor.md) |
| 10.2b: status | [Status output](design-status.md) |
| 10.2c: agent doctor | [Design index](design.md#102c-エージェント側の診断-wgft-agent-doctor) |
| 10.2d: Web UI doctor | [Web UI diagnostics](design-web-doctor.md) |
| 11-11b: security, configuration, startup failures | [Security and configuration](design-security.md) |
| 12-13: milestones and open questions | [Milestones and open questions](design-roadmap.md) |
| Revision record | [Revision record](design-revisions.md) |
