# Diagnose failed forwarding

English | [日本語](troubleshooting.ja.md)

Start on the VPS with `server doctor`, then inspect the agent host if the result points there.
These checks describe current observations; they keep no history and do not prove that an external client can use the service.
For a server that has not started, use [server check](../cli.md#wgft-server-check) and the startup log first.

## 1. Locate the failing rule on the VPS

With the supplied Linux systemd deployment:

```sh
sudo wgft server doctor
sudo wgft rule ls
```

The first command surveys the server, agents and rules.
Use the rule ID from the list to follow one rule from the public side to its target:

```sh
sudo wgft server doctor r_01M2R009
```

Replace `r_01M2R009` with the affected rule's ID.
The command reads the running server's admin API; the default is `/run/wgft/admin.sock`.
Use the same `WGFT_ADMIN` setting as the server if it differs.
For Docker, run the command inside the server container using the [Docker guide's CLI route](setup-docker.md#vps-server).
The Web UI also has diagnostics for each rule.

| Result | Meaning and next action |
| --- | --- |
| `OK` | The observed check succeeded. Read its age; a successful observation can become stale. |
| `FAILED` | The check observed a failure. Follow its reason and suggested next check. |
| `UNKNOWN` | Evidence is stale, contradictory, or insufficient. Collect a current agent report or the missing evidence. |
| `NOT TESTED` | The command does not test this condition. Use the external or application check described below. |
| `SKIPPED` | An earlier failure prevented the check, or forwarding is disabled by configuration. Resolve that condition first. |

A disconnected agent's `last:` values are saved observations, not its current state.
A disabled rule or agent is deliberately not forwarding and does not make `server doctor` fail.
Check whether that pause was intentional before enabling it.

## 2. Inspect the agent host

Run the diagnostic as the same user and with the same data directory as the agent.
For the provided Linux systemd unit:

```sh
sudo runuser -u wgft -- wgft agent doctor
```

For a foreground agent using the README's directory, invoke `agent doctor` with that binary and `--data-dir ~/.wgft`.
The [data-directory option](../cli.md#wgft-agent-doctor) must name the running agent's directory.
If it reports missing credentials, check that path before issuing another join string or revoking the agent.
A new registration under an existing name is refused, and revocation disconnects the existing agent.
On Windows or macOS, use the same account and credentials location as in the [desktop setup](setup-desktop.md).
For Docker, the [agent setup](setup-docker.md#home-agent) includes the diagnostic command inside the container.

`agent doctor` reads credentials, host information and the running agent's local control socket.
It resolves the API and WireGuard endpoint names but makes no connection to a forwarding target.
Its brief shared lock can race with startup; the supplied systemd unit retries a start that loses that race.
Running it as root hides the agent user's file-permission problems, so `host.privileges` becomes `UNKNOWN`.

In userspace mode, a stopped agent cannot forward and its process check fails.
In kernel mode, configured forwarding can continue after the process stops; the verdict uses the interface, nftables table and forwarding settings instead.
To read a stopped kernel-mode agent's kernel state, use `sudo wgft agent doctor`.
Without `CAP_NET_ADMIN`, unreadable kernel evidence produces exit 2.
The [kernel agent guide](agent-kernel.md) explains the target and service requirements.

## 3. Check the untested parts of the route

The VPS cannot establish that its own public DNAT port works from outside.
Test a TCP port from another host, or use the service's real client.
For UDP, use the real client and check the service's response: a bare UDP send does not establish delivery.
A UDP target can therefore remain `NOT TESTED` even when its listener is open.
Its last-reply value is an observation and does not change that verdict.

For TCP, `server doctor` can optionally open one connection through the tunnel and agent to the target:

`--probe` creates a real target connection and accepts one TCP rule at a time.
`--from` evaluates the supplied address against the rule's source allow/deny lists; it does not impersonate an external client or test the public firewall.
Without `--probe`, `server doctor` does not dial a target.

## Common findings

| Finding | Check or action |
| --- | --- |
| Public traffic never arrives | Allow the forwarded TCP or UDP ports as well as UDP 51820 and TCP 8443 in the VPS firewall. For a Docker bridge server, publish each forwarded port in compose too. |
| Target rejected by the agent | Compare the rule with the running agent's `WGFT_AGENT_ALLOW_TARGETS`. Both modes refuse broadcast and multicast targets; kernel mode also needs a suitable LAN target. See [target restrictions](operations.md#restrict-agent-targets) and [kernel agent targets](agent-kernel.md). |
| `not active` with `bind failed` in userspace mode | Check port ownership. A public port can collide with the host's ephemeral range; choose one outside that range or reserve it with `net.ipv4.ip_local_reserved_ports`. |
| Socket buffer warning on Linux | Follow the [socket buffer guide](socket-buffers.md) on the host, including the container host for Docker, then restart the agent or server to reopen its sockets. The agent's buffer check can fail without raising its exit code. |
| Userspace-mode TCP transfers sometimes crawl | If `nstat -az UdpRcvbufErrors` grows where the agent or server runs, a UDP socket there is dropping packets. Check the requirement in [slow transfers when the requirement is not met](socket-buffers.md#slow-transfers-when-the-requirement-is-not-met). |
| `startup hold` in the server log | Saved rules could not be applied. The admin API stays available and the server retries. Use `wgft rule rm` or `wgft rule disable` to correct the affected rules. In kernel mode, inspect `wgft server nft` because old forwarding can remain after a process restart. |
| `ip-flapping` | A return to a network used within the last ten minutes caused the warning. For expected roaming, use `sudo wgft agent dismiss-warning home ip-flapping`; otherwise investigate duplicated keys or permanent tokens with `wgft agent warnings --help`. |

## Logs and exit codes

For the supplied systemd services:

```sh
sudo journalctl -u wgft -b
sudo journalctl -u wgft-agent -f
```

`server started` means forwarding and the APIs are ready.
Read logs to investigate when a failure began.

| Code | `server doctor` | `agent doctor` |
| --- | --- | --- |
| 0 | No check is `FAILED`. | No item used for the mode's verdict is `FAILED`. |
| 1 | At least one check is `FAILED`. | At least one verdict item is `FAILED`. |
| 2 | No report could be produced, for example an unavailable admin API or missing rule. | Permissions prevented a complete verdict; this takes precedence over exit 1. Invalid arguments also exit 2 before a report. |
| 3 | A setting is invalid. | A setting is invalid. |

Exit 0 can include unknown or untested conditions and deliberate pauses.
Read the individual checks before treating it as evidence that a service works.
`--json` keeps the diagnostic exit behavior.
The complete options, machine fields and verdict rules are in the [server doctor](../cli.md#wgft-server-doctor) and [agent doctor](../cli.md#wgft-agent-doctor) references.

[User manuals](README.md) · [Forwarding and operations](operations.md)
