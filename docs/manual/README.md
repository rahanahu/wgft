# User manuals

English | [日本語](README.ja.md)

With root access on a Linux VPS, use [Linux setup](setup.md) to keep the server and agent running and add the first rule.
For Windows, macOS, Docker or a VPS without root, choose a path from [deployment options](setup-alternatives.md).

| Goal | Guide and result |
| --- | --- |
| Create the first forward on Linux | [Linux setup](setup.md): install the binary, set up systemd, register the agent, add a rule and allow firewall ports. |
| Install in another environment | [Deployment options](setup-alternatives.md): choose [Windows and macOS agents](setup-desktop.md), [Docker](setup-docker.md), or [VPS userspace mode](setup-server-userspace.md). |
| Open the dashboard and forward TCP or HTTPS | [Forwarding and operations](operations.md): access the admin API, configure PROXY protocol and restrict agent targets. |
| Find where traffic stops | [Troubleshooting](troubleshooting.md): diagnose the VPS and agent, interpret results, check untested traffic and read logs. |
| Update without registering again | [Update guide](upgrade.md): preserve data, replace Linux binaries and understand downgrade limits. |
| Run a Linux agent in kernel mode | [Kernel agent](agent-kernel.md): check privileges and LAN targets, configure the service and return to userspace mode. |
| Resolve a Linux buffer warning | [Socket buffers](socket-buffers.md): configure the host and restart the affected process. |
| Remove wgft | [Removal](operations.md#removal): choose which forwarding state and data to retain. |
| Look up all command options | [CLI reference](../cli.md): read generated help, settings and examples. |

[All documentation](../README.md)
