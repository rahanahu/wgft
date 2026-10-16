# Choose your deployment

Choose a procedure for the VPS and one for the home agent.
Kernel mode is recommended on the VPS and on a Linux agent.
Userspace mode is for environments where kernel mode cannot be used, and its guarantees are weaker: forwarding stops when the wgft process stops.
The [userspace design](../design/userspace/README.md) covers its limits.
With any combination, finish by [adding a forwarding rule](setup.md#4-add-a-forwarding-rule).

| Location | Environment | Mode | Procedure |
|---|---|---|---|
| VPS | Linux with root | Kernel: recommended | [Basic systemd steps](setup.md#2-run-the-vps-server-with-systemd) |
| VPS | No root or kernel WireGuard | Userspace | [Userspace mode](setup-server-userspace.md) |
| VPS | Docker | Userspace | [Docker server](setup-docker.md#vps-server) |
| Home | Linux with systemd | Kernel: recommended | [Basic systemd steps](setup.md#3-run-the-linux-agent-with-systemd), adding the [kernel-mode agent](agent-kernel.md) settings before enabling the service |
| Home | Linux with systemd | Userspace | [Basic systemd steps](setup.md#3-run-the-linux-agent-with-systemd) |
| Home | Windows or macOS | Userspace | [Desktop agents](setup-desktop.md) |
| Home | Docker | Userspace | [Docker agent](setup-docker.md#home-agent) |

## Issue a join string

- VPS with systemd: [Web UI or CLI](setup.md#issue-a-join-string)
- VPS without root: [Userspace-mode CLI](setup-server-userspace.md#start-without-root)
- VPS in Docker: [CLI inside the container](setup-docker.md#vps-server)

## Try a Linux agent in the foreground

[Download the binary](setup.md#1-install-the-binary) and run:
On arm64, replace `amd64` with `arm64` in the commands below too.

```sh
chmod +x wgft-linux-amd64
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

Put the issued join string in `<join string>`.
After registration, start it with `wgft agent run --data-dir ~/.wgft`.

[日本語](setup-alternatives.ja.md)
