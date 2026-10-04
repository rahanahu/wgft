# Choose your deployment

Choose a procedure for the VPS and one for the home agent.
With any combination, finish by [adding a forwarding rule](setup.md#4-add-a-forwarding-rule).

| Location | Environment | Procedure |
|---|---|---|
| VPS | Linux with root | [Basic systemd steps](setup.md#2-run-the-vps-server-with-systemd) |
| VPS | No root or kernel WireGuard | [Userspace mode](setup-server-userspace.md) |
| VPS | Docker | [Docker server](setup-docker.md#vps-server) |
| Home | Linux with systemd | [Basic systemd steps](setup.md#3-run-the-linux-agent-with-systemd) |
| Home | Linux, kernel mode | [Kernel-mode agent](agent-kernel.md) |
| Home | Windows or macOS | [Desktop agents](setup-desktop.md) |
| Home | Docker | [Docker agent](setup-docker.md#home-agent) |

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
