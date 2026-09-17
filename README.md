# wgft - WireGuard Forwarding Tool

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/rahanahu/wgft/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

English | [日本語](README.ja.md)

wgft forwards TCP and UDP traffic from a VPS to services on your home network over WireGuard. The home agent connects outward to the VPS, so you do not need to open ports on the home router and it works behind CGNAT or double NAT.

```mermaid
flowchart LR
  c1[client] -->|UDP 2456| s
  c2[client] -->|TCP 443| s
  subgraph vps[VPS - public IP]
    s[wgft server]
  end
  s ==>|WireGuard tunnel| a
  subgraph home[home - no open ports]
    a[wgft agent] --> g[game server<br>192.168.1.20:2456]
    a --> p[reverse proxy<br>192.168.1.30:443]
  end
```

wgft is aimed at workloads where arbitrary TCP/UDP forwarding matters, especially game servers. HTTPS also works, but wgft does not terminate TLS or provide authentication; those stay with your reverse proxy at home.

## Features

- One binary contains the VPS server, home agent, and CLI
- Kernel mode uses the kernel's WireGuard and nftables DNAT path, so forwarding survives a wgft process restart
- Userspace mode works without root and can run entirely in a container
- TCP and UDP port/range forwarding
- Per-rule allow/deny lists and rate limits
- Rule changes do not disconnect unrelated sessions
- Optional PROXY protocol v2 for preserving the real client IP on TCP rules
- Web dashboard for agents, rules, warnings, and forwarding state
- `wgft server teardown` removes only state created by wgft

## Why wgft?

wgft was inspired by Pangolin. Pangolin showed how useful the VPS-to-home tunnel model can be, but for game servers and other raw TCP/UDP services I wanted a smaller tool focused on port forwarding.

wgft therefore stays deliberately narrow: WireGuard for the tunnel, nftables for kernel forwarding, and simple TCP/UDP rules. It does not provide TLS termination, SSO, certificate management, or application publishing; those are left to a reverse proxy or other software.

## Modes

| | Kernel mode `kernel` | Userspace mode `userspace` |
|---|---|---|
| Root on the VPS | Required | Not required |
| Kernel and nftables | Kernel 6.1+, nftables 1.0.6+ | None |
| Forwarding path | Kernel WireGuard + nftables DNAT | wireguard-go + userspace netstack |
| If the wgft process stops or crashes | Configured forwarding continues | Forwarding stops |
| Rate-limit evaluation | Kernel | wgft process |

In kernel mode, forwarding stays in the kernel if the wgft process crashes or restarts after startup. A VPS reboot clears that runtime state, so wgft must start again to restore forwarding. Keep the provided systemd service enabled for normal operation so reboot recovery happens automatically.

Use kernel mode when you have root on the VPS. Use userspace mode when root or kernel WireGuard is unavailable, or when you want to run the server in a container.

Both sides currently run on Linux and wgft is IPv4-only. The home agent does not need root or a TUN device.

## Quick start

This is the shortest path for the common setup: kernel mode on a Linux VPS and a plain binary agent at home. For userspace mode, Docker, systemd details, firewall notes, HTTPS, and teardown, see the [setup guide](docs/setup.md).

### 1. Install wgft

Download the release binary on both machines:

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
chmod +x wgft-linux-amd64
```

Use `arm64` instead of `amd64` on arm64 systems.

### 2. Start the VPS server

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
sudo chmod 0600 /etc/wgft/server.env
sudo wgft server check
sudo wgft server run
```

Open UDP 51820 and TCP 8443 on the VPS firewall. `wgft server check` also prints any forwarding exceptions required by an existing firewall.

Kernel mode requires IPv4 forwarding. wgft sets `net.ipv4.ip_forward=1` when needed; `wgft server teardown` reports how to revert it.

In another VPS shell, create a one-time join string:

```sh
sudo wgft agent join-string --name home
```

### 3. Start the home agent

```sh
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

The credentials are stored in `~/.wgft/agent.json`; the join string is needed only for the first registration.

### 4. Add a rule

Back on the VPS:

```sh
sudo wgft agent ls
sudo wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
```

For a port range, `--to` specifies the first destination port. This example maps VPS UDP 2456 to `192.168.1.20:2456` and UDP 2457 to `192.168.1.20:2457`.

Open the forwarded port on the VPS firewall. Once the rule is active, traffic arriving at the VPS is sent through the WireGuard tunnel to the home target.

## Web UI

![wgft dashboard](docs/images/dashboard.png)

The dashboard shows agent connectivity, rules, drop counters, warnings, and the active nftables state. It can also issue join strings and manage ordinary rule operations.

The admin API is not exposed publicly by default; it listens on `/run/wgft/admin.sock`. Reach it through SSH:

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

Then open `http://localhost:8686`. Other admin access options are documented in the [setup guide](docs/setup.md#web-ui).

## Documentation

- [Setup guide](docs/setup.md) - kernel/userspace modes, rootless operation, Docker, systemd, HTTPS, Web UI access, and teardown
- [CLI reference](docs/cli.md) - generated command reference with examples
- [Design](docs/design.md) - protocol, security, forwarding behavior, and design decisions
- [Architecture](docs/architecture.md) - package layout and code paths
- [CLAUDE.md](CLAUDE.md) - project development conventions and test setup

`wgft <command> --help` also includes examples for every command.

## Status

Alpha, v0.2.0. Kernel mode has been verified on the author's VPS/home setup for UDP and TCP forwarding, NAT traversal, reconnects, reboot recovery, and teardown. Userspace mode has been verified in the development lab. See the design and setup documentation for implementation and deployment details.

## Security

The provided server systemd unit runs wgft as an unprivileged user with only the capabilities needed for forwarding. The public surface is WireGuard, the agent API, and ports you explicitly forward; the admin API is local-only by default.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Third-party module licenses are collected in `THIRD_PARTY_LICENSES.txt` and included with releases and container images.
