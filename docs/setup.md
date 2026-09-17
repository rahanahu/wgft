# Setup

This guide contains the detailed installation and operating steps that are intentionally kept out of the project README.

## Requirements

Both sides run on Linux and wgft is currently IPv4-only.

The home agent does not need root or a TUN device. Server requirements depend on the selected mode:

| | Kernel mode `kernel` | Userspace mode `userspace` |
|---|---|---|
| Root on the VPS | Required | Not required |
| Kernel and nftables | Kernel 6.1+, nftables 1.0.6+ | None |
| Forwarding path | Kernel WireGuard + nftables DNAT | wireguard-go + userspace netstack |
| If `wgft server` stops | Existing forwarding continues | Forwarding stops |
| Rate-limit evaluation | Kernel | wgft process |

Use kernel mode when you have root on the VPS. Userspace mode is intended for VPS environments without root, kernels without WireGuard support, or container-only deployments.

## 1. Install the binary

The same binary contains the server, agent, and CLI.

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64.sha256
sha256sum -c wgft-linux-amd64.sha256
```

Use `arm64` instead of `amd64` on arm64 systems.

With Go 1.26 or newer:

```sh
go install github.com/rahanahu/wgft/cmd/wgft@latest
```

## 2. Configure the VPS

wgft reads `WGFT_*` environment variables. The systemd setup reads `/etc/wgft/server.env`; [deploy/server.env.example](../deploy/server.env.example) documents all settings.

### Kernel mode

Install the binary and create the minimal configuration:

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
sudo chmod 0600 /etc/wgft/server.env
```

Check the configuration before the first start:

```sh
sudo wgft server check
```

`check` reports the effective settings, detects a leftover WireGuard interface using the same server key, and prints any forwarding rules your existing firewall must allow.

wgft does not edit your existing firewall. It enables `net.ipv4.ip_forward=1` when needed; teardown reports how to revert it.

Open UDP 51820 for WireGuard and TCP 8443 for the agent API. For example with ufw:

```sh
sudo ufw allow 51820/udp
sudo ufw allow 8443/tcp
```

With firewalld:

```sh
sudo firewall-cmd --permanent --add-port=51820/udp --add-port=8443/tcp
sudo firewall-cmd --reload
```

Install the provided service:

```sh
sudo install -m 0644 deploy/server.service /etc/systemd/system/wgft.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft
```

For an interactive test instead:

```sh
sudo wgft server run
```

### Userspace mode with systemd

Use the same service as kernel mode, but change the mode:

```sh
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
```

Open UDP 51820, TCP 8443, and every forwarded port in the VPS firewall. Forwarding stops while the server process is down.

### Userspace mode without root

Keep configuration and data in your home directory:

```sh
install -d -m 0700 ~/wgft
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\nWGFT_DATA_DIR=%s/wgft\nWGFT_ADMIN=unix://%s/wgft/admin.sock\n' "$HOME" "$HOME" > ~/wgft/server.env
chmod 0600 ~/wgft/server.env
wgft server run --config ~/wgft/server.env
```

Ports below 1024 cannot be bound directly by an ordinary user. In the remaining examples, use `--config ~/wgft/server.env` instead of `sudo` when running this way.

### Userspace mode in Docker

The server container uses userspace mode. Clone the repository, set `WGFT_WG_ENDPOINT` in [deploy/server.compose.yaml](../deploy/server.compose.yaml), and start it:

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# edit WGFT_WG_ENDPOINT in deploy/server.compose.yaml
docker compose -f deploy/server.compose.yaml up -d
```

Every forwarded port must appear under `ports:` in the compose file. `network_mode: host` avoids maintaining that list, but an unprivileged container cannot bind host ports below 1024.

When using the container, run CLI commands through:

```sh
docker compose -f deploy/server.compose.yaml exec wgft-server wgft ...
```

## 3. Register a home agent

Create a one-time join string on the VPS:

```sh
sudo wgft agent join-string --name home
```

The join string can be used once and expires after one hour. Quote it when passing it through a shell because it contains `#`.

### Run the agent as a binary

```sh
chmod +x wgft-linux-amd64
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

The first successful registration writes `~/.wgft/agent.json`. Later starts need only:

```sh
wgft agent run --data-dir ~/.wgft
```

### Run the agent with systemd

The provided unit runs as an unprivileged `wgft` user:

```sh
sudo install -m 0755 ~/.local/bin/wgft /usr/local/bin/wgft
sudo useradd --system --home-dir /var/lib/wgft --shell /usr/sbin/nologin wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_JOIN=<join string>\n' | sudo tee /etc/wgft/agent.env >/dev/null
sudo chown root:wgft /etc/wgft/agent.env
sudo chmod 0640 /etc/wgft/agent.env
sudo install -m 0644 deploy/agent.service /etc/systemd/system/wgft-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft-agent
```

The credentials then live in `/var/lib/wgft/agent.json`.

### Run the agent in Docker

Set `WGFT_JOIN` in [deploy/agent.compose.yaml](../deploy/agent.compose.yaml) and start it:

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# edit WGFT_JOIN in deploy/agent.compose.yaml
docker compose -f deploy/agent.compose.yaml up -d
```

If the container cannot reach LAN targets, enable `network_mode: host` in the compose file.

## 4. Add forwarding rules

Verify that the agent is connected:

```sh
sudo wgft agent ls
```

Add a UDP game-server rule:

```sh
sudo wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
```

For a port range, the target port is the first port; subsequent ports follow in order.

Forward HTTPS while preserving the real client address with PROXY protocol v2:

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
```

Open the forwarded ports in the VPS firewall as well.

Rules are distributed to the agent without disconnecting unrelated sessions. Source allow/deny lists and rate limits can be managed through the CLI; see [cli.md](cli.md).

## Web UI

The admin API listens on `/run/wgft/admin.sock` by default and is not exposed on the VPS network. Forward a local port over SSH:

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

Then browse to `http://localhost:8686` while the SSH session is open.

If root SSH login is disabled, set:

```text
WGFT_ADMIN=127.0.0.1:8686
```

and forward to the loopback listener instead:

```sh
ssh -L 8686:127.0.0.1:8686 vps
```

For Tailscale access, set `WGFT_ADMIN_TAILSCALE=true`. `WGFT_ADMIN_HOST` can add accepted host names.

## Publishing HTTPS

wgft does not terminate TLS. Forward ports 443 and 80 to a reverse proxy at home and let that proxy manage certificates and authentication.

For Caddy, port 443 can use PROXY protocol so access logs retain the real client IP:

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
sudo wgft rule add --agent home --tcp 80  --to 192.168.1.30:80
```

Caddy 2.11 or newer is required for the listener wrapper used here:

```text
{
    servers 192.168.1.30:443 {
        listener_wrappers {
            proxy_protocol {
                allow 192.168.1.30/32
            }
            tls
        }
    }
}

example.com {
    reverse_proxy 192.168.1.40:8080
}
```

The `allow` address should be the host running the wgft agent, which is the TCP peer seen by Caddy.

## Teardown

Stop the service and inspect what would be removed:

```sh
sudo systemctl disable --now wgft
sudo wgft server teardown --dry-run
```

Remove wgft-managed state:

```sh
sudo wgft server teardown --purge --yes
```

Without `--purge`, keys and certificates remain so the server keeps the same identity after restart. With `--purge`, server keys, rules, and agent registrations are removed and agents must be registered again.

For the Docker agent, remove its volume as well when you want to delete its credentials:

```sh
docker compose -f deploy/agent.compose.yaml down -v
```

## Command reference

`wgft <command> --help` includes examples. The complete generated reference is in [cli.md](cli.md).
