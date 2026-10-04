# Forwarding and operations

The [setup guide](setup.md) adds the first forwarding rule.
This page covers other forwarding options, the Web UI, diagnostics, and removal.

## Web UI

By default, the admin API listens only on `/run/wgft/admin.sock` inside the VPS.
Open an SSH tunnel from your computer, then visit `http://localhost:8686`:

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

If root SSH login is unavailable, set `WGFT_ADMIN=127.0.0.1:8686` in the VPS `server.env` and restart the server.
Then use:

```sh
ssh -L 8686:127.0.0.1:8686 vps
```

For access over Tailscale, set `WGFT_ADMIN_TAILSCALE=true`.
If the server starts before Tailscale has a tailnet address, restart the server.

## TCP and HTTPS forwarding

To pass the real client IP to a TCP target, use PROXY protocol v2.
The target must also support PROXY protocol v2:

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
```

wgft does not terminate TLS.
Manage HTTPS certificates and authentication on the home reverse proxy.
To forward HTTP too:

```sh
sudo wgft rule add --agent home --tcp 80 --to 192.168.1.30:80
```

For Caddy 2.11 or newer, use this listener wrapper to accept the real client IP on port 443:

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

Set `allow` to the LAN address of the agent host, which is the TCP peer Caddy sees.

Allow the public ports in the VPS firewall.
The Web UI's "+ Add rule" form can create the same rules.
See the [CLI reference](../cli.md) for source allow/deny lists and rate limits.

## Restrict agent targets

Set `WGFT_AGENT_ALLOW_TARGETS` on the agent if it should not connect to arbitrary LAN targets issued by the server.
With systemd, add a value like this to `/etc/wgft/agent.env`:

```text
WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458
```

Entries are comma-separated and may be `CIDR`, `CIDR:port`, or `CIDR:first-last`.
Bracket an IPv6 address with a port, as in `[2001:db8::/32]:8080`, although forwarding currently supports IPv4 only.
Omitting the setting allows all targets.
An out-of-list target does not open a listener, and `wgft agent ls` and the Web UI show the reason.
Whether or not this setting is present, the agent refuses broadcast and multicast targets in both modes.
These are `255.255.255.255`, multicast addresses, and the broadcast address of a network on the agent host, such as `192.168.1.255` for `192.168.1.0/24`.
The agent finds the broadcast address from its host's interface networks, not from an address ending in `.255`, and both ends of a `/31` network are ordinary hosts.
A rule with such a target does not forward, and `wgft agent ls` shows the reason.
Sending Wake-on-LAN packets to a broadcast address through a rule is not supported.
In userspace mode such packets may have reached the LAN before this check was added; they no longer do.
When the agent runs in a container on a Docker bridge network, as `deploy/agent.compose.yaml` does by default, the agent host's networks are the container's own, so the broadcast address of your LAN is not refused as a broadcast address there.
After changing the setting, run `sudo systemctl restart wgft-agent`.

## Logs and diagnostics

The provided systemd units write logs to journald:

```sh
sudo journalctl -u wgft -b
sudo journalctl -u wgft-agent -f
sudo wgft server doctor
sudo runuser -u wgft -- wgft agent doctor
```

The server logs `server started` once forwarding and the APIs are ready.
If it cannot apply saved rules, it logs `startup hold`, opens only the admin API, and retries.
You can still use `wgft rule rm` and `wgft rule disable` to fix the rules causing the hold.
After a process-only restart, old forwarding state may remain in the kernel.
What actually forwards depends on where the apply failed; inspect kernel state with `wgft server nft`.

In userspace mode, a public port can collide with the host's ephemeral port range.
The rule then reads `not active` with a `bind failed` reason.
Choose a port outside that range or reserve it with `net.ipv4.ip_local_reserved_ports`.

If an agent returns to a network used in the last ten minutes, it reports `ip-flapping`.
For expected roaming, dismiss it with `sudo wgft agent dismiss-warning home ip-flapping`.
For an agent that should not roam, investigate possible key or permanent-token duplication; see `wgft agent warnings --help`.

## Removal

Stop the server and preview what teardown will remove:

```sh
sudo systemctl disable --now wgft
sudo wgft server teardown --dry-run
```

`sudo wgft server teardown --purge --yes` also removes the server key, rules, and agent registrations.
Omit `--purge` to retain them.
A kernel-mode agent leaves an interface and nftables table after stopping; run [agent teardown](agent-kernel.md#return-to-userspace-mode) before removing credentials.
To remove a Docker agent and its credentials, run `docker compose -f deploy/agent.compose.yaml down -v`.
