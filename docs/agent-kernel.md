# Kernel mode for the Linux agent

In kernel mode, the Linux host's WireGuard and nftables handle forwarding.
Configured forwarding continues while the agent process restarts.
This requires kernel WireGuard and `CAP_NET_ADMIN`.
There is no Docker procedure for this mode.

As in userspace mode, `WGFT_AGENT_ALLOW_TARGETS` can restrict where the agent forwards.
Use IPv4 LAN addresses for targets.
Loopback addresses such as `127.0.0.1` cannot be used.
A UDP service on the agent host itself must listen on that host's LAN address.
If it listens on all addresses, replies will not match the forwarded flow and will not reach the client.

## systemd configuration

Use the unit from the [basic Linux agent guide](setup.md#3-run-the-linux-agent-with-systemd).
The provided drop-in gives the agent `CAP_NET_ADMIN`; `agent.env` selects the mode:

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/agent.kernel.conf"
sudo install -D -m 0644 agent.kernel.conf /etc/systemd/system/wgft-agent.service.d/kernel.conf
printf 'WGFT_MODE=kernel\n' | sudo tee -a /etc/wgft/agent.env >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart wgft-agent
```

On a new host, run all commands above except restart before `systemctl enable --now wgft-agent` in the basic guide.
Do not add `ProtectKernelTunables=` to the unit: it prevents the agent from setting `net.ipv4.ip_forward` to 1 when needed.

While the agent runs, diagnose it as the agent user:

```sh
sudo runuser -u wgft -- wgft agent doctor
```

Forwarding continues while the agent is stopped, but rule changes and externally removed nftables state are not repaired.
Run `sudo wgft agent doctor` to inspect the stopped agent's kernel state.
An `nftables.conf` with `flush ruleset` removes the agent's table, so do not reload nftables while the agent is stopped.

## Return to userspace mode

Stop the agent and remove the remaining WireGuard interface and nftables table before changing modes:

```sh
sudo systemctl stop wgft-agent
sudo wgft agent teardown --dry-run
sudo wgft agent teardown
sudo sed -i '/^WGFT_MODE=/d' /etc/wgft/agent.env
sudo rm /etc/systemd/system/wgft-agent.service.d/kernel.conf
sudo systemctl daemon-reload
sudo systemctl start wgft-agent
```

`agent teardown` keeps registration and keys.
It does not restore `ip_forward` automatically; its output shows a command if a change is needed.
Before downgrading to v1.1.x, run teardown with a v1.2 or newer binary, then start the old version.

See section 7b of the [design document](design.md) for behavior and unverified environments.
