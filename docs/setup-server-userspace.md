# Run the VPS in userspace mode

Use userspace mode on a VPS without root or kernel WireGuard.
The `wgft server` process forwards traffic, so forwarding stops when it stops.
Allow WireGuard UDP 51820, agent API TCP 8443, and every forwarded port in the VPS firewall.

At the default flow limits, the server needs about 5.9 GiB of host memory even with one agent and one forwarded TCP port.
This is the documented worst-case estimate: the flow state, buffers and other holdings counted in the calculation, each filled to its limit at once by an attack.
It is not a normal-use estimate.
Lower flow limits cannot bring this below about 2.9 GiB.
The [design document](design.md) gives the calculation.
Check the Linux [socket buffer requirement](socket-buffers.md) too.

## Run with systemd

Follow the [basic VPS steps](setup.md#2-run-the-vps-server-with-systemd), setting only the mode in `/etc/wgft/server.env` to `WGFT_MODE=userspace`.
The provided `server.service` is shared by both modes.
On a VM or dedicated host, the unit's `CAP_NET_ADMIN` lets the WireGuard sockets get the required buffers.
On an LXC-based VPS, the host sysctls decide; whether the server can meet the requirement has not been verified.
Check the server log for warnings.

## Start without root

[Download and verify the binary](setup.md#1-install-the-binary), then keep it, configuration, and data in your home directory.
On arm64, replace `amd64` with `arm64` in the install command below too.
Replace `vps.example.com` with the VPS public name or IP address:

```sh
mkdir -p ~/.local/bin
install -m 0755 wgft-linux-amd64 ~/.local/bin/wgft
install -d -m 0700 ~/wgft
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\nWGFT_DATA_DIR=%s/wgft\nWGFT_ADMIN=unix://%s/wgft/admin.sock\n' "$HOME" "$HOME" > ~/wgft/server.env
chmod 0600 ~/wgft/server.env
~/.local/bin/wgft server run --config ~/wgft/server.env
```

An ordinary user cannot bind ports below 1024 directly.
For later CLI commands, pass `--config ~/wgft/server.env` instead of using `sudo`.
If the host socket buffer limits are too low, changing them requires root on the host.

Issue the join string on the VPS with `~/.local/bin/wgft agent join-string --name home --config ~/wgft/server.env`.
Continue with [agent installation](setup.md#3-run-the-linux-agent-with-systemd).
After the agent connects, add the [forwarding rule](setup.md#4-add-a-forwarding-rule) on the VPS:

```sh
~/.local/bin/wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game --config ~/wgft/server.env
```

Allow UDP 2456 and 2457 in the VPS firewall too.
