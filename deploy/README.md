# deploy - files for running wgft on real machines

The step-by-step procedure is in the [README](../README.md) (Setup section). This directory holds the files it refers to.

| File | Purpose |
| --- | --- |
| `server.service` | systemd unit for the VPS-side `server` (`ExecStart=wgft server run`). Runs as root (kernel WireGuard + nftables) |
| `server.env.example` | Template for `/etc/wgft/server.env`: site-specific settings such as `WGFT_MODE` and `WGFT_WG_ENDPOINT` (`WGFT_*` format) |
| `Dockerfile.agent` | Container for the home agent. Static binary, unprivileged, no TUN |
| `agent.compose.yaml` | Docker Compose for the agent: `WGFT_JOIN` / `WGFT_NAME` and the state volume |

Binaries are built with `../scripts/build-release.sh` into `dist/wgft-linux-<arch>` (a single file, no CGO).

The two sides are not symmetric. **The server needs privileges** (it configures wg0 and nftables over netlink). **The agent is unprivileged** (user-space wireguard-go + gVisor netstack, so no TUN and no NET_ADMIN; it only needs outbound UDP and reachability to the LAN targets).

## Removal

On the VPS, `wgft server teardown` removes only what wgft created (`table inet wgft` and the wg interface; with `--purge` also the server database with keys and certificates). It refuses to run while the server is up, so stop it first. It never reverts other tables, firewall ports or `ip_forward` by itself; it prints the concrete values to revert by hand.

```sh
sudo systemctl disable --now wgft
sudo wgft server teardown --dry-run     # show what would be removed and what to revert by hand
sudo wgft server teardown --purge --yes # do it (--purge also removes keys and certificates)
```

On the home side:

```sh
# with compose, including the state volume
docker compose -f deploy/agent.compose.yaml down -v
# with the bare binary, stop it and remove the credentials file (agent.json) and its neighbours
# from the directory you passed to --data-dir (the README uses ~/.wgft; the default is /var/lib/wgft)
#   rm -f ~/.wgft/agent.json ~/.wgft/agent.json.lock ~/.wgft/agent.json.sock
```

If you run `wgft agent revoke <name>` on the VPS first, a running agent stops with 401 and its peer, conntrack entries and assigned address are reclaimed.
