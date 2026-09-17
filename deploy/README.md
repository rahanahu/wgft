# deploy - files for running wgft on real machines

The step-by-step procedure is in the [README](../README.md) (Setup section). This directory holds the files it refers to.

| File | Purpose |
| --- | --- |
| `server.service` | systemd unit for the VPS-side `server` (`ExecStart=wgft server run`). Runs as an unprivileged `DynamicUser=` with `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`, sandboxed (kernel WireGuard + nftables) |
| `server.env.example` | Template for `/etc/wgft/server.env`: site-specific settings such as `WGFT_MODE` and `WGFT_WG_ENDPOINT` (`WGFT_*` format) |
| `Dockerfile.server` | Container for the server in the userspace mode (docs/design.md section 6.3). Static binary, unprivileged, no nftables, runs as uid 65532 |
| `server.compose.yaml` | Docker Compose for the server: `WGFT_WG_ENDPOINT` and the state volume. Pulls `ghcr.io/rahanahu/wgft-server` (amd64 and arm64, built from `Dockerfile.server` by the release workflow); `build:` is there, commented out, for building from source |
| `agent.service` | systemd unit for the home agent as a plain binary. Runs as the unprivileged user `wgft`; `/etc/wgft/agent.env` holds `WGFT_JOIN` for the first start |
| `Dockerfile.agent` | Container for the home agent. Static binary, unprivileged, no TUN, runs as uid 65532 |
| `agent.compose.yaml` | Docker Compose for the agent: `WGFT_JOIN` / `WGFT_NAME` and the state volume. Pulls `ghcr.io/rahanahu/wgft-agent` (amd64 and arm64, built from `Dockerfile.agent` by the release workflow); `build:` is there, commented out, for building from source |

Binaries are built with `../scripts/build-release.sh` into `dist/wgft-linux-<arch>` (a single file, no CGO).

The two sides are not symmetric in kernel mode. **The server needs privileges** (it configures wg0 and nftables over netlink). **The agent is unprivileged** (user-space wireguard-go + gVisor netstack, so no TUN and no NET_ADMIN; it only needs outbound UDP and reachability to the LAN targets). The server's userspace mode drops that asymmetry: `Dockerfile.server` runs the same wireguard-go and netstack as the agent, so it needs no privileges either. It replaces kernel mode, not just its packaging; see docs/design.md section 6.3 for what that trades away.

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
