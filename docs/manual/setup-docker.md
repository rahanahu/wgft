# Run with Docker

The provided compose files run both server and agent in userspace mode.
Set the [socket buffers](socket-buffers.md) on the container host.
The server also has a [worst-case memory requirement](setup-server-userspace.md).

## VPS server

Clone the repository, then set `WGFT_WG_ENDPOINT` and the public `ports:` in [deploy/server.compose.yaml](../../deploy/server.compose.yaml):

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
docker compose -f deploy/server.compose.yaml up -d
```

Run CLI commands as `docker compose -f deploy/server.compose.yaml exec wgft-server wgft ...`.
Issue a join string with `docker compose -f deploy/server.compose.yaml exec wgft-server wgft agent join-string --name home`.
With `network_mode: host`, you need not list the `ports:`, but an unprivileged container cannot bind ports below 1024.

## Home agent

Set `WGFT_JOIN` in [deploy/agent.compose.yaml](../../deploy/agent.compose.yaml) to the join string issued on the VPS:

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
docker compose -f deploy/agent.compose.yaml up -d
docker compose -f deploy/agent.compose.yaml exec wgft-agent wgft agent doctor
```

If the agent cannot reach LAN targets, enable `network_mode: host` in the compose file.
Once the agent connects, [add a forwarding rule](setup.md#4-add-a-forwarding-rule).
Run this on the VPS:

```sh
docker compose -f deploy/server.compose.yaml exec wgft-server wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
```

Allow UDP 2456 and 2457 in the VPS firewall too.
If you use different public ports, also change `ports:` in the VPS compose file.

[日本語](setup-docker.ja.md)
