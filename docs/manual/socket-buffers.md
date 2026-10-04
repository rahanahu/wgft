# Linux socket buffers

In Linux userspace mode, WireGuard needs a 7 MiB receive buffer and a 7 MiB send buffer on its UDP socket.
This applies to Linux agents and userspace-mode servers.
Kernel mode does not have this requirement.

Linux limits requests from an unprivileged process with `net.core.rmem_max` and `net.core.wmem_max`.
Set both to at least 7340032 on the host:

```sh
printf 'net.core.rmem_max = 7340032\nnet.core.wmem_max = 7340032\n' | sudo tee /etc/sysctl.d/90-wgft.conf
sudo sysctl --system
```

Restart the agent or server after changing the settings.
A socket keeps the size it got when it opened.
wgft checks Linux's reported value: both receive and send must report at least 14680064 bytes.

For the systemd agent, run the diagnostic as the agent user:

```sh
sudo runuser -u wgft -- wgft agent doctor
```

The `socket buffers` item under `Tunnel` reads `OK` when the requirement is met.
The agent still forwards when it reads `FAILED`, but logs `warning: the WireGuard UDP sockets`.
On Windows and macOS the agent does not measure the buffers, and `agent doctor` reads `NOT TESTED`.

## Containers

For an unprivileged Docker, LXC, or Incus container, set the sysctls on the **container host**.
Root inside the container and `docker run --sysctl` cannot change these limits.
After changing the host settings, restart a Docker agent container and check it with:

```sh
docker compose -f deploy/agent.compose.yaml exec wgft-agent wgft agent doctor
```

For an LXC or Incus agent, run `systemctl restart wgft-agent` inside the container and then run `agent doctor` as shown above.
The sysctl values visible inside a container depend on the kernel, so use the measured socket values to decide.
For a server container, read `docker compose -f deploy/server.compose.yaml logs` and check that the warning has stopped.

## Server notes

On a VM or dedicated host, the provided systemd server unit grants `CAP_NET_ADMIN`, allowing its WireGuard sockets to exceed these sysctl limits.
Inside a container or on an LXC-based VPS, that capability alone cannot exceed the host limits.
Whether a server on an LXC-based VPS can meet the requirement has not been verified.
Check the server's own warning log.

A userspace-mode server also requests a separate send buffer for each public UDP port.
If it logs `warning: the public UDP socket`, raise the host's `net.core.wmem_max` as above.
`CAP_NET_ADMIN` alone does not prevent this warning for that socket.

The [design document](../design/agent-dataplane.md) records the verified environments and mechanism.
