# Setup

This guide contains the detailed installation and operating steps that are intentionally kept out of the project README.

## Requirements

The VPS side runs on Linux. The home agent also runs on Windows amd64, verified on Windows 11, and on macOS on Apple silicon, verified on macOS 27. Intel Macs are not supported. wgft is currently IPv4-only.

The home agent does not need root or a TUN device. Server requirements depend on the selected mode:

| | Kernel mode `kernel` | Userspace mode `userspace` |
|---|---|---|
| Root on the VPS | Required | Not required |
| Kernel and nftables | Kernel 6.1+, nftables 1.0.6+ | None |
| Forwarding path | Kernel WireGuard + nftables DNAT | wireguard-go + userspace netstack |
| If the wgft process stops or crashes | Configured forwarding continues | Forwarding stops |
| Rate-limit evaluation | Kernel | wgft process |
| Memory of `wgft server` | Mostly constant for normal DNAT rules; proxy-mode TCP grows with connection count | Grows with the number of flows, bounded by the flow caps |

In kernel mode, this resilience applies after wgft has created the WireGuard and nftables runtime state. If the wgft process crashes or restarts, that state remains in the kernel and forwarding continues. A VPS reboot clears the runtime state, so the wgft service must start again to rebuild it; keep the provided systemd service enabled for normal operation.

Use kernel mode when you have root on the VPS. Userspace mode is intended for VPS environments without root, kernels without WireGuard support, or container-only deployments.

In userspace mode, `wgft server` itself listens on each rule's listen port. If that port lies inside the host's ephemeral port range (the Linux default is 32768-60999, `net.ipv4.ip_local_port_range`), an outbound connection made by any process on the VPS can be using it as a source port, or holding it in TIME_WAIT for 60 seconds, at the moment the server tries to bind it. The bind then fails, and the rule stays declared but is reported not active, with the reason `bind failed: listen tcp4 :<port>: bind: address already in use`; the server log shows `rule <id>: not active: bind failed: ...`, and the Web UI's rule state and `rule_states` in `wgft rule ls --json` show the same reason. `wgft server` retries every 30 seconds, so the rule recovers on its own once the port is free; `SO_REUSEADDR` does not help. Kernel mode is not affected, because nothing on the VPS listens on the forwarded port. To avoid the collision, choose listen ports outside the ephemeral range, or reserve them with `sysctl net.ipv4.ip_local_reserved_ports=<ports>`.

In kernel mode, a rule set is applied to the kernel as one nftables batch, and wgft sizes the netlink socket buffers to that batch ([design.md](design.md) section 6.1). In the lab, the shipped systemd unit applied rule sets of up to 2000 rules in kernel mode both as a single `rule import` batch and as one generation per `rule add`; larger sets were not tried. No currently documented kernel-mode deployment is limited by `net.core.rmem_max` or `net.core.wmem_max`: the shipped systemd unit grants the capability wgft needs to size its own buffers past those sysctls, and the Docker deployment documented above runs userspace mode only, not kernel mode.

Kernel mode also relies on the host's conntrack table. `wgft server check` and the startup log warn if `nf_conntrack_max` is below wgft's recommended minimum of 65536, and suggest `sysctl -w net.netfilter.nf_conntrack_max=65536` to raise it.

Flows are capped at three levels: per rule, per source address, and process-wide. The agent cannot distinguish the original source address, so it applies only the per-rule and process-wide caps. In userspace mode, `wgft server` applies all three in Go. In kernel mode, a DNAT rule's traffic passes straight through nftables and never reaches `wgft server`, so only the per-source cap applies there, via nftables `ct count`; a proxy-mode rule's TCP connections terminate at `wgft server` itself even in kernel mode, so those get all three levels, counted the same way as in userspace mode. At a cap, new flows are refused and existing ones keep working. In kernel mode the home agent still relays the flows and is subject to its own caps.

The process-wide caps are `WGFT_MAX_UDP_FLOWS`, 8192 by default, and `WGFT_MAX_TCP_FLOWS`, 2048 by default. Server and agent are separate processes, so configure them separately when needed. From the two values wgft derives a Go runtime soft memory limit and prints it at startup. In the lab, a userspace-mode server with the default caps filled plus a traffic flood peaked at 208 MiB RSS. With `WGFT_MAX_UDP_FLOWS=2048` and `WGFT_MAX_TCP_FLOWS=1024`, the same load ran inside a 150 MiB cgroup limit. This has not yet been verified on a real 256 MiB VPS. With systemd, the provided unit also contains a commented `MemoryMax=` example; if enabled, keep it above the soft limit printed at startup.

To keep one rule from taking all of the capacity, wgft also caps each rule internally. That cap is not a setting. While only one rule accepts new flows, it may hold the whole process-wide budget. Once two or more rules accept new flows, a single rule stops at half the budget, rounded up, and the other half is reserved so that a flood against one rule still leaves room for the others. The per-source cap is a `wgft server`-only setting, `WGFT_MAX_UDP_FLOWS_PER_SOURCE` (default 256) and `WGFT_MAX_TCP_FLOWS_PER_SOURCE` (default 128), summed across all rules; it stops one source address from filling a rule's cap and locking out other users. It does not scale with the process-wide caps, so an operator with a lot of memory who raises those still keeps the default per-source cap unless they also raise this setting explicitly; 0 disables it for that protocol. The agent has no such setting: its only peer is the server, so every flow looks like it comes from the same address.

## 1. Install the binary

The same binary contains the server, agent, and CLI. Minimal images, such as some VPS templates and Proxmox LXC templates, do not include `curl`; install it first, for example `sudo apt install curl`.

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64.sha256
sha256sum -c wgft-linux-amd64.sha256
```

Use `arm64` instead of `amd64` on arm64 systems. Windows and macOS are covered in [Run the agent on Windows](#run-the-agent-on-windows) and [Run the agent on macOS](#run-the-agent-on-macos).

With Go 1.27 or newer:

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
sudo chmod 0644 /etc/wgft/server.env
```

Check the configuration before the first start:

```sh
sudo wgft server check
```

`check` reports the effective settings, detects a leftover WireGuard interface using the same server key, and prints any forwarding rules your existing firewall must allow. It also warns if the host's own input firewall would block wgft's own ports (WireGuard and the agent API) or a rule's listen port that wgft itself binds on the host (proxy-mode rules in kernel mode, every rule in userspace mode), and suggests the exact line to add; it never edits the firewall itself.

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

`/etc/wgft/server.env` is intentionally mode 0644 because it contains no secrets and the provided service runs as an unprivileged dynamic user. If you installed wgft using an older setup guide, the file may still be mode 0600. Run `sudo chmod 0644 /etc/wgft/server.env` before starting or restarting the service. This also applies when migrating from an older root-running unit.

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

The join string is a secret: whoever has it can register as this agent. The examples below set it as `WGFT_JOIN` in the environment or a dotenv file rather than passing it on the command line as a flag, because a flag value is visible to other local users via `ps` and stays in shell history.

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

### Run the agent on Windows

Download `wgft-windows-amd64.exe` and `wgft-windows-amd64.exe.sha256` from the [Releases page](https://github.com/rahanahu/wgft/releases). Open PowerShell in the folder they were saved to, for example Downloads, and verify the download:

```powershell
if ((Get-FileHash -Algorithm SHA256 .\wgft-windows-amd64.exe).Hash -ne (Get-Content .\wgft-windows-amd64.exe.sha256).Split(' ')[0]) {
    throw "SHA256 mismatch"
}
```

This prints nothing and lets you continue when the hash matches. On a mismatch it throws and stops the script, so you cannot run the binary by mistake. PowerShell's `-ne` compares strings case-insensitively, which matters here because `Get-FileHash` returns the hash in uppercase while the published `.sha256` file has it in lowercase. Then run:

```powershell
Rename-Item wgft-windows-amd64.exe wgft.exe
$env:WGFT_JOIN = '<join string>'
.\wgft.exe agent run
```

Double-clicking the .exe in Explorer instead of running it from PowerShell prints a reminder to do this and waits for Return before the window closes.

The join string contains `#`, so PowerShell needs it in single quotes. The first successful registration writes `%ProgramData%\wgft\agent.json`; the default location needs no administrator rights. Later starts need only:

```powershell
.\wgft.exe agent run
```

Windows Defender Firewall may prompt to allow `wgft.exe` on the first start, because wireguard-go listens on UDP on all interfaces. This was verified on Windows 11: the tunnel and relay keep working whether that prompt is allowed or cancelled, including across WireGuard key rotations, because the agent only makes outbound connections. Stop the agent with Ctrl+C or by closing the console window; a later start recovers and reuses the saved credentials.

The release binary is not code-signed. On the Windows 11 system used for verification, downloading it through a browser and starting it by double-clicking in Explorer triggered Microsoft Defender SmartScreen's "Windows protected your PC" warning, which blocked the app until More info and then Run anyway were selected. Depending on Windows or organization policy, the warning may not be bypassable. Choosing Run anyway there prevented the prompt from appearing again for that file, and starting it from PowerShell as described above did not show it at all.

wgft installs no Windows service, scheduled task, or tray icon. `agent run` runs as whichever user starts it, the way many game servers run on a gaming PC. Keeping it running across logons, for example with a shortcut in the Startup folder, is left to you; this has not been tested.

### Run the agent on macOS

The macOS build is for Apple silicon (arm64) and was verified on macOS 27. Intel Macs are not supported. Download it with `curl` in Terminal:

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64.sha256
shasum -a 256 -c wgft-darwin-arm64.sha256
sudo mkdir -p /usr/local/bin
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
```

Files downloaded with `curl` carry no quarantine mark. A web browser adds that mark, and Gatekeeper blocks a binary that carries it and is not notarized by Apple, which is the case for wgft. `/usr/local/bin` may not exist on Apple silicon Macs; `mkdir -p` creates it.

Register once from Terminal:

```sh
WGFT_JOIN='<join string>' /usr/local/bin/wgft agent run
```

The first successful registration prints `registered as agent <name>` and writes `~/Library/Application Support/wgft/agent.json`. The directory is created with mode 0700 and the file with mode 0600. Press Ctrl+C to stop this foreground agent before installing the daemon below; the credentials stay in `agent.json`. The daemon and a terminal agent cannot run at the same time, because the second one refuses to start with `credentials file is in use by another process`.

To keep the agent running, install [deploy/io.github.rahanahu.wgft.agent.plist](../deploy/io.github.rahanahu.wgft.agent.plist) as a LaunchDaemon. It runs `wgft agent run` with your user's rights through `UserName`, not as root, and points `WGFT_DATA_DIR` at the same `~/Library/Application Support/wgft`. Replace the `YOUR_USER` placeholders with your user name and home directory, then install and load it:

```sh
curl -LO https://raw.githubusercontent.com/rahanahu/wgft/main/deploy/io.github.rahanahu.wgft.agent.plist
sed -e "s|/Users/YOUR_USER|$HOME|g" -e "s|YOUR_USER|$(id -un)|g" io.github.rahanahu.wgft.agent.plist > wgft-agent.plist
plutil -lint wgft-agent.plist
sudo install -m 0644 -o root -g wheel wgft-agent.plist /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

The plist is readable by every user, so it holds no join string; the first registration above is done from Terminal for that reason. Check that the daemon is running and read its log:

```sh
sudo launchctl print system/io.github.rahanahu.wgft.agent | grep -E 'state|pid'
tail -f ~/Library/Logs/wgft-agent.log
```

On the VPS, `sudo wgft agent ls` shows `ok` in the `TUNNEL` column once the tunnel is up. launchd restarts the agent when it exits with an error or is killed, at most once every 10 seconds (`ThrottleInterval`). launchd has no counterpart to the systemd unit's `RestartPreventExitStatus=3`, and a configuration error, which exits with code 3, is restarted on the same interval, as checked on macOS 27. The agent then starts and fails every 10 seconds for as long as the error stands, `launchctl print` reports `last exit code = 3` and `state = spawn scheduled`, and nothing else marks the daemon as broken. Check the log if the agent keeps restarting.

Stop the daemon with:

```sh
sudo launchctl bootout system/io.github.rahanahu.wgft.agent
```

The plist stays in `/Library/LaunchDaemons`, so the daemon starts again at the next boot. To remove it for good, also run `sudo rm /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist`.

To upgrade, download the new `wgft-darwin-arm64` as above, then:

```sh
sudo launchctl bootout system/io.github.rahanahu.wgft.agent
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

wgft supports upgrading in place, but reverting to an older version afterward is not promised. Back up `~/Library/Application Support/wgft` before upgrading so you can restore it if you need to move back.

Two macOS behaviors shape this setup:

- Local Network privacy: started as a LaunchAgent from `~/Library/LaunchAgents`, the agent reached the default gateway, but connections to other LAN hosts failed with `connect: no route to host` and no permission dialog appeared. The same binary reached those hosts over UDP and TCP when started from Terminal, which passes on Terminal's own permission, and when run as a LaunchDaemon with `UserName` set to the same user, as this plist does. Attributing the failure to Local Network privacy is an inference from the symptoms; no system log entry confirmed it. `brew services` also uses LaunchAgents, so it may hit the same problem; this has not been tested. On macOS 27, the first connection a freshly installed binary made to another LAN host failed once with the same `connect: no route to host`, and every later connection to that host succeeded. Why it failed only once is not known.
- FileVault: with FileVault on, the LaunchDaemon started only when the user first logged in after a reboot, not at boot. It logged `network is unreachable` until the Mac's own network came up, then connected by itself. That wait was about 15 seconds on one Mac and about 60 seconds on a Mac whose Wi-Fi also connects only after login. Starting at boot without a login when FileVault is off, and keeping running after logout, have not been tested.

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

### Restrict the agent to the LAN addresses it needs

The agent connects to whatever target the server sends it, so an attacker who takes over the VPS could point it at any address on your LAN. `WGFT_AGENT_ALLOW_TARGETS` lists the addresses the agent may connect to:

```sh
WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458 wgft agent run --data-dir ~/.wgft
```

With systemd, write it next to `WGFT_JOIN` in `/etc/wgft/agent.env`:

```sh
printf 'WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458\n' | sudo tee -a /etc/wgft/agent.env >/dev/null
```

Entries are comma-separated and each one is `CIDR`, `CIDR:port` or `CIDR:lo-hi`. A bare address means that one host, and an entry without a port allows all of its ports. An IPv6 entry with a port needs brackets, as in `[2001:db8::/32]:8080`. The agent checks the address it is about to connect to, so a target that is a hostname is checked after it has been resolved, on every new connection and UDP session. A rule whose literal target falls outside the list gets no listener and shows as an error with the reason in `wgft agent ls` and the Web UI; for a port range, only the ports outside the list stay closed. Leaving the setting unset, the default, means no restriction. An invalid value stops the agent at startup with exit code 3, and so does a value that holds no entries at all, such as a lone comma: a security setting must not turn itself off silently.

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

When the agent opens a TCP listener for a new rule, it makes one trial connection to the target and closes it at once, so that a target which refuses connections is reported before any traffic arrives. The target sees one connection carrying no data. While nothing listens there, `wgft agent ls` shows the rule under `RULES` with `cannot connect to target`, and that state clears at the agent's next report, within 30 seconds of the target coming up. UDP rules carry no such check, because a datagram that is sent tells nothing about whether it arrived.

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

## Logs

The server and the agent write their logs to stderr and keep no log files of their own. With the provided systemd units, journald stores them:

```sh
sudo journalctl -u wgft -b            # server, since the last boot
sudo journalctl -u wgft-agent -f      # agent, follow new lines
sudo journalctl -u wgft --since "1 hour ago"
```

In Docker, use `docker compose -f deploy/server.compose.yaml logs` or `docker logs` on the container.

Once the data plane is applied and the admin and agent APIs are listening, the server logs one `server started` line with its version, mode, generation, and the number of rules and agents. If that line is missing, startup failed; the lines before it show where. Each successful rule change is logged with its origin, such as `cli rule add` or `ui import`, the affected rule IDs, and the resulting generation. To list only rule changes:

```sh
sudo journalctl -u wgft | grep 'rules: '
```

wgft does not log individual packets or successful flows, and never logs join strings, tokens, or private keys.

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