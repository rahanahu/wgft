# Setup

Install wgft on a Linux VPS and a home Linux machine, then keep both running with systemd.
The VPS uses kernel mode, and the agent uses its default userspace mode.
You do not need to open a port on your home router.

For Windows, macOS, Docker, or other environments, first choose a procedure from [deployment options](setup-alternatives.md).

## Requirements

- VPS: Linux 6.1 or newer, nftables 1.0.6 or newer, root access, and kernel WireGuard support.
- Agent: Linux. Its default userspace mode needs neither root access nor a TUN device.
- Network: IPv4 only. Allow UDP 51820, TCP 8443, and the forwarded ports in the VPS firewall.

If the Linux agent logs a socket buffer warning, check the [host settings](socket-buffers.md).

## 1. Install the binary

Run this on both the VPS and the home Linux machine.
Install `curl` first if it is absent from a minimal OS image.

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64.sha256
sha256sum -c wgft-linux-amd64.sha256
```

On arm64 machines, replace `amd64` with `arm64` in the download and all later install commands.
Install the binary on the VPS:

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
```

## 2. Run the VPS server with systemd

Replace `vps.example.com` with the VPS public name or IP address.

```sh
sudo mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
sudo chmod 0644 /etc/wgft/server.env
sudo wgft server check
```

`server check` reports missing settings and firewall permissions but does not change the firewall.
Allow UDP 51820 and TCP 8443 in the VPS firewall.
For example, with ufw:

```sh
sudo ufw allow 51820/udp
sudo ufw allow 8443/tcp
```

Get the systemd unit from the same release as the binary:

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/server.service"
sudo install -m 0644 server.service /etc/systemd/system/wgft.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft
```

Check startup with `sudo systemctl status wgft`.
With firewalld, run `sudo firewall-cmd --permanent --add-port=51820/udp --add-port=8443/tcp` and `sudo firewall-cmd --reload`.

## 3. Run the Linux agent with systemd

### Issue a join string

Open an SSH tunnel from your computer to the VPS:

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

Replace `vps` with the VPS connection name, then open `http://localhost:8686` in a browser.
Choose "+ Add agent", enter `home`, and select "Generate join string".
Keep the displayed join string for the home agent.
If you cannot log in over SSH as root, see [Web UI access](operations.md#web-ui).

With the CLI, run `sudo wgft agent join-string --name home` on the VPS instead.
The join string is a secret, can be used once, and expires after one hour.

### Install the agent service

Run this on the home Linux machine.
Replace `<join string>` with the issued value:

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/agent.service"
sudo useradd --system --home-dir /var/lib/wgft --shell /usr/sbin/nologin wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_JOIN=<join string>\n' | sudo tee /etc/wgft/agent.env >/dev/null
sudo chown root:wgft /etc/wgft/agent.env
sudo chmod 0640 /etc/wgft/agent.env
sudo install -m 0644 agent.service /etc/systemd/system/wgft-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft-agent
```

The agent stores its credentials in `/var/lib/wgft/agent.json`.
Check the connection in the Web UI agent list or with `sudo wgft agent ls` on the VPS.

To use kernel mode on the Linux agent, see [kernel-mode agent](agent-kernel.md).

## 4. Add a forwarding rule

In the Web UI, choose "+ Add rule".
Set the agent to `home`, protocol to `UDP`, listen port to `2456-2457`, and target to `192.168.1.20:2456`.
This forwards UDP 2456 and 2457 on the VPS to the same ports on `192.168.1.20` at home.

With the CLI, run this on the VPS instead:

```sh
sudo wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
sudo wgft rule ls
```

Allow UDP 2456 and 2457 in the VPS firewall and check the rule state in the Web UI list.
If traffic does not arrive, run `sudo wgft server doctor` and see [logs and diagnostics](operations.md#logs-and-diagnostics).
The [operations guide](operations.md) covers TCP, HTTPS, and removal; [deployment options](setup-alternatives.md) cover other OSes and modes.
