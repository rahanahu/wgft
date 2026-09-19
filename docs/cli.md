# wgft command reference

Generated from the command help; do not edit by hand. `wgft <command> --help` prints the same text.
To regenerate after changing the help: `go test ./cmd/wgft -run TestCLIDocUpToDate -update`.

## Commands

| Command | What it does |
|---|---|
| [`wgft agent dismiss-warning`](#wgft-agent-dismiss-warning) | Dismiss a warning |
| [`wgft agent join-string`](#wgft-agent-join-string) | Issue an agent join string |
| [`wgft agent ls`](#wgft-agent-ls) | List registered agents |
| [`wgft agent pubkey`](#wgft-agent-pubkey) | Print the wg public key |
| [`wgft agent revoke`](#wgft-agent-revoke) | Revoke a permanent token |
| [`wgft agent rotate-key`](#wgft-agent-rotate-key) | Regenerate the wg key pair |
| [`wgft agent run`](#wgft-agent-run) | Run the agent |
| [`wgft agent warnings`](#wgft-agent-warnings) | List theft-detection warnings |
| [`wgft rule add`](#wgft-rule-add) | Add a rule |
| [`wgft rule allow add`](#wgft-rule-allow-add) | Add allow CIDRs |
| [`wgft rule allow rm`](#wgft-rule-allow-rm) | Remove allow CIDRs |
| [`wgft rule deny add`](#wgft-rule-deny-add) | Add deny CIDRs |
| [`wgft rule deny rm`](#wgft-rule-deny-rm) | Remove deny CIDRs |
| [`wgft rule disable`](#wgft-rule-disable) | Disable a rule |
| [`wgft rule enable`](#wgft-rule-enable) | Enable a rule |
| [`wgft rule import`](#wgft-rule-import) | Replace all rules with JSON, an array of rules |
| [`wgft rule ls`](#wgft-rule-ls) | List rules |
| [`wgft rule merge`](#wgft-rule-merge) | Merge two adjacent rules into one |
| [`wgft rule rate new-flow`](#wgft-rule-rate-new-flow) | Cap on new flows for the whole rule |
| [`wgft rule rate packet`](#wgft-rule-rate-packet) | Cap on packets for the whole rule |
| [`wgft rule rate per-source`](#wgft-rule-rate-per-source) | Cap on new flows per source IP |
| [`wgft rule rm`](#wgft-rule-rm) | Delete rules |
| [`wgft rule set`](#wgft-rule-set) | Change only an existing rule's group / note |
| [`wgft rule split`](#wgft-rule-split) | Split a range into two just before <port> |
| [`wgft server check`](#wgft-server-check) | Check the config and environment without starting |
| [`wgft server nft`](#wgft-server-nft) | Print the applied table inet wgft as-is |
| [`wgft server run`](#wgft-server-run) | Run the daemon |
| [`wgft server teardown`](#wgft-server-teardown) | Remove what wgft created: table inet wgft and the wg interface |
| [`wgft version`](#wgft-version) | Print the wgft version |

## wgft

```text
wgft forwards TCP and UDP ports of a VPS to services at home over WireGuard.

One binary holds both sides. Where each command runs:
  server ...                  on the VPS
  agent run|pubkey|rotate-key on the home side, next to the services
  agent ls|join-string|...    on the VPS, against the admin API
  rule ...                    on the VPS, against the admin API

Commands that talk to the admin API use the Unix socket of the running server
(WGFT_ADMIN, default unix:///run/wgft/admin.sock), so run them as root on the VPS.
Settings are WGFT_* environment variables; a dotenv file (--config) and flags are
other ways to pass the same values.
```

Flags:

```text
```

## wgft agent

```text
Agent-related commands.

On the agent host:
  run           run the agent: bring up the tunnel and relay incoming traffic to the LAN
  pubkey        print the wg public key; generate and save one if absent
  rotate-key    regenerate the wg key pair

On the VPS (against the admin API):
  ls            list registered agents
  join-string   issue a join string; one-time
  revoke        revoke a permanent token
  warnings      list theft-detection warnings
  dismiss-warning  dismiss a warning
```

## wgft agent dismiss-warning

Dismiss a warning after confirming it was legitimate. <kind> is ip-mismatch or
ip-flapping as printed by "agent warnings". Without [detail] every warning of
that kind for the agent is dismissed; with it, only the one whose DETAIL column
matches.

```text
wgft agent dismiss-warning <name> <kind> [detail] [flags]
```

Examples:

```sh
wgft agent dismiss-warning home ip-flapping
```

Flags:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft agent join-string

Issue a join string for a new agent. It is printed once, can be used once, and
expires after one hour. Issuing another one for the same name invalidates the
earlier unused one.

Give the string to the agent as WGFT_JOIN. It contains a #, so write it into a
dotenv file as it is, without quotes.

```text
wgft agent join-string [flags]
```

Examples:

```sh
wgft agent join-string --name home
```

Flags:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
      --name string     agent name
```

## wgft agent ls

List registered agents with the state of their stream and tunnel.

Columns: STREAM is the address the agent's control connection comes from,
HEARTBEAT its age, GEN the rule generation the agent has applied, TUNNEL ok or
error, WG_ENDPOINT and HANDSHAKE the WireGuard peer as the VPS sees it, RULES how
many rules the agent reports as working, WARN the number of open warnings.

```text
wgft agent ls [flags]
```

Examples:

```sh
wgft agent ls
wgft agent ls --json
```

Flags:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
      --json            output as JSON
```

## wgft agent pubkey

Print the agent's WireGuard public key. If the credentials file has no key yet,
one is generated and saved first. Registration does not need this; it is for
checking which key an agent uses.

```text
wgft agent pubkey [flags]
```

Examples:

```sh
wgft agent pubkey
wgft agent pubkey --data-dir /srv/wgft
```

Flags:

```text
      --config string     dotenv config file (default "/etc/wgft/agent.env")
      --data-dir string   data dir, env WGFT_DATA_DIR (default "/var/lib/wgft")
```

## wgft agent revoke

Revoke an agent. Its permanent token stops working, its stream is closed, its
WireGuard peer and tunnel address are reclaimed, and unused join strings issued
for the name stop working. Rules that point at the agent are kept but forward
nothing until an agent registers under that name again, which a new join
string allows.

```text
wgft agent revoke <name> [flags]
```

Examples:

```sh
wgft agent revoke home
```

Flags:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft agent rotate-key

Replace the agent's WireGuard key pair. With the agent running, the request goes
through its control socket and the agent reconnects with the new key at once;
with the agent stopped, the credentials file is rewritten. The server learns
the new public key over the stream, so nothing has to be done on the VPS.

```text
wgft agent rotate-key [flags]
```

Examples:

```sh
wgft agent rotate-key
```

Flags:

```text
      --config string     dotenv config file (default "/etc/wgft/agent.env")
      --data-dir string   data dir, env WGFT_DATA_DIR (default "/var/lib/wgft")
```

## wgft agent run

Agent host daemon. Brings up the tunnel and listeners first from the key in the credentials file (agent.json) and the last full state,
then connects to the server stream to receive the full state. On first run it registers with the join string (WGFT_JOIN); the name (WGFT_NAME) is
optional and normally left unset, since the join string is already bound to a name.

```text
wgft agent run [flags]
```

Examples:

```sh
WGFT_JOIN='wgft://vps.example.com:8443/TOKEN#sha256:...' wgft agent run
wgft agent run --config /etc/wgft/agent.env
```

Flags:

```text
      --config string       dotenv config file (default "/etc/wgft/agent.env")
      --data-dir string     data dir, env WGFT_DATA_DIR; holds agent.json (default "/var/lib/wgft")
      --join string         join string wgft://host:port/token#sha256:..., env WGFT_JOIN
      --max-tcp-flows int   process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS; lower it on hosts with little memory (default 2048)
      --max-udp-flows int   process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS; lower it on hosts with little memory (default 8192)
      --name string         agent name, env WGFT_NAME; optional, the join string is already bound to a name
```

## wgft agent warnings

```text
List theft-detection warnings. They appear when the same credentials seem to be
in use from two places:
  ip-mismatch  the stream and the WireGuard endpoint come from different
               addresses for a sustained time
  ip-flapping  the address of one channel went back to an earlier value within
               ten minutes
If it was you (a line change, a move), dismiss the warning. If not, revoke the
agent and register it again with a new join string.
```

```text
wgft agent warnings [flags]
```

Examples:

```sh
wgft agent warnings
```

Flags:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule

Manage forwarding rules via the admin API.

Flags:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule add

Add a forwarding rule. Give exactly one of --tcp and --udp. A port range
"lo-hi" maps onto the same number of ports at the target, starting at the port
in --to: --udp 2456-2457 --to 192.168.1.20:2456 reaches 2456 and 2457.

Without --proxy the rule is forwarded by the kernel (or by the wgft process in
userspace mode), and the service at home sees the agent as the client. With
--proxy the server terminates TCP itself, and --proxy-protocol then passes the
real client address to the target in a PROXY protocol v2 header. The target
must expect that header.

The command refuses a port that another process on the VPS already listens on;
--force overrides that.

```text
wgft rule add [flags]
```

Examples:

```sh
wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456
wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
```

Flags:

```text
      --agent string     agent name
      --disabled         add in a disabled state
      --force            ignore conflicts with ports already bound on the VPS
      --group string     group to bundle rules under; optional, alphanumerics and - _ ., up to 32 chars
      --note string      note describing the rule's purpose; optional, up to 120 chars
      --proxy            server accepts and relays TCP in proxy mode
      --proxy-protocol   add a PROXY protocol v2 header; use with --proxy
      --tcp string       TCP port to listen on at the VPS; range allowed
      --to string        target host:port on the home side; for a listen port range, the first port (the rest follow in order)
      --udp string       UDP port to listen on at the VPS; range allowed
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule allow

While the allow list of a rule is empty, every source may connect. Once it
holds at least one CIDR, every other source is dropped. The deny list is
checked first.

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule allow add

Add CIDRs to the allow list of a rule. From the first entry on, sources outside
the list are dropped, and their open sessions are cut.

```text
wgft rule allow add <id> <cidr>...
```

Examples:

```sh
wgft rule allow add r_01M2R009 192.0.2.0/24
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule allow rm

Remove CIDRs from the allow list. Removing the last one opens the rule to every source again.

```text
wgft rule allow rm <id> <cidr>...
```

Examples:

```sh
wgft rule allow rm r_01M2R009 192.0.2.0/24
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule deny

Sources in the deny list of a rule are dropped. The list holds IPv4 CIDRs; a
single address is written as /32.

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule deny add

Add CIDRs to the deny list of a rule. Sessions from those sources that are
already open are cut at once.

```text
wgft rule deny add <id> <cidr>...
```

Examples:

```sh
wgft rule deny add r_01M2R009 203.0.113.7/32 198.51.100.0/24
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule deny rm

Remove deny CIDRs.

```text
wgft rule deny rm <id> <cidr>...
```

Examples:

```sh
wgft rule deny rm r_01M2R009 203.0.113.7/32
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule disable

Disable a rule without deleting it. The VPS stops listening on its ports and
open sessions are cut; ID, limits and lists are kept.

```text
wgft rule disable <id>
```

Examples:

```sh
wgft rule disable r_01M2R009
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule enable

Enable a disabled rule.

```text
wgft rule enable <id>
```

Examples:

```sh
wgft rule enable r_01M2R009
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule import

Replace the whole rule set with the JSON array in the file: rules not in the
file are deleted, the others are created or updated. The file holds the array
that "rule ls --json" prints under "rules", so an export can be edited and
imported back. Every agent named in it must be registered.

```text
wgft rule import <file.json> [flags]
```

Examples:

```sh
wgft rule ls --json | jq .rules > rules.json
wgft rule import rules.json
```

Flags:

```text
      --force   ignore conflicts with ports already bound on the VPS
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule ls

List rules, grouped by --group. ID is shortened; every rule command accepts such
a prefix as long as it is unambiguous. TARGET shows the effective target range.
MODE is proxy for rules added with --proxy and kernel for all others; in
userspace mode "kernel" rules are relayed by the wgft process, not the kernel.
DENY and ALLOW are the number of CIDRs, RATES the configured limits, DROPPED
the packets or flows dropped by them so far.

```text
wgft rule ls [flags]
```

Examples:

```sh
wgft rule ls
wgft rule ls --json
```

Flags:

```text
      --json   output as JSON
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule merge

Merge two rules whose listen ranges and target ranges are adjacent into one.
Their agent, protocol, mode, lists and limits must be the same. One batch, so
sessions stay up. The merged rule keeps the ID of <id1>.

```text
wgft rule merge <id1> <id2>
```

Examples:

```sh
wgft rule merge r_01M2R009 r_01M2R00A
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule rate

```text
Set or clear the rate limits of a rule. <rate> is N/unit with unit one of
second, minute, hour, day, week, for example 10/second or 30/minute; "none"
clears the limit. Each limit allows a burst of 5 on top of the rate, and what
exceeds it is dropped and counted in the DROPPED column of "rule ls".

  per-source  new flows per source address
  new-flow    new flows for the whole rule
  packet      packets for the whole rule

A flow is a TCP connection or, for UDP, a source address and port not seen
before. In kernel mode, flows dropped by per-source or new-flow never enter
the connection tracking table of the VPS, so these two protect the VPS as well
as the home line.
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule rate new-flow

Cap on new flows for the whole rule.

```text
wgft rule rate new-flow <id> <rate>
```

Examples:

```sh
wgft rule rate new-flow r_01M2R009 100/second
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule rate packet

Cap the packets of the whole rule. In kernel mode it counts every packet of
the rule; in userspace mode it applies to UDP datagrams only and has no effect
on TCP rules.

```text
wgft rule rate packet <id> <rate>
```

Examples:

```sh
wgft rule rate packet r_01M2R009 5000/second
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule rate per-source

Cap on new flows per source IP.

```text
wgft rule rate per-source <id> <rate>
```

Examples:

```sh
wgft rule rate per-source r_01M2R009 10/minute
wgft rule rate per-source r_01M2R009 none
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule rm

Delete rules. Open sessions through them are cut.

```text
wgft rule rm <id>...
```

Examples:

```sh
wgft rule rm r_01M2R009
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule set

Change only an existing rule's group / note; ID stays, no effect on forwarding.

```text
wgft rule set <id> [flags]
```

Examples:

```sh
wgft rule set r_01M2R009 --group game --note "game server"
wgft rule set r_01M2R009 --note ""
```

Flags:

```text
      --group string   group ("" to clear)
      --note string    note ("" to clear)
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft rule split

Split a port-range rule into two at <port>: the first keeps the ports below it,
the second starts at <port>. Targets follow. Both changes go out in one batch,
so sessions stay up. Use it to give part of a range its own limits or lists.

```text
wgft rule split <id> <port>
```

Examples:

```sh
wgft rule split r_01M2R009 2457
```

Flags inherited from parent commands:

```text
      --admin string    admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
      --config string   dotenv config file (default "/etc/wgft/server.env")
```

## wgft server

```text
VPS-side daemon. It holds the WireGuard tunnel to the agents, forwards the ports
of the rules, serves the agent API on a public port and the admin API with the
Web UI on a Unix socket.

Two forwarding modes, chosen with WGFT_MODE on the first start and recorded:
  kernel     kernel WireGuard and nftables; needs root to install
  userspace  wireguard-go inside the process; no root, runs in a container

Configuration is WGFT_* environment variables, a dotenv file (--config, default
/etc/wgft/server.env) or flags. The admin API has no password: only root and the
server itself can open its socket.
```

## wgft server check

Check the configuration and the environment without starting or changing
anything: the effective value and source of every setting, other nftables
tables that would drop or steal forwarded traffic, whether the host's own
input firewall would block wgft's own ports (WireGuard and the agent API),
net.ipv4.ip_forward, the size of the connection tracking table, and the
recorded mode and address range. Run it as root; without root the nftables
and firewall parts are skipped.

```text
wgft server check [flags]
```

Examples:

```sh
sudo wgft server check
```

Flags:

```text
      --admin string                   admin API listen address, env WGFT_ADMIN; unix:///path or host:port (default "unix:///run/wgft/admin.sock")
      --admin-host strings             extra names allowed by the Host check, env WGFT_ADMIN_HOST, comma-separated
      --admin-tailscale                also listen on the tailnet address, env WGFT_ADMIN_TAILSCALE
      --agent-api string               agent API listen address, env WGFT_AGENT_API, public (default "0.0.0.0:8443")
      --agent-api-host string          host:port to embed in the join string, env WGFT_AGENT_API_HOST
      --config string                  dotenv config file (default "/etc/wgft/server.env")
      --data-dir string                data dir, env WGFT_DATA_DIR; holds wgft.sqlite (default "/var/lib/wgft")
      --max-tcp-flows int              process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS; lower it on hosts with little memory (default 2048)
      --max-tcp-flows-per-source int   cap on concurrent TCP connections from one source address, summed over all rules, env WGFT_MAX_TCP_FLOWS_PER_SOURCE; 0 disables the per-source cap (default 128)
      --max-udp-flows int              process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS; lower it on hosts with little memory (default 8192)
      --max-udp-flows-per-source int   cap on concurrent UDP sessions from one source address, summed over all rules, env WGFT_MAX_UDP_FLOWS_PER_SOURCE; 0 disables the per-source cap (default 256)
      --mode string                    forwarding mode kernel or userspace, env WGFT_MODE; recorded on first run and checked thereafter
      --mtu int                        wg MTU, env WGFT_MTU (default 1420)
      --wg-address string              wg address range, env WGFT_WG_ADDRESS (default "10.200.0.1/24")
      --wg-endpoint string             WireGuard reachable host:port handed to agents, env WGFT_WG_ENDPOINT
      --wg-interface string            WireGuard interface name, env WGFT_WG_INTERFACE (default "wgft0")
      --wg-port uint16                 WireGuard listen UDP port, env WGFT_WG_PORT (default 51820)
```

## wgft server nft

Print the nftables table the server has applied, as "nft list table inet wgft"
shows it. In userspace mode there is no table and the command says so.

```text
wgft server nft [flags]
```

Examples:

```sh
sudo wgft server nft
```

Flags:

```text
      --admin string   admin API address, env WGFT_ADMIN (default "unix:///run/wgft/admin.sock")
```

## wgft server run

Run the server in the foreground. This is what the systemd unit and the
container image start. On a conflict that a restart cannot fix (someone else's
WireGuard interface, a port or address already in use, a kernel without
WireGuard) it exits with code 3.

```text
wgft server run [flags]
```

Examples:

```sh
wgft server run
wgft server run --mode userspace --wg-endpoint vps.example.com:51820
```

Flags:

```text
      --admin string                   admin API listen address, env WGFT_ADMIN; unix:///path or host:port (default "unix:///run/wgft/admin.sock")
      --admin-host strings             extra names allowed by the Host check, env WGFT_ADMIN_HOST, comma-separated
      --admin-tailscale                also listen on the tailnet address, env WGFT_ADMIN_TAILSCALE
      --adopt-existing                 adopt an existing interface whose key does not match; default is to treat it as someone else's and abort
      --agent-api string               agent API listen address, env WGFT_AGENT_API, public (default "0.0.0.0:8443")
      --agent-api-host string          host:port to embed in the join string, env WGFT_AGENT_API_HOST
      --config string                  dotenv config file (default "/etc/wgft/server.env")
      --data-dir string                data dir, env WGFT_DATA_DIR; holds wgft.sqlite (default "/var/lib/wgft")
      --max-tcp-flows int              process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS; lower it on hosts with little memory (default 2048)
      --max-tcp-flows-per-source int   cap on concurrent TCP connections from one source address, summed over all rules, env WGFT_MAX_TCP_FLOWS_PER_SOURCE; 0 disables the per-source cap (default 128)
      --max-udp-flows int              process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS; lower it on hosts with little memory (default 8192)
      --max-udp-flows-per-source int   cap on concurrent UDP sessions from one source address, summed over all rules, env WGFT_MAX_UDP_FLOWS_PER_SOURCE; 0 disables the per-source cap (default 256)
      --mode string                    forwarding mode kernel or userspace, env WGFT_MODE; recorded on first run and checked thereafter
      --mtu int                        wg MTU, env WGFT_MTU (default 1420)
      --wg-address string              wg address range, env WGFT_WG_ADDRESS (default "10.200.0.1/24")
      --wg-endpoint string             WireGuard reachable host:port handed to agents, env WGFT_WG_ENDPOINT
      --wg-interface string            WireGuard interface name, env WGFT_WG_INTERFACE (default "wgft0")
      --wg-port uint16                 WireGuard listen UDP port, env WGFT_WG_PORT (default 51820)
```

## wgft server teardown

Clean up after a stopped server. Removes only what wgft created itself.
Refuses if it is still running (run systemctl disable --now wgft first). Removes table inet wgft and the wg
interface, and with --purge the server database (keys, certificates, rules, agents) too. Other tables, firewall ports, and ip_forward are not
reverted automatically; it only prints a list to revert by hand.

```text
wgft server teardown [flags]
```

Examples:

```sh
sudo systemctl disable --now wgft
sudo wgft server teardown --dry-run
sudo wgft server teardown
sudo wgft server teardown --purge
```

Flags:

```text
      --adopt-existing    remove wg even when the key does not match or the server database is missing
      --config string     dotenv config file (default "/etc/wgft/server.env")
      --data-dir string   data dir, env WGFT_DATA_DIR (default "/var/lib/wgft")
      --dry-run           only print what would be removed and the list to revert by hand
      --purge             also remove the server database (keys, certificates, rules, agents); agents must re-register
      --yes               skip the --purge confirmation
```

## wgft version

Print the wgft version.

```text
wgft version
```
