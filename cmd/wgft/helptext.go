package main

import (
	"strings"

	"github.com/spf13/cobra"
)

// helpText は、コマンドごとの長い説明と使用例。コマンドの定義(agent.go、rule.go、server.go)には 1 行の
// Short だけを置き、--help と docs/cli.md に出る詳しい文はこの表にまとめる。キーは "wgft" を除いたパス。
type helpText struct {
	Long    string
	Example string
}

var helpTexts = map[string]helpText{
	"": {
		Long: `wgft forwards TCP and UDP ports of a VPS to services at home over WireGuard.

One binary holds both sides. Where each command runs:
  server ...                  on the VPS
  agent run|pubkey|rotate-key on the home side, next to the services
  agent ls|join-string|...    on the VPS, against the admin API
  rule ...                    on the VPS, against the admin API

Commands that talk to the admin API use the Unix socket of the running server
(WGFT_ADMIN, default unix:///run/wgft/admin.sock), so run them as root on the VPS.
Settings are WGFT_* environment variables; a dotenv file (--config) and flags are
other ways to pass the same values.`,
	},
	"agent join-string": {
		Long: `Issue a join string for a new agent. It is printed once, can be used once, and
expires after one hour. Issuing another one for the same name invalidates the
earlier unused one.

The join string is a secret: whoever has it can register as this agent. Give
it to the agent as WGFT_JOIN, in the environment or a dotenv file, rather than
the --join flag; a flag value is visible to other local users via ps and is
kept in shell history. It contains a #, so write it into a dotenv file as it
is, without quotes.`,
		Example: `  wgft agent join-string --name home`,
	},
	"agent ls": {
		Long: `List registered agents with the state of their stream and tunnel.

Columns: STREAM is the address the agent's control connection comes from,
HEARTBEAT its age, GEN the rule generation the agent has applied, TUNNEL ok or
error, WG_ENDPOINT and HANDSHAKE the WireGuard peer as the VPS sees it, RULES how
many rules the agent reports as working, WARN the number of open warnings.`,
		Example: `  wgft agent ls
  wgft agent ls --json`,
	},
	"agent revoke": {
		Long: `Revoke an agent. Its permanent token stops working, its stream is closed, its
WireGuard peer and tunnel address are reclaimed, and unused join strings issued
for the name stop working. Rules that point at the agent are kept but forward
nothing until an agent registers under that name again, which a new join
string allows.`,
		Example: `  wgft agent revoke home`,
	},
	"agent warnings": {
		Long: `List theft-detection warnings. They appear when the same credentials seem to be
in use from two places:
  ip-mismatch  the stream and the WireGuard endpoint come from different
               addresses for a sustained time
  ip-flapping  the address of one channel went back to an earlier value within
               ten minutes
If it was you (a line change, a move), dismiss the warning. If not, revoke the
agent and register it again with a new join string.`,
		Example: `  wgft agent warnings`,
	},
	"agent dismiss-warning": {
		Long: `Dismiss a warning after confirming it was legitimate. <kind> is ip-mismatch or
ip-flapping as printed by "agent warnings". Without [detail] every warning of
that kind for the agent is dismissed; with it, only the one whose DETAIL column
matches.`,
		Example: `  wgft agent dismiss-warning home ip-flapping`,
	},
	"agent pubkey": {
		Long: `Print the agent's WireGuard public key. If the credentials file has no key yet,
one is generated and saved first. Registration does not need this; it is for
checking which key an agent uses.`,
		Example: `  wgft agent pubkey
  wgft agent pubkey --data-dir /srv/wgft`,
	},
	"agent rotate-key": {
		Long: `Replace the agent's WireGuard key pair. With the agent running, the request goes
through its control socket and the agent reconnects with the new key at once;
with the agent stopped, the credentials file is rewritten. The server learns
the new public key over the stream, so nothing has to be done on the VPS.`,
		Example: `  wgft agent rotate-key`,
	},
	"agent run": {
		Long: `Agent host daemon. Brings up the tunnel and listeners first from the key in the credentials file (agent.json) and the last full state,
then connects to the server stream to receive the full state. On first run it registers with the join string (WGFT_JOIN); the name (WGFT_NAME) is
optional and normally left unset, since the join string is already bound to a name.

WGFT_JOIN is a secret. Prefer setting it as an environment variable or in the
dotenv file (--config); the --join flag leaves it visible to other local
users via ps and in shell history.

WGFT_AGENT_ALLOW_TARGETS limits the addresses this agent connects to, so that
a compromised server cannot use it to reach the rest of the LAN. Entries are
comma-separated CIDR, CIDR:port or CIDR:lo-hi; a bare address means one host.
Unset means no limit.`,
		Example: `  WGFT_JOIN='wgft://vps.example.com:8443/TOKEN#sha256:...' wgft agent run
  wgft agent run --config /etc/wgft/agent.env
  WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458 wgft agent run`,
	},
	"rule add": {
		Long: `Add a forwarding rule. Give exactly one of --tcp and --udp. A port range
"lo-hi" maps onto the same number of ports at the target, starting at the port
in --to: --udp 2456-2457 --to 192.168.1.20:2456 reaches 2456 and 2457.

Without --proxy the rule is forwarded by the kernel (or by the wgft process in
userspace mode), and the service at home sees the agent as the client. With
--proxy the server terminates TCP itself, and --proxy-protocol then passes the
real client address to the target in a PROXY protocol v2 header. The target
must expect that header.

The command refuses a port that another process on the VPS already listens on;
--force overrides that.`,
	},
	"rule ls": {
		Long: `List rules, grouped by --group. ID is shortened; every rule command accepts such
a prefix as long as it is unambiguous. TARGET shows the effective target range.
MODE is proxy for rules added with --proxy and kernel for all others; in
userspace mode "kernel" rules are relayed by the wgft process, not the kernel.
DENY and ALLOW are the number of CIDRs, RATES the configured limits, DROPPED
the packets or flows dropped by them so far.`,
		Example: `  wgft rule ls
  wgft rule ls --json`,
	},
	"rule rm": {
		Long:    `Delete rules. Open sessions through them are cut.`,
		Example: `  wgft rule rm r_01M2R009`,
	},
	"rule enable": {
		Long:    `Enable a disabled rule.`,
		Example: `  wgft rule enable r_01M2R009`,
	},
	"rule disable": {
		Long: `Disable a rule without deleting it. The VPS stops listening on its ports and
open sessions are cut; ID, limits and lists are kept.`,
		Example: `  wgft rule disable r_01M2R009`,
	},
	"rule set": {
		Example: `  wgft rule set r_01M2R009 --group game --note "game server"
  wgft rule set r_01M2R009 --note ""`,
	},
	"rule deny": {
		Long: `Sources in the deny list of a rule are dropped. The list holds IPv4 CIDRs; a
single address is written as /32.`,
	},
	"rule deny add": {
		Long: `Add CIDRs to the deny list of a rule. Sessions from those sources that are
already open are cut at once.`,
		Example: `  wgft rule deny add r_01M2R009 203.0.113.7/32 198.51.100.0/24`,
	},
	"rule deny rm": {
		Example: `  wgft rule deny rm r_01M2R009 203.0.113.7/32`,
	},
	"rule allow": {
		Long: `While the allow list of a rule is empty, every source may connect. Once it
holds at least one CIDR, every other source is dropped. The deny list is
checked first.`,
	},
	"rule allow add": {
		Long: `Add CIDRs to the allow list of a rule. From the first entry on, sources outside
the list are dropped, and their open sessions are cut.`,
		Example: `  wgft rule allow add r_01M2R009 192.0.2.0/24`,
	},
	"rule allow rm": {
		Long:    `Remove CIDRs from the allow list. Removing the last one opens the rule to every source again.`,
		Example: `  wgft rule allow rm r_01M2R009 192.0.2.0/24`,
	},
	"rule rate": {
		Long: `Set or clear the rate limits of a rule. <rate> is N/unit with unit one of
second, minute, hour, day, week, for example 10/second or 30/minute; "none"
clears the limit. Each limit allows a burst of 5 on top of the rate, and what
exceeds it is dropped and counted in the DROPPED column of "rule ls".

  per-source  new flows per source address
  new-flow    new flows for the whole rule
  packet      packets for the whole rule

A flow is a TCP connection or, for UDP, a source address and port not seen
before. In kernel mode, flows dropped by per-source or new-flow never enter
the connection tracking table of the VPS, so these two protect the VPS as well
as the home line.`,
	},
	"rule rate per-source": {
		Example: `  wgft rule rate per-source r_01M2R009 10/minute
  wgft rule rate per-source r_01M2R009 none`,
	},
	"rule rate new-flow": {
		Example: `  wgft rule rate new-flow r_01M2R009 100/second`,
	},
	"rule rate packet": {
		Long: `Cap the packets of the whole rule. It applies to UDP datagrams only, in both
kernel and userspace mode. A TCP rule still accepts and stores the value, for
import/export compatibility, but it has no effect.`,
		Example: `  wgft rule rate packet r_01M2R009 5000/second`,
	},
	"rule split": {
		Long: `Split a port-range rule into two at <port>: the first keeps the ports below it,
the second starts at <port>. Targets follow. Both changes go out in one batch,
so sessions stay up. Use it to give part of a range its own limits or lists.`,
		Example: `  wgft rule split r_01M2R009 2457`,
	},
	"rule merge": {
		Long: `Merge two rules whose listen ranges and target ranges are adjacent into one.
Their agent, protocol, mode, lists and limits must be the same. One batch, so
sessions stay up. The merged rule keeps the ID of <id1>.`,
		Example: `  wgft rule merge r_01M2R009 r_01M2R00A`,
	},
	"rule import": {
		Long: `Replace the whole rule set with the JSON array in the file: rules not in the
file are deleted, the others are created or updated. The file holds the array
that "rule ls --json" prints under "rules", so an export can be edited and
imported back. Every agent named in it must be registered.`,
		Example: `  wgft rule ls --json | jq .rules > rules.json
  wgft rule import rules.json`,
	},
	"server": {
		Long: `VPS-side daemon. It holds the WireGuard tunnel to the agents, forwards the ports
of the rules, serves the agent API on a public port and the admin API with the
Web UI on a Unix socket.

Two forwarding modes, chosen with WGFT_MODE on the first start and recorded:
  kernel     kernel WireGuard and nftables; needs root to install
  userspace  wireguard-go inside the process; no root, runs in a container

Configuration is WGFT_* environment variables, a dotenv file (--config, default
/etc/wgft/server.env) or flags. The admin API has no password: only root and the
server itself can open its socket.`,
	},
	"server run": {
		Long: `Run the server in the foreground. This is what the systemd unit and the
container image start. On a conflict that a restart cannot fix (someone else's
WireGuard interface, a port or address already in use, a kernel without
WireGuard) it exits with code 3.`,
		Example: `  wgft server run
  wgft server run --mode userspace --wg-endpoint vps.example.com:51820`,
	},
	"server check": {
		Long: `Check the configuration and the environment without starting or changing
anything: the effective value and source of every setting, other nftables
tables that would drop or steal forwarded traffic, whether the host's own
input firewall would block wgft's ports (WireGuard, the agent API, and any
rule's listen port that wgft itself binds: proxy-mode rules in kernel mode,
every rule in userspace mode), net.ipv4.ip_forward, the size of the
connection tracking table, and the recorded mode and address range. Run it
as root; without root the nftables and firewall parts are skipped.`,
		Example: `  sudo wgft server check`,
	},
	"server nft": {
		Long: `Print the nftables table the server has applied, as "nft list table inet wgft"
shows it. In userspace mode there is no table and the command says so.`,
		Example: `  sudo wgft server nft`,
	},
	"server teardown": {
		Example: `  sudo systemctl disable --now wgft
  sudo wgft server teardown --dry-run
  sudo wgft server teardown
  sudo wgft server teardown --purge`,
	},
}

// applyHelp は helpTexts の内容をコマンド木に載せる。表に無いコマンドは定義のままにする。
func applyHelp(root *cobra.Command) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if t, ok := helpTexts[helpKey(c)]; ok {
			if t.Long != "" {
				c.Long = t.Long
			}
			if t.Example != "" {
				c.Example = t.Example
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// helpKey は "wgft rule rate packet" を "rule rate packet" に、ルートを "" にする。
func helpKey(c *cobra.Command) string {
	return strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), "wgft"))
}
