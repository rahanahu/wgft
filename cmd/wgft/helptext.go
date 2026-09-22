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
  status                      on the VPS, against the admin API

Commands that talk to the admin API use the Unix socket of the running server
(WGFT_ADMIN, default unix:///run/wgft/admin.sock), so run them as root on the VPS.
Settings are WGFT_* environment variables; a dotenv file (--config) and flags are
other ways to pass the same values.`,
	},
	"status": {
		Long: `Summarize whether the deployment looks healthy, in four lines: Server, Agents,
Rules, Warnings. It reads the admin API of the running server (WGFT_ADMIN,
default unix:///run/wgft/admin.sock) and nothing else. Where "server doctor"
follows one rule from the public side to the target to find where traffic
stops, "status" only counts: it does not say where a problem is, only that
there is one.

Server, Agents and Rules each read healthy, degraded or unknown as such;
unknown means there is no evidence either way, such as an older server that
predates a field this command reads, and it is never counted as healthy or as
degraded. Server is healthy when the server's forwarding has caught up with
the current rules and the last change applied without error, degraded when it
has fallen behind, the last change failed, or a repair after a published
change failed, and unknown when a generation field is missing and there is no
apply_error to fall back on.

Agents counts registered agents as healthy, degraded or unknown; a healthy
agent needs both its control connection and its WireGuard tunnel to be
healthy. An agent counts as degraded when its control connection is down, or
when its tunnel has failed, reports an error, or its last handshake has gone
stale, the same freshness rule "server doctor"'s tunnel.handshake check uses.
An agent counts as unknown when its tunnel reports a state this build does
not recognize. Once any agent is degraded or unknown, the value spells out
all three counts against the total, such as "1 healthy, 1 degraded / 2"; when
every agent is healthy it just says "1 / 2 healthy". A live control connection
no longer counts as healthy by itself: an agent whose tunnel has quietly died
while its control connection stays up now reads degraded here too, matching
"server doctor" on the same input, instead of being counted healthy.

Rules counts the enabled rules as active, degraded or unknown, out of the
total; a disabled rule is not counted against the total, since being disabled
is a declared state, not a fault. A rule counts as active only when the
server has published it and its agent's freshest report says it can reach
the target: the server publishing a rule is not evidence that the agent is
actually forwarding it, since the agent can still refuse the target on its
own (WGFT_AGENT_ALLOW_TARGETS, a listener bind failure, and so on). A rule
counts as degraded when the server reports it pending or not_active, or when
its agent's freshest report is an error. A rule counts as unknown when the
server reports nothing about it, reports a state this build does not
recognize, or its agent has not freshly reported it, including a report left
over from before the agent's connection dropped. Once any rule is degraded or
unknown, the value spells out all three counts against the total, such as
"5 active, 2 degraded, 1 unknown / 8"; when every rule is active it just says
"8 active". Warnings reads a count of open theft-detection warnings, or
"none"; the added line also says how long ago each one was raised, when the
server reports that.

When a line is healthy, it holds nothing more than that: no generation
number, apply state string or endpoint. A degraded or unknown line gets one
added line naming what it found, such as which agent has not been seen, which
rule is not active and why, or that the server reports no apply state at all.

Exit code is 0 when every line is healthy or the only problem is unknown, 1
when a line is degraded, 2 when the summary itself could not be built (the
admin API is unreachable, or a bad argument or flag was given, the same as
"server doctor"), and 3 when the configuration itself is invalid, such as a
malformed dotenv file passed with --config. Unknown alone never raises the
exit code, matching "server doctor"'s own UNKNOWN, so an older server that
has not yet grown a field does not sound an alarm during a rolling upgrade.

Exit 1 here does not mean traffic stopped: it means some part of the
deployment needs operator attention. "server doctor" answers whether one
rule's forwarding path is broken; "status" answers whether the deployment as
a whole looks degraded, a different question. In particular, "server doctor"
deliberately exits 0 for a rule whose agent's control connection is down
while its tunnel still handshakes, since traffic may still be flowing; the
same agent shows up here as degraded too, and "status" exits 1 for it. The
reverse also raises it: an agent can keep its control connection up while its
tunnel itself has gone stale or failed, and "status" now catches that in the
Agents line instead of counting a control-connected agent as healthy
regardless of its tunnel. The same difference is why an open warning raises
the exit code here but not in "server doctor": "server doctor" asks whether a
rule's forwarding path is broken right now, so a warning that lingers until
an operator dismisses it sits outside that path, while "status" asks whether
this deployment still has something an operator needs to act on, and an
undismissed warning is exactly that.

--json prints the summary model: an object with server, agents, rules and
warnings. server holds a status of healthy, degraded or unknown, and an
optional detail. agents and rules each hold healthy/active, degraded and
unknown counts plus the total, and an optional detail. It only ever gains
members.`,
		Example: `  wgft status
  wgft status --json`,
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
error, WG_ENDPOINT and HANDSHAKE the WireGuard peer as the VPS sees it, RULES
lists id:reason for the rules currently failing, or "N ok" once none are, PROTO
the protocol negotiated on the agent's current connection, WARN the number of
open warnings. When an agent is disconnected (STREAM shows -), TUNNEL and
RULES are its last report before the stream dropped, prefixed with "last:";
they are not the current state. HEARTBEAT shows how long ago that report was.

PROTO shows vN for a connection that negotiated a numbered version, legacy
for an agent whose advertisement carried no protocol_min/protocol_max at all
(an older agent build), and - either while disconnected or while connected to
a server too old to report which one it picked. A disconnected agent shows -
rather than the version it last negotiated, since that value is no longer in
effect and does not become current again until the agent reconnects.

PROTO is what this one connection is using, not a range. "wgft version"
prints the range of numbered versions built into the binary it runs as; a
legacy agent, which advertises no version at all, connects regardless of that
range (design.md 7a.6 section). Even run on the VPS, that range belongs to
the on-disk binary and can differ from the range the running server process
uses until the server restarts with it.`,
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
--force overrides that.

--dry-run checks the rule against what a real "wgft rule add" would enforce
before saving, as far as the admin API lets it observe: its own shape,
whether it duplicates an ID or overlaps another rule's listen port, whether
it overlaps a port the server has reserved for itself (WireGuard, the admin
API, or the agent API), and whether --agent names a currently registered
agent. --force has no effect together with --dry-run: --dry-run never calls
Batch, the only place --force applies, so a rule overlapping a reserved
port is still refused. It prints what would change and exits 1 if it finds
a problem, 0 if not, and never saves anything either way. It does not try
to reach --to, and it does not check for a port already bound by another
process on the VPS or a DNAT some other nftables table has installed on
it, e.g. by Docker; the latter is refused even with --force. Both need
root and nft, which this command does not have; run "wgft server doctor
<rule>" for reachability once the rule exists. If the server's reserved
ports cannot be read, including because the admin API predates this
check, --dry-run exits 2: it could not determine whether the rule would
be accepted, which is not the same as finding it acceptable.`,
		Example: `  wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456
  wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
  wgft rule add --agent home --udp 2456 --to 192.168.1.20:2456 --dry-run`,
	},
	"rule ls": {
		Long: `List rules, grouped by --group. ID is shortened; every rule command accepts such
a prefix as long as it is unambiguous. TARGET shows the effective target range.
MODE is proxy for rules added with --proxy and kernel for all others; in
userspace mode "kernel" rules are relayed by the wgft process, not the kernel.
DENY and ALLOW are the number of CIDRs, RATES the configured limits, DROPPED
the packets or flows dropped by them so far by your rate limits and lists.
REFUSED is unrelated: it is how many times Resource Guard, wgft's own process-
wide flow budget, refused a new flow on this rule since the server started (not
persisted across restarts). A "flow budget" line follows the table when the
server reports its process-wide budget: in_use/limit per protocol. Kernel mode
never reports one for UDP, since it counts UDP flows through conntrack, not
through this budget.

AGENT_STATE is the rule's owning agent's own report of it: "ok", or
"error: <reason>" for a target refused by the agent's
WGFT_AGENT_ALLOW_TARGETS, a listener that failed to bind, or a TCP target
that failed its connectivity check. "-" means nothing has been reported
yet, whether or not the agent is connected. A "last:" prefix means the
report (or, for "-", the lack of one) is not current: either the agent is
disconnected and this is its last known state before that, or it never
reported at all, same idea as the "last:" prefix in "agent ls"'s RULES
column. --json carries the same information under agent_rule_states,
keyed by rule ID: every current rule has an entry there, with "state"
present only once the agent has reported it and "connected" always
present, so a script can tell "never reported" (state absent) from "no
report because this server does not track it" (the whole field absent).`,
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
		Long: `Change only an existing rule's group or note; give --group, --note or both.
Neither affects forwarding, and neither raises the rule generation.

--dry-run checks the change against what a real "wgft rule set" would
enforce before saving, as far as the admin API lets it observe: the rule's
own shape, whether it duplicates another rule's ID, whether its listen_port
overlaps another rule or a port the server has reserved for itself
(WireGuard, the admin API, or the agent API), and whether the rule's agent
is still currently registered. "rule set" cannot change listen_port, so
that check can only surface a conflict that already exists, never one this
command created. There is no --agent flag on this command; the agent
checked is the one already stored on the rule. It prints what would change
and exits 1 if it finds a problem, 0 if not, and never saves anything
either way; run "wgft server doctor <rule>" for reachability, which this
does not check. If the admin API cannot be reached, including to look up
the rule itself, or the server's reserved ports cannot be read, including
because the admin API predates this check, --dry-run exits 2: it could not
determine whether the change would be accepted.`,
		Example: `  wgft rule set r_01M2R009 --group game --note "game server"
  wgft rule set r_01M2R009 --note ""
  wgft rule set r_01M2R009 --note "game server" --dry-run`,
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
container image start. On a failure a restart cannot fix it exits with code 3
and names the category: config for a bad value, prerequisite for a missing
kernel module or capability, conflict with a recorded value, mode-gate for a
mode change that needs a teardown. Everything else exits 1 for the unit to
retry, including a port or interface another owner still holds.`,
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
	"server doctor": {
		Long: `Answer, for traffic that is not getting through: how far does it work, where
does it stop, and what to look at next. Run it on the VPS, as root: it reads
the admin API of the running server (WGFT_ADMIN, default
unix:///run/wgft/admin.sock) and nothing else. Where "server check" asks
whether this host is configured correctly, "doctor" asks why a rule does not
carry traffic.

Without an argument it surveys the server, the agents and every rule in a line
each. With a rule it follows that one rule from the public side to the target,
grouped as Server, Tunnel and Agent, and ends with where traffic stops.

Every item is in one of five states, and they mean exactly this:

  OK          this command observed the item succeed
  FAILED      this command observed the item fail
  UNKNOWN     there is evidence, but it is stale, contradictory or not enough
  NOT TESTED  this command does not test that reachability or condition at all
  SKIPPED     it could have been tested, but an earlier failure made it impossible

OK is never permanent: it carries how old the observation is, and an item falls
to UNKNOWN once its evidence is older than that item allows (90s for a
heartbeat and for the agent's own report of a rule, 3m for a WireGuard
handshake). The public port therefore reads NOT TESTED even when the server
serves it: DNAT applies to input from outside, so the server cannot reach its
own public port from itself. Test that from another host.

--probe opens one real TCP connection from the server, through the tunnel and
the agent, to the target, so it takes one rule at a time and the target sees a
connection. Without it nothing is dialled. --verbose adds the internal detail
(generations, apply state, endpoints, counters). --from <address> evaluates the
deny and allow lists against one client address.

Every run ends with what it did NOT test, and with the fact that it has no
history: it only evaluates the current state, so to find when a rule stopped
working, read the logs.

While an agent is disconnected, everything that agent reported is history:
those lines read "last:" and are never given as the current cause, the same way
"agent ls" marks them.

--json prints the diagnostic model: a "checks" array of {id, status, reason,
observed_at, ...}. The ids and the reason codes are the machine interface. They
only ever gain members: read an id you do not know by ignoring it, and a reason
you do not know as "unknown".

Exit codes, specific to this command: 0 when no check is FAILED, 1 when one or
more is, 2 when the report could not be produced at all (the admin API did not
answer, or the named rule does not exist), 3 for a bad setting. UNKNOWN and NOT
TESTED alone never make it non-zero.`,
		Example: `  sudo wgft server doctor
  sudo wgft server doctor r_01M2R009
  sudo wgft server doctor r_01M2R009 --probe --from 203.0.113.7
  sudo wgft server doctor r_01M2R009 --verbose
  sudo wgft server doctor --json`,
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
	"version": {
		Long: `Print the wgft version, followed by the range of protocol versions this
binary supports. That range is static, and it does not depend on any agent
being connected, but it covers only numbered versions; a server also accepts
a legacy agent that reports no version at all, regardless of this range,
during v1.0.x (design.md 7a.6 section). It is not the version in use with a
particular agent, which "wgft agent ls" prints per connection in its PROTO
column.`,
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
