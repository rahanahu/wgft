# Security Policy

wgft's server (`vpsd`) runs as root on a public VPS to manage nftables, WireGuard,
and conntrack. A vulnerability here can mean a remote root compromise of your
VPS, so please report it privately.

## Supported versions

wgft is alpha software. Only the latest published release is supported;
please upgrade before reporting an issue that might already be fixed.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:
open the "Security" tab, then "Report a vulnerability" (this opens a private
draft security advisory visible only to you and the maintainer). If that
option is not available to you, open a regular issue that only says you need
a private channel, without any details of the problem, and the maintainer will
reply with one.

When reporting, please include:

- The wgft version (`wgft --version`) and how you run it (systemd, Docker,
  by hand)
- The VPS OS/kernel and, if relevant, `nft --version`
- Steps to reproduce, or a proof of concept
- The impact you believe the issue has (for example: remote code execution,
  privilege escalation, firewall bypass, authentication bypass, information
  disclosure)
- Any relevant logs, with tokens and secrets redacted

## Response time

wgft has a single maintainer and no dedicated security team, so response
time is best effort. Expect an initial reply within a few days; fixes for
confirmed vulnerabilities are prioritized over other work.

## A compromised server as a stepping stone into the LAN

The agent connects to whatever `target` the server sends it. The server runs on
an internet-facing VPS, so an attacker who takes over the VPS can add a rule
with `target=192.168.1.1:22` and use the agent to reach the rest of your home
LAN. Certificate pinning and the agent's token do not help here: they stop a
third party from impersonating the server, not a server that has been taken
over.

Restrict the agent to the addresses it really needs with
`WGFT_AGENT_ALLOW_TARGETS` on the agent host:

```sh
WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458
```

Entries are comma-separated and each one is `CIDR`, `CIDR:port` or
`CIDR:lo-hi`; a bare address means that one host. The agent checks the address
it is about to connect to, so a `target` that is a hostname is checked after
it is resolved, at every new connection and UDP session. A rule whose literal
target is outside the list does not get a listener at all and is reported back
to the server as an error, visible in the Web UI and `wgft agent ls`. The list
lives only on the agent host; the server never learns it.

The setting is optional and unset by default, which means no restriction. It
limits which addresses can be reached, not what happens at an address that is
on the list.

## Rotating the agent API certificate

The server generates the agent API certificate on its first start, and every
agent pins its fingerprint when it registers. wgft v1 has no way to replace
that certificate while agents keep running. If its private key leaks, the
remedy is `wgft server teardown --purge` followed by registering every agent
again with a fresh join string, which carries the new fingerprint. The private
key lives in the server database next to the WireGuard server key and the agent
tokens, so protecting that file protects all three.

## Areas of particular interest

wgft is exposed on the public internet in three ways: the WireGuard
listener (kernel), the agent API served by `vpsd` (Go HTTPS), and the
forwarded ports themselves (kernel DNAT). Reports about any of the
following are especially welcome:

- The agent API: registration, authentication, token handling, and the
  WebSocket control/relay stream
- The admin API's Host and Origin checks, and anything that could let a
  browser or a different host reach it
- The nftables rule generation and teardown logic, including anything that
  could leave stale rules, open unintended ports, or affect traffic outside
  wgft's own chains

Thank you for helping keep wgft and the VPS it manages safe.
