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
