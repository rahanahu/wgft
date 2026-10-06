# Pinned netstack dependency

[日本語](netstack-dependency.ja.md) · [Userspace design](README.md)

wgft pins the official gVisor module to `v0.0.0-20261004063249-f57b8fc79db4`.
This official go-branch commit includes fixes after the weekly `release-20260928.0` tag.
wgft does not carry a netstack fork or local dependency patches.

The selected source balances the segment reference when TIME_WAIT reuse cannot enqueue its incoming SYN.
It also preserves a cloned buffer's original backing bytes when `Buffer.GrowTo` exposes and zeroes additional bytes.
These fixes improve reference cleanup and copy-on-write correctness; they do not impose a count ceiling on TCP endpoints or empty TCP segments.

Normal close retains the dependency's TIME_WAIT behavior.
RACK loss detection remains enabled, and wgft continues to enable SACK.
The sender, receiver and RACK sources are unchanged from the preceding pin.
The update therefore does not fix the known [slow recovery after short outages](../vps/userspace.md#63-ユーザー空間モード).
The dependency still admits zero-payload TCP segments independently of its receive-memory threshold.
Stale receive-memory accounting and the acceptance of particular payload-bearing handshake forms remain separate limitations.
A fixed Device-wide table bounds post-close TCP endpoints; see [TCP retention](tcp-retention.md#閉じた後の接続の表).
This version pin does not establish an aggregate retained-memory or process RSS bound.

The TCP buffer adapter validates the actual type of the private atomic receive-memory field before reading it.
An incompatible layout disables the corresponding reclamation path rather than using an assumed offset.
Native platform behavior and full integration must be checked on the exact version before merging a dependency update.
