//! 捨てたものの数。誤りは相手に返さず、ここで数えるだけにする。

/// Why the device dropped a datagram or a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// The datagram is not a WireGuard message of a known type and length.
    Malformed,
    /// A MAC, an AEAD tag or a key did not check out.
    Unauthenticated,
    /// A handshake or data counter was already seen or is outside the replay window.
    Replayed,
    /// Too many handshakes from this source while the device is under load.
    RateLimited,
    /// The message names a key or receiver index that belongs to no configured peer.
    UnknownPeer,
    /// The peer has no session that can take the message.
    NoSession,
    /// The decrypted packet is not a well formed IPv4 packet.
    InvalidInnerPacket,
    /// The decrypted packet's source is not in the sending peer's allowed IPs.
    DisallowedSource,
    /// No peer's allowed IPs hold the outbound packet's destination.
    NoRoute,
    /// The peer to send to has no endpoint yet.
    NoEndpoint,
    /// The outbound packet is longer than the MTU.
    TooBig,
    /// A packet waiting for a handshake was pushed out by newer ones.
    StagedOverflow,
    /// The transmit queue was full.
    TransmitOverflow,
    /// The delivery queue was full.
    DeliverOverflow,
    /// The event queue was full; the oldest event was lost.
    EventOverflow,
    /// sanstun refused a call that the device should never make; a bug in this crate.
    Internal,
}

impl DropReason {
    /// Every reason, in declaration order.
    pub const ALL: [DropReason; 16] = [
        DropReason::Malformed,
        DropReason::Unauthenticated,
        DropReason::Replayed,
        DropReason::RateLimited,
        DropReason::UnknownPeer,
        DropReason::NoSession,
        DropReason::InvalidInnerPacket,
        DropReason::DisallowedSource,
        DropReason::NoRoute,
        DropReason::NoEndpoint,
        DropReason::TooBig,
        DropReason::StagedOverflow,
        DropReason::TransmitOverflow,
        DropReason::DeliverOverflow,
        DropReason::EventOverflow,
        DropReason::Internal,
    ];

    /// A short lower-case name for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            DropReason::Malformed => "malformed",
            DropReason::Unauthenticated => "unauthenticated",
            DropReason::Replayed => "replayed",
            DropReason::RateLimited => "rate-limited",
            DropReason::UnknownPeer => "unknown-peer",
            DropReason::NoSession => "no-session",
            DropReason::InvalidInnerPacket => "invalid-inner-packet",
            DropReason::DisallowedSource => "disallowed-source",
            DropReason::NoRoute => "no-route",
            DropReason::NoEndpoint => "no-endpoint",
            DropReason::TooBig => "too-big",
            DropReason::StagedOverflow => "staged-overflow",
            DropReason::TransmitOverflow => "transmit-overflow",
            DropReason::DeliverOverflow => "deliver-overflow",
            DropReason::EventOverflow => "event-overflow",
            DropReason::Internal => "internal",
        }
    }
}

/// Counts of dropped datagrams, packets and events by [`DropReason`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drops([u64; DropReason::ALL.len()]);

impl Drops {
    pub(crate) fn add(&mut self, reason: DropReason, n: u64) {
        let slot = &mut self.0[reason as usize];
        *slot = slot.saturating_add(n);
    }

    /// The count for one reason.
    #[must_use]
    pub fn get(&self, reason: DropReason) -> u64 {
        self.0[reason as usize]
    }

    /// The sum over all reasons.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.0.iter().fold(0, |a, b| a.saturating_add(*b))
    }

    /// The reasons with a non-zero count and their counts.
    pub fn nonzero(&self) -> impl Iterator<Item = (DropReason, u64)> {
        DropReason::ALL
            .iter()
            .map(|r| (*r, self.get(*r)))
            .filter(|(_, n)| *n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_each_reason_at_its_own_index() {
        for (i, r) in DropReason::ALL.iter().enumerate() {
            assert_eq!(*r as usize, i);
        }
    }
}
