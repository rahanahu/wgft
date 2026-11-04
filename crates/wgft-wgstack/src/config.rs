//! 作成の時の設定と表の大きさ。

use core::fmt;
use core::net::Ipv4Addr;

/// The smallest MTU the stack accepts, the IPv4 minimum datagram size every host must accept.
pub const MIN_MTU: usize = 576;
/// The largest MTU the stack accepts, which covers jumbo frames.
pub const MAX_MTU: usize = 9216;

/// The table and budget sizes of a stack, fixed at creation.
///
/// Every table the stack keeps is sized from these values when the stack is created, and the stack never
/// grows them. [`Bound::for_limits`](crate::Bound::for_limits) turns them into the memory bound before
/// anything is allocated. What happens when each limit is reached is listed on each field.
///
/// [`Limits::default`] is a small, conservative set for a stack that serves a handful of connections: its
/// bound is about 21.6 MiB at MTU 1420, of which about 4 MiB is allocated at creation. Raise the fields you
/// need and start from the default for the rest:
///
/// ```
/// use wgft_wgstack::Limits;
///
/// let small = Limits { max_flows: 8, accept_queue: 4, tw_rows: 32, ..Limits::default() };
/// assert_eq!(small.conns(), 12);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// K, the connection slots for established connections. Together with `accept_queue` it makes
    /// N_c = K + Q connection slots ([`Limits::conns`]); each slot reserves a 256 KiB send floor and a 256 KiB
    /// receive floor in the bound. The stack does not stop at K established connections: an accepted
    /// connection may take any free slot. A caller that wants fewer active connections counts them itself.
    /// When no slot is free, a completing handshake is dropped and counted in `Stats::accept_overflow`.
    pub max_flows: usize,
    /// Q, the connections that may wait in accept queues in total; one listener may hold half of it. When a
    /// listener's queue is full, the final ACK of a handshake is dropped (`Stats::accept_overflow`) and the
    /// half-open row stays, so the handshake can complete when the application has accepted. 1 is refused,
    /// since it leaves each listener no room; 0 is accepted for a stack without listeners, on which no
    /// listener can accept a connection.
    pub accept_queue: usize,
    /// Half-open (handshake) rows; one listener may use half of them. When a listener's share or the table is
    /// full, SYNs are answered with SYN cookies, and dropped while the accept queue is also full
    /// (`Stats::syn_accept_full`).
    pub syn_rows: usize,
    /// TIME_WAIT and FIN_WAIT_2 rows. When the table is full the oldest row is evicted (`Stats::tw_evicted`),
    /// which shortens that 4-tuple's protection against old duplicate segments.
    pub tw_rows: usize,
    /// Slots of the control output ring, each one MTU, for RSTs, handshake replies, ICMP errors and echo
    /// replies. When it is full, new control packets are dropped (`Stats::ctl_dropped`) and
    /// [`Stack::send_ping`](crate::Stack::send_ping) returns [`Error::NoBufferSpace`](crate::Error::NoBufferSpace).
    pub ctl_slots: usize,
    /// Datagrams the reassembly table can assemble at once. When it is full, the oldest incomplete datagram
    /// is evicted (`Stats::fragments_evicted`).
    pub frag_entries: usize,
    /// Fragments the reassembly table can hold at once. When none is free and nothing can be evicted, the
    /// new fragment is dropped (`Stats::fragments_dropped`).
    pub frag_pieces: usize,
    /// Received UDP datagrams held at once; one endpoint may hold a quarter. Datagrams over the limit are
    /// dropped (`Stats::udp_dropped`). From [`UDP_ENDPOINT_SHARE`](crate::UDP_ENDPOINT_SHARE), so each
    /// endpoint can hold at least one, to 65535.
    pub udp_rx_datagrams: usize,
    /// Queued UDP datagrams to send; one endpoint may queue a quarter. Over the limit
    /// [`Stack::send_to`](crate::Stack::send_to) returns `WouldBlock` and
    /// [`Stack::send_to_latest`](crate::Stack::send_to_latest) drops the oldest queued datagram. The range is
    /// that of `udp_rx_datagrams`.
    pub udp_tx_datagrams: usize,
    /// Bytes of received UDP datagrams held, in 16 KiB chunks; one endpoint may hold a quarter. Datagrams over
    /// the budget are dropped. At least [`Limits::MIN_UDP_BYTES`], so the largest datagram fits one endpoint's
    /// quarter.
    pub udp_rx_bytes: usize,
    /// Bytes of queued UDP datagrams to send, split and bounded below as `udp_rx_bytes`; over the budget the
    /// send calls behave as for `udp_tx_datagrams`.
    pub udp_tx_bytes: usize,
    /// The reassembly table's byte limit, counting its fixed bookkeeping, the fragment copies it holds and one
    /// completed datagram. Must at least cover the bookkeeping for `frag_entries` and `frag_pieces`.
    pub frag_bytes: usize,
    /// Boost slots B: a connection with demand may take one and grow its send and receive buffers from the
    /// 256 KiB floors to 4 MiB; each slot adds about 7.8 MiB to the bound. When all slots are taken, a
    /// connection that asks stays at its floors, and an idle holder may be moved back to the floors for it.
    /// The [`Budget`](crate::Budget) must have this many slots. 0 disables boost; at most
    /// [`Limits::MAX_BOOST_SLOTS`].
    pub boost_slots: usize,
    /// Freed 16 KiB buffer chunks kept for reuse instead of returned to the allocator; counted in the bound's
    /// fixed term.
    pub pool_chunks: usize,
}

/// 既定の表の大きさです。wgft の外の利用者のための小さく保守的な値で、上界は MTU 1420 で約 21.6 MiB です。値と測り方は
/// docs/design/v2/wgstack-rs.md の「既定の表の大きさ」にあります。
const DEFAULT_LIMITS: Limits = Limits {
    max_flows: 16,
    accept_queue: 16,
    syn_rows: 64,
    tw_rows: 1024,
    ctl_slots: 32,
    frag_entries: 8,
    frag_pieces: 64,
    udp_rx_datagrams: 128,
    udp_tx_datagrams: 128,
    udp_rx_bytes: crate::udp::MIN_BYTES,
    udp_tx_bytes: crate::udp::MIN_BYTES,
    frag_bytes: 256 << 10,
    boost_slots: 0,
    pool_chunks: 8,
};

impl Limits {
    /// The largest [`Limits::boost_slots`].
    pub const MAX_BOOST_SLOTS: usize = 64;
    /// The smallest [`Limits::udp_rx_bytes`] and [`Limits::udp_tx_bytes`], 256 KiB: the largest datagram
    /// (4 chunks) then fits one endpoint's quarter of the budget.
    pub const MIN_UDP_BYTES: usize = crate::udp::MIN_BYTES;

    /// 凍結した Go の wgstack の本番の表の大きさで、K を `max_flows` にした値です。0 は K = 2048 です。
    /// Go の記録の再生と上界の表の試験が使います。wgft の agent は同じ値を自分で書いて渡します。試験の build と
    /// feature `harness` の build だけにあり、公開の API ではありません。
    #[cfg(any(test, feature = "harness"))]
    #[doc(hidden)]
    pub const fn go_reference(max_flows: usize) -> Self {
        Self {
            max_flows: if max_flows == 0 { 2048 } else { max_flows },
            accept_queue: 512,
            syn_rows: 1024,
            tw_rows: 65536,
            ctl_slots: 256,
            frag_entries: crate::frag::LIMITS.entries,
            frag_pieces: crate::frag::LIMITS.fragments,
            udp_rx_datagrams: crate::udp::RX_DATAGRAMS,
            udp_tx_datagrams: crate::udp::TX_DATAGRAMS,
            udp_rx_bytes: crate::udp::RX_BYTES,
            udp_tx_bytes: crate::udp::TX_BYTES,
            frag_bytes: crate::frag::LIMITS.bytes,
            boost_slots: crate::buf::BOOST_SLOTS,
            pool_chunks: crate::buf::chunk::POOL_KEEP,
        }
    }

    /// 再組み立ての表の上限です。
    pub(crate) const fn frag(&self) -> crate::frag::Limits {
        crate::frag::Limits {
            entries: self.frag_entries,
            fragments: self.frag_pieces,
            bytes: self.frag_bytes,
            ..crate::frag::LIMITS
        }
    }

    /// The connection slots N_c = K + Q.
    pub const fn conns(&self) -> usize {
        self.max_flows.saturating_add(self.accept_queue)
    }
}

impl Default for Limits {
    fn default() -> Self {
        DEFAULT_LIMITS
    }
}

/// The congestion control algorithm for every TCP connection of the stack.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Congestion {
    /// CUBIC (RFC 9438), the default.
    #[default]
    Cubic,
    /// NewReno: RFC 5681 congestion avoidance with RFC 6582 recovery.
    NewReno,
}

/// When a connection asks for a boost, the larger per-connection buffers taken from the [`Budget`](crate::Budget).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BoostPolicy {
    /// Ask when the data read or written over a recent interval reaches a threshold. The default.
    #[default]
    OnDemand,
    /// Ask for the receive direction as well when [`Stack::accept`](crate::Stack::accept) returns the
    /// connection.
    AtAccept,
    /// Never ask.
    Never,
}

/// The default send turn length N in segments, used by [`Config::with_send_turn`]. A turn is
/// N x MTU bytes (wgstack-rs.md, send turn).
pub const SEND_TURN_SEGMENTS: u8 = 8;

/// The configuration a stack is created with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// The stack's single IPv4 address. The stack accepts packets to this address only.
    pub addr: Ipv4Addr,
    /// The MTU of the link that carries the stack's packets, from [`MIN_MTU`] to [`MAX_MTU`].
    pub mtu: usize,
    /// The table and budget sizes.
    pub limits: Limits,
    /// The congestion control algorithm.
    pub congestion: Congestion,
    /// When connections ask for a boost slot.
    pub boost: BoostPolicy,
    /// The send turn length N in segments; 0 is off and the default. When on, the head TCP
    /// connection keeps being picked for up to N x MTU bytes once the TCP class is picked.
    /// Experimental; with 0 the output is bit-identical to a core without the feature
    /// (wgstack-rs.md, send turn).
    pub send_turn: u8,
}

impl Config {
    /// A configuration with the default [`Limits`], CUBIC and on-demand boost.
    pub const fn new(addr: Ipv4Addr, mtu: usize) -> Self {
        Self {
            addr,
            mtu,
            limits: DEFAULT_LIMITS,
            congestion: Congestion::Cubic,
            boost: BoostPolicy::OnDemand,
            send_turn: 0,
        }
    }

    /// The configuration with the send turn on at [`SEND_TURN_SEGMENTS`].
    #[must_use]
    pub const fn with_send_turn(self) -> Self {
        self.with_send_turn_segments(SEND_TURN_SEGMENTS)
    }

    /// The configuration with a send turn of `segments` segments; 0 turns it off.
    #[must_use]
    pub const fn with_send_turn_segments(self, segments: u8) -> Self {
        Self {
            send_turn: segments,
            ..self
        }
    }

    /// The send turn length in bytes (N x MTU); 0 is off.
    pub(crate) fn send_turn_bytes(&self) -> u32 {
        u32::from(self.send_turn).saturating_mul(u32::try_from(self.mtu).unwrap_or(u32::MAX))
    }
}

/// A configuration error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The MTU is outside [`MIN_MTU`] to [`MAX_MTU`].
    Mtu(usize),
    /// A table or budget size is out of range.
    Limits,
    /// The [`Budget`](crate::Budget) has a different number of slots than [`Limits::boost_slots`].
    BudgetSlots {
        /// The budget's slots.
        budget: usize,
        /// `Limits::boost_slots`.
        limits: usize,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mtu(m) => write!(f, "MTU {m} is out of range {MIN_MTU} to {MAX_MTU}"),
            Self::Limits => f.write_str("the table sizes are out of range"),
            Self::BudgetSlots { budget, limits } => write!(
                f,
                "the budget has {budget} boost slots but the limits ask for {limits}"
            ),
        }
    }
}

impl core::error::Error for ConfigError {}

impl Config {
    /// Checks the configuration. [`Stack::new`](crate::Stack::new) calls it too.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err(ConfigError::Mtu(self.mtu));
        }
        let l = &self.limits;
        // 番号は u32 に収め、タイマーの輪の節 (枠の数 × 4) も溢れない大きさにします。
        let fits = |n: usize| u32::try_from(n).is_ok_and(|n| n < u32::MAX / 8);
        let (Some(conns), Some(rows)) = (
            l.max_flows.checked_add(l.accept_queue),
            l.syn_rows.checked_add(l.tw_rows),
        ) else {
            return Err(ConfigError::Limits);
        };
        // 待ち受け 1 つの accept の待ち行列と握手の途中の行の数は、その半分までで、16 bit の欄に数えます。
        let per_listener = |n: usize| u16::try_from(n / 2).is_ok();
        // UDP の datagram の番号は 16 bit の欄に入れ、u16::MAX を「無し」に使います。endpoint 1 つの上限
        // (予算の 4 分の 1) が 0 だと、送信は WouldBlock のまま進まず、受信はすべて捨てるので、下限は 4 です。
        let udp = |n: usize| (crate::udp::ENDPOINT_SHARE..=usize::from(u16::MAX)).contains(&n);
        // UDP の chunk の番号も 16 bit の欄に入れます。
        let udp_bytes = |n: usize| n >= crate::udp::MIN_BYTES;
        let udp_chunks = (l.udp_rx_bytes / crate::buf::chunk::CHUNK_SIZE)
            .checked_add(l.udp_tx_bytes / crate::buf::chunk::CHUNK_SIZE)
            .is_some_and(|n| n < usize::from(u16::MAX));
        if l.max_flows == 0
            || l.tw_rows == 0
            || l.ctl_slots == 0
            || l.ctl_slots > 1 << 16
            || !fits(conns)
            || !fits(rows)
            || !per_listener(l.accept_queue)
            || l.accept_queue == 1
            || !per_listener(l.syn_rows)
            || l.frag().base_cost().is_err()
            || !udp(l.udp_rx_datagrams)
            || !udp(l.udp_tx_datagrams)
            || !udp_bytes(l.udp_rx_bytes)
            || !udp_bytes(l.udp_tx_bytes)
            || !udp_chunks
            || l.boost_slots > Limits::MAX_BOOST_SLOTS
            || l.pool_chunks > 1 << 16
        {
            return Err(ConfigError::Limits);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_mtu_and_limits() {
        let c = Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420);
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.limits, Limits::default());
        assert_eq!(c.limits.conns(), 32);
        assert_eq!(Limits::go_reference(0).conns(), 2560);
        assert_eq!(
            Config {
                limits: Limits::go_reference(0),
                ..c
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            (c.congestion, c.boost),
            (Congestion::Cubic, BoostPolicy::OnDemand)
        );
        for (congestion, boost) in [
            (Congestion::NewReno, BoostPolicy::Never),
            (Congestion::Cubic, BoostPolicy::AtAccept),
        ] {
            let other = Config {
                congestion,
                boost,
                ..c
            };
            assert_eq!(other.validate(), Ok(()));
        }
        for mtu in [575, 9217] {
            assert_eq!(Config { mtu, ..c }.validate(), Err(ConfigError::Mtu(mtu)));
        }
        assert_eq!(Config { mtu: 576, ..c }.validate(), Ok(()));
        assert_eq!(Config { mtu: 9216, ..c }.validate(), Ok(()));
        let bad = Config {
            limits: Limits {
                tw_rows: 0,
                ..c.limits
            },
            ..c
        };
        assert_eq!(bad.validate(), Err(ConfigError::Limits));
        let zero_syn = Config {
            limits: Limits {
                syn_rows: 0,
                accept_queue: 0,
                ..c.limits
            },
            ..c
        };
        assert_eq!(
            zero_syn.validate(),
            Ok(()),
            "the dial side has no half-open rows and no accept queue"
        );
    }

    /// 予算の大きさの範囲:UDP の byte は下限から chunk の番号の 16 bit まで、boost の枠は 64 まで、再組み立ての
    /// byte は固定の管理領域を覆う大きさです。
    #[test]
    fn validates_the_budget_sizes() {
        let c = Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420);
        let with = |f: &dyn Fn(&mut Limits)| {
            let mut limits = c.limits;
            f(&mut limits);
            Config { limits, ..c }.validate()
        };
        let min = Limits::MIN_UDP_BYTES;
        assert_eq!(min, 256 << 10);
        assert_eq!(with(&|l| l.udp_rx_bytes = min), Ok(()));
        assert_eq!(with(&|l| l.udp_tx_bytes = min), Ok(()));
        assert_eq!(
            with(&|l| l.udp_rx_bytes = min - 1),
            Err(ConfigError::Limits)
        );
        assert_eq!(
            with(&|l| l.udp_tx_bytes = min - 1),
            Err(ConfigError::Limits)
        );
        let chunk = crate::buf::chunk::CHUNK_SIZE;
        let most = (usize::from(u16::MAX) - 1) * chunk;
        assert_eq!(
            with(&|l| {
                l.udp_rx_bytes = most - min;
                l.udp_tx_bytes = min;
            }),
            Ok(())
        );
        assert_eq!(
            with(&|l| {
                l.udp_rx_bytes = most - min + chunk;
                l.udp_tx_bytes = min;
            }),
            Err(ConfigError::Limits)
        );
        assert_eq!(with(&|l| l.udp_rx_datagrams = 4), Ok(()));
        assert_eq!(with(&|l| l.udp_tx_datagrams = 4), Ok(()));
        for n in 0..4 {
            assert_eq!(with(&|l| l.udp_rx_datagrams = n), Err(ConfigError::Limits));
            assert_eq!(with(&|l| l.udp_tx_datagrams = n), Err(ConfigError::Limits));
        }
        assert_eq!(with(&|l| l.accept_queue = 1), Err(ConfigError::Limits));
        assert_eq!(with(&|l| l.accept_queue = 2), Ok(()));
        assert_eq!(with(&|l| l.boost_slots = 0), Ok(()));
        assert_eq!(with(&|l| l.boost_slots = 64), Ok(()));
        assert_eq!(with(&|l| l.boost_slots = 65), Err(ConfigError::Limits));
        assert_eq!(with(&|l| l.pool_chunks = 0), Ok(()));
        assert_eq!(with(&|l| l.frag_bytes = 1 << 20), Ok(()));
        assert_eq!(with(&|l| l.frag_bytes = 1024), Err(ConfigError::Limits));
    }
}
