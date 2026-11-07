//! 作成の時の設定と表の大きさ。

use core::fmt;
use core::net::Ipv4Addr;

/// The smallest MTU the stack accepts, the IPv4 minimum datagram size every host must accept.
pub const MIN_MTU: usize = 576;
/// The largest MTU the stack accepts, which covers jumbo frames.
pub const MAX_MTU: usize = 9216;

/// The table sizes of a stack, fixed at creation.
///
/// 一部の値だけを変えるときは、既定の値から作ります。
///
/// ```
/// use wgft_wgstack::Limits;
///
/// let small = Limits { max_flows: 8, accept_queue: 4, tw_rows: 32, ..Limits::default() };
/// assert_eq!(small.conns(), 12);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The number K of connections that can be established at once.
    pub max_flows: usize,
    /// accept の待ち行列の全体の数 Q です。接続の枠の数は K + Q です。待ち受け 1 つはその半分までです。
    /// 1 は待ち受けの分が 0 になり、どの接続も accept できないので設定の誤りにします。0 は待ち受けを持たない
    /// 核 (能動の open だけの核) のための値で、受け付けますが、どの待ち受けも接続を受けられません。
    pub accept_queue: usize,
    /// 握手の途中の表の行の数 N_syn です。
    pub syn_rows: usize,
    /// TIME_WAIT と FIN_WAIT_2 の行の数 M です。
    pub tw_rows: usize,
    /// 制御の出力の輪の枠の数 Q_ctl です。
    pub ctl_slots: usize,
    /// 再組み立ての表の項目の数です。
    pub frag_entries: usize,
    /// 再組み立ての表の断片の枠の数です。
    pub frag_pieces: usize,
    /// UDP の受信の datagram の数の予算です。endpoint 1 つの上限はその 4 分の 1 です。endpoint の分が 0 に
    /// ならないよう、[`UDP_ENDPOINT_SHARE`](crate::UDP_ENDPOINT_SHARE) から 65535 までです。
    pub udp_rx_datagrams: usize,
    /// UDP の送信の datagram の数の予算です。endpoint 1 つの上限はその 4 分の 1 です。範囲は
    /// `udp_rx_datagrams` と同じです。
    pub udp_tx_datagrams: usize,
    /// UDP の受信の byte の予算です。endpoint 1 つの上限はその 4 分の 1 です。chunk (16 KiB) の単位で数え、
    /// 最も大きい datagram が endpoint 1 つの上限に収まるよう、[`Limits::MIN_UDP_BYTES`] 以上にします。
    pub udp_rx_bytes: usize,
    /// UDP の送信の byte の予算です。分け方と下限は `udp_rx_bytes` と同じです。
    pub udp_tx_bytes: usize,
    /// 再組み立ての表の保持の byte の上限です。固定の管理領域、保持する断片の写し、完成の写し 1 つを数えます。
    pub frag_bytes: usize,
    /// boost の枠の数 B です。[`Budget`](crate::Budget) は同じ数の枠で作ります。0 は boost を使いません。
    /// [`Limits::MAX_BOOST_SLOTS`] までです。
    pub boost_slots: usize,
    /// 返った chunk (16 KiB) を次の確保のために残す数です。上界の固定の項に数えます。
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
    /// [`Limits::boost_slots`] の上限です。空きの枠の印を 1 語に収めます。
    pub const MAX_BOOST_SLOTS: usize = 64;
    /// [`Limits::udp_rx_bytes`] と [`Limits::udp_tx_bytes`] の下限です。最も大きい datagram (4 chunk) が
    /// endpoint 1 つの上限 (予算の 4 分の 1) に収まる大きさです。
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

    /// 接続の枠の数 N_c = K + Q です。
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
    /// RFC 9438 の CUBIC です。既定です。
    #[default]
    Cubic,
    /// RFC 5681 の輻輳の回避と RFC 6582 です。
    NewReno,
}

/// When a connection asks for a boost, the larger per-connection buffers taken from the [`Budget`](crate::Budget).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BoostPolicy {
    /// 需要の区間が閾値に届いた時に求めます。既定です。
    #[default]
    OnDemand,
    /// accept が接続を返す時に、受信の向きを含めて求めます。
    AtAccept,
    /// boost を求めません。
    Never,
}

/// 作成の時の設定です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// The stack's single IPv4 address. The stack accepts packets to this address only.
    pub addr: Ipv4Addr,
    /// The MTU of the link that carries the stack's packets, from [`MIN_MTU`] to [`MAX_MTU`].
    pub mtu: usize,
    /// 表の大きさです。
    pub limits: Limits,
    /// 輻輳の制御です。
    pub congestion: Congestion,
    /// boost の与え方です。
    pub boost: BoostPolicy,
}

impl Config {
    /// 既定の表の大きさの設定です。
    pub const fn new(addr: Ipv4Addr, mtu: usize) -> Self {
        Self {
            addr,
            mtu,
            limits: DEFAULT_LIMITS,
            congestion: Congestion::Cubic,
            boost: BoostPolicy::OnDemand,
        }
    }
}

/// 設定の誤りです。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// MTU が範囲の外です。
    Mtu(usize),
    /// 表の大きさが範囲の外です。
    Limits,
    /// [`Budget`](crate::Budget) の枠の数が [`Limits::boost_slots`] と違います。
    BudgetSlots {
        /// `Budget` の枠の数です。
        budget: usize,
        /// `Limits::boost_slots` です。
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
    /// 設定を確かめます。
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
