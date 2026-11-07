//! 上界の式と保持の量 (wgstack-rs.md の「上界の式の写し方」と「保持の量の測り方」)。
//!
//! 上界の式の項と規則は Go と同じです。項の大きさは、作成の時の設定と Rust の型の大きさだけから決め、確保した
//! 配列の要求の大きさで数えます。割り当て器の丸めの係数は含みません。上界の表は試験が生成します
//! (`docs/design/v2/wgstack-bound.md`)。

use crate::budget::Budget;
use crate::buf::chunk::{CHUNK_SIZE, Chunk};
use crate::buf::records::Record;
use crate::buf::recv::Interval;
use crate::buf::ring::BOOST_RING_SLOTS;
use crate::buf::{
    BOOST_INTERVALS, BOOST_RECORDS, BOOST_SIZE, FLOOR_INTERVALS, FLOOR_RECORDS, RECV_FLOOR,
    SEND_FLOOR,
};
use crate::config::Limits;
use crate::icmp::{PING_ENDPOINTS, Pings};
use crate::index;
use crate::output::Dlist;
use crate::stack::{EventTargets, NoHook};
use crate::tcp::NUM_TIMERS;
use crate::tcp::conn;
use crate::tcp::listen::{Listener, PortTable};
use crate::tcp::syn::SynRow;
use crate::tcp::timewait::TwRow;
use crate::time::Time;
use crate::udp::{Udp, UdpEp};

/// The memory bound of a stack, in bytes, by term.
///
/// The bound is computed from the [`Limits`], the MTU and type sizes only, so it is known before the stack
/// handles any packet and does not change with use ([`Bound::for_limits`], [`Stack::bound`](crate::Stack::bound)).
/// Each term is an upper limit on the heap bytes that the stack requests for that purpose; [`Held`] reports
/// what it holds now. The bound counts requested sizes: it does not include allocator rounding or
/// bookkeeping, the caller's buffers, the [`Hook`](crate::Hook)'s own memory, or the call stack.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bound {
    /// Fixed tables, allocated at creation: the stack value, connection slots, the hash indexes, the half-open
    /// and TIME_WAIT rows, the per-port listener and UDP endpoint tables, the timer wheel, the output lists and
    /// the control output ring, the event list, and the kept pool chunks.
    pub fix: u64,
    /// The floor buffers of every connection slot: N_c × (send floor + receive floor + floor send records +
    /// floor out-of-order intervals), with N_c = [`Limits::conns`].
    pub floor_conn: u64,
    /// The part of `floor_conn` taken by the floor send-record ring and interval table. A slot allocates them
    /// on its first use and keeps them until the stack closes, so a slot that carries no data holds them too.
    /// Included in `floor_conn`; not added to `total` again.
    pub floor_arrays: u64,
    /// The boost slots: per slot the boost-stage send and receive buffers above the floors, the boost record
    /// ring and interval table and the boost-stage chunk tables, plus slot bookkeeping. The arrays are
    /// allocated by [`Budget::new`](crate::Budget::new); the buffer chunks when a boosted connection uses them.
    pub boost: u64,
    /// The reassembly table's byte limit ([`Limits::frag_bytes`]).
    pub frag: u64,
    /// The UDP receive byte budget ([`Limits::udp_rx_bytes`]) plus the receive datagram table and half of the
    /// chunk records.
    pub udp_rx: u64,
    /// The UDP send byte budget ([`Limits::udp_tx_bytes`]) plus the send datagram table and the other half of
    /// the chunk records.
    pub udp_tx: u64,
    /// The ping endpoint rows and their reply buffers.
    pub ping: u64,
    /// The sum of the terms. A connection that changes buffer stage holds both stages for a moment; that
    /// stays inside its boost slot's reservation, so it has no term of its own.
    pub total: u64,
}

/// 段を変える間の一時の保持が、その接続の boost の予約の内にあることです (wgstack-rs.md の「上界の式の写し方」)。
///
/// 段を変えるのは枠を持つ接続だけで、枠は段を移す前に受け取り、移した後に返します (`try_boost`、`grow_recv`、
/// `demote`)。核は 1 つのスレッドで動くので、1 回の移しは 1 本の接続の 1 回の呼び出しの中で終わり、その間にほかの
/// 接続が枠や chunk を取ることはありません。枠を持つ接続の予約は、両方の向きの boost の段で 2B 個の chunk です
/// (B は boost の段の chunk の数、F は floor の段の chunk の数)。
///
/// 移す間に接続が持つ chunk は、呼び出しごとに次の数以下です。送信の輪は確認した分の chunk を返すので、生きている
/// 範囲 (floor 以下) に掛かる chunk だけを持ち、境目がそろわなければ F + 1 個です。新しい floor の輪は位置を
/// floor で割った余りに置くので F 個以下です。
///
/// - `enter_boost`:送信の古い floor の輪 F、新しい boost の輪 F + 1、floor の受信の輪 F で、3F + 1 です
/// - `grow_recv`:boost の送信の輪 B、受信の古い floor の輪 F、新しい boost の輪 F + 1 で、B + 2F + 1 です
/// - `demote`:受信の取り消しは区間の表だけを変え、古い boost の受信の輪は chunk を B 個まで持ったままです。
///   受信の古い輪 B と新しい floor の輪 F、送信の古い boost の輪 F + 1 と新しい floor の輪 F で、B + 3F + 1 です
///
/// 最も大きい `demote` の和が 2B 以下であることを確かめます。
pub(crate) const STAGE_CHANGE_FITS: bool = {
    let c = CHUNK_SIZE as u64;
    let floor = (if SEND_FLOOR > RECV_FLOOR {
        SEND_FLOOR
    } else {
        RECV_FLOOR
    }) / c;
    let boost = BOOST_SIZE / c;
    let enter_boost = 3 * floor + 1;
    let grow_recv = boost + 2 * floor + 1;
    let demote = boost + 3 * floor + 1;
    enter_boost <= demote && grow_recv <= demote && demote <= 2 * boost
};
const _: () = assert!(STAGE_CHANGE_FITS);

/// 項の内訳です。生成する表が使います。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FixParts {
    pub(crate) stack: u64,
    pub(crate) conn_slots: u64,
    pub(crate) conn_index: u64,
    pub(crate) syn: u64,
    pub(crate) tw: u64,
    pub(crate) listeners: u64,
    pub(crate) udp_endpoints: u64,
    pub(crate) wheel: u64,
    pub(crate) output: u64,
    pub(crate) events: u64,
    pub(crate) chunk_pool: u64,
}

impl FixParts {
    fn sum(&self) -> u64 {
        self.stack
            + self.conn_slots
            + self.conn_index
            + self.syn
            + self.tw
            + self.listeners
            + self.udp_endpoints
            + self.wheel
            + self.output
            + self.events
            + self.chunk_pool
    }
}

fn b(n: usize) -> u64 {
    n as u64
}

/// 接続の枠 1 つの floor の項 f_s + f_r + r_f + h_f です。
pub(crate) fn floor_per_conn() -> u64 {
    SEND_FLOOR + RECV_FLOOR + floor_arrays_per_conn()
}

/// 接続の枠 1 つの floor の配列の項 r_f + h_f です。
fn floor_arrays_per_conn() -> u64 {
    b(FLOOR_RECORDS * size_of::<Record>() + FLOOR_INTERVALS * size_of::<Interval>())
}

/// boost の枠 1 つの項 d_s + d_r + d_rec + d_h + 2 × d_tbl です。d_tbl は boost の段の輪の chunk の表です。
pub(crate) fn boost_per_slot() -> u64 {
    (BOOST_SIZE - SEND_FLOOR)
        + (BOOST_SIZE - RECV_FLOOR)
        + b(BOOST_RECORDS * size_of::<Record>()
            + BOOST_INTERVALS * size_of::<Interval>()
            + 2 * BOOST_RING_SLOTS * size_of::<Option<Chunk>>())
}

/// 核の表の固定の項の内訳です。表の作成と同じ数で数えます。
pub(crate) fn fix_parts(l: &Limits, mtu: usize, stack_size: usize) -> FixParts {
    let n = l.conns();
    let ent = size_of::<index::IndexEnt>();
    let nodes = n * NUM_TIMERS;
    let dlist = |k: usize| b(Dlist::bytes_for(k));
    FixParts {
        stack: b(stack_size),
        conn_slots: b(n * conn::slot_bytes()),
        conn_index: b(index::capacity_for(n) * (ent + size_of::<u64>())),
        syn: b(l.syn_rows * (size_of::<SynRow>() + size_of::<u32>())
            + index::capacity_for(l.syn_rows) * ent),
        tw: b(
            l.tw_rows * (size_of::<TwRow>() + 3 * size_of::<u32>() + size_of::<Time>())
                + index::capacity_for(l.tw_rows) * ent
                + n * size_of::<u32>(),
        ),
        listeners: b(PortTable::<Listener>::bytes()),
        udp_endpoints: b(PortTable::<UdpEp>::bytes()),
        wheel: b(
            nodes * (size_of::<u64>() + 2 * size_of::<u32>() + size_of::<u16>())
                + nodes * size_of::<u32>(),
        ),
        output: dlist(n)
            + dlist(l.syn_rows + l.tw_rows)
            + b(l.ctl_slots * (mtu + size_of::<u16>())),
        events: {
            let t = EventTargets::count(n);
            b(t) + dlist(t)
        },
        chunk_pool: b(l.pool_chunks * (CHUNK_SIZE + size_of::<Chunk>())),
    }
}

impl Bound {
    /// The bound of a stack with the table sizes `limits` and the MTU `mtu`, counting the stack value of a
    /// stack without a hook ([`NoHook`](crate::NoHook)).
    pub fn for_limits(limits: &Limits, mtu: usize) -> Self {
        Self::with_stack_size(limits, mtu, crate::stack::stack_size::<NoHook>())
    }

    pub(crate) fn with_stack_size(l: &Limits, mtu: usize, stack_size: usize) -> Self {
        let fix = fix_parts(l, mtu, stack_size).sum();
        let floor_conn = b(l.conns()) * floor_per_conn();
        let floor_arrays = b(l.conns()) * floor_arrays_per_conn();
        let boost = b(l.boost_slots) * boost_per_slot() + b(Budget::slot_bytes(l.boost_slots));
        let frag = b(l.frag_bytes);
        // chunk の管理の配列は向きごとの予算の chunk の数の和で、項はそれぞれの向きの分を持ちます。
        let ck = |bytes: usize| b(bytes / CHUNK_SIZE * Udp::chunk_rec_size());
        let udp_rx =
            b(l.udp_rx_bytes) + b(l.udp_rx_datagrams * Udp::dgram_size()) + ck(l.udp_rx_bytes);
        let udp_tx =
            b(l.udp_tx_bytes) + b(l.udp_tx_datagrams * Udp::dgram_size()) + ck(l.udp_tx_bytes);
        let ping = b(PING_ENDPOINTS * (mtu + Pings::ep_size()));
        Self {
            fix,
            floor_conn,
            floor_arrays,
            boost,
            frag,
            udp_rx,
            udp_tx,
            ping,
            total: fix + floor_conn + boost + frag + udp_rx + udp_tx + ping,
        }
    }
}

/// What a stack holds now beyond its fixed tables; all zero after [`Stack::close`](crate::Stack::close).
///
/// The heap bytes the stack has gained since creation equal exactly `chunk_bytes + record_bytes +
/// interval_bytes + frag_bytes + udp_rx_bytes + udp_tx_bytes + pool_bytes - lent_array_bytes`. Boost arrays are
/// allocated by the [`Budget`](crate::Budget) and counted in `record_bytes` and `interval_bytes` while a
/// connection borrows them, hence the subtraction. The crate's allocation-counting tests check this
/// equation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// Connection slots in use.
    pub conns: usize,
    /// Connection slots that hold their floor record ring and interval table. A slot allocates them on first
    /// use and keeps them, so this counts the slots used since the stack was created.
    pub slot_arrays: usize,
    /// Half-open (handshake) rows in use.
    pub syn_rows: usize,
    /// TIME_WAIT and FIN_WAIT_2 rows in use.
    pub tw_rows: usize,
    /// Connections in accept queues, including ones being moved there.
    pub accept_queued: usize,
    /// Packets queued in the control output ring.
    pub ctl_queued: usize,
    /// Bytes of buffer chunks held by connection send and receive rings.
    pub chunk_bytes: usize,
    /// Chunks kept in the pool for reuse; the bound counts up to [`Limits::pool_chunks`] of them in `fix`.
    pub pool_chunks: usize,
    /// Bytes of the kept pool chunks (`pool_chunks` × the chunk size).
    pub pool_bytes: usize,
    /// The part of `record_bytes` and `interval_bytes` that boosted connections borrow from the `Budget`.
    pub lent_array_bytes: usize,
    /// Bytes of send-record rings: the floor rings and the borrowed boost rings.
    pub record_bytes: usize,
    /// Bytes of out-of-order interval tables: the floor tables and the borrowed boost tables.
    pub interval_bytes: usize,
    /// Connections that hold a boost slot.
    pub boosted: usize,
    /// The send and receive capacity reserved by the connection slots in use.
    pub reserved: u64,
    /// Bytes of fragment copies held by the reassembly table, without its fixed bookkeeping.
    pub frag_bytes: usize,
    /// Chunk bytes held by received UDP datagrams.
    pub udp_rx_bytes: usize,
    /// Received UDP datagrams held.
    pub udp_rx_datagrams: usize,
    /// Chunk bytes held by queued UDP datagrams to send.
    pub udp_tx_bytes: usize,
    /// Queued UDP datagrams to send.
    pub udp_tx_datagrams: usize,
    /// Ping endpoints in use.
    pub ping_endpoints: usize,
    /// Targets with a pending event.
    pub events: usize,
}

impl Held {
    /// Returns whether every term is zero.
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests;
