//! 上界の式と保持の量 (wgstack-rs.md の「上界の式の写し方」と「保持の量の測り方」)。
//!
//! 上界の式の項と規則は Go と同じです。項の大きさは、作成の時の設定と Rust の型の大きさだけから決め、確保した
//! 配列の要求の大きさで数えます。割り当て器の丸めの係数は含みません。上界の表は試験が生成します
//! (`docs/design/v2/wgstack-bound.md`)。

use crate::budget::Budget;
use crate::buf::chunk::{CHUNK_SIZE, Chunk, POOL_KEEP};
use crate::buf::records::Record;
use crate::buf::recv::Interval;
use crate::buf::ring::BOOST_RING_SLOTS;
use crate::buf::{
    BOOST_INTERVALS, BOOST_RECORDS, BOOST_SIZE, BOOST_SLOTS, FLOOR_INTERVALS, FLOOR_RECORDS,
    RECV_FLOOR, SEND_FLOOR,
};
use crate::config::Limits;
use crate::frag;
use crate::icmp::{PING_ENDPOINTS, Pings};
use crate::index;
use crate::output::Dlist;
use crate::stack::{EventTargets, NoHook};
use crate::tcp::NUM_TIMERS;
use crate::tcp::conn;
use crate::tcp::listen::{Listener, PortTable};
use crate::tcp::syn::SynRow;
use crate::tcp::timewait::TwRow;
use crate::udp::{self, Udp, UdpEp};

/// 上界の式の値です。単位は byte です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bound {
    /// M_fix:核の構造、接続の枠、hash の表、行の表、待ち受けの表、UDP の endpoint の表、タイマーの輪、出力の
    /// list と制御の輪、知らせの list、chunk の置き場です。
    pub fix: u64,
    /// N_c × (f_s + f_r + r_f + h_f) です。
    pub floor_conn: u64,
    /// `floor_conn` のうち、floor の送信の記録の輪と区間の表の N_c × (r_f + h_f) です。枠を初めて使う時に確保し、
    /// 枠と共に持つので、データを運ばない接続も持ちます。`floor_conn` の内訳で、`total` に重ねて足しません。
    pub floor_arrays: u64,
    /// B × (d_s + d_r + d_rec + d_h + 2 × d_tbl) と枠の管理です。d_rec と d_h は boost の輪と表の全体、d_tbl は
    /// boost の段の輪の chunk の表で、`Budget` が作成の時に確保します。floor の輪と表は枠に残るので `floor_conn`
    /// が数えます。
    pub boost: u64,
    /// M_frag:再組み立ての表の保持 byte の上限です。
    pub frag: u64,
    /// M_udp_rx:UDP の受信の byte の予算と、受信の datagram の管理の配列と、chunk の管理の配列の半分です。
    pub udp_rx: u64,
    /// M_udp_tx:UDP の送信の byte の予算と、送信の datagram の管理の配列と、chunk の管理の配列の残りの半分です。
    pub udp_tx: u64,
    /// N_ping × c_ping:ping の endpoint の行と応答の置き場です。
    pub ping: u64,
    /// 項の和です。段を変える間の一時の保持は、段を変える接続が持つ boost の枠の予約の内にあるので、別の項を
    /// 持ちません ([`STAGE_CHANGE_FITS`])。
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
        tw: b(l.tw_rows * (size_of::<TwRow>() + 3 * size_of::<u32>())
            + index::capacity_for(l.tw_rows) * ent
            + n * size_of::<u32>()),
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
        chunk_pool: b(POOL_KEEP * (CHUNK_SIZE + size_of::<Chunk>())),
    }
}

impl Bound {
    /// 表の大きさ `limits` と MTU `mtu` の核の上界です。核の値の大きさは hook の無い核で数えます。
    pub fn for_limits(limits: &Limits, mtu: usize) -> Self {
        Self::with_stack_size(limits, mtu, crate::stack::stack_size::<NoHook>())
    }

    pub(crate) fn with_stack_size(l: &Limits, mtu: usize, stack_size: usize) -> Self {
        let fix = fix_parts(l, mtu, stack_size).sum();
        let floor_conn = b(l.conns()) * floor_per_conn();
        let floor_arrays = b(l.conns()) * floor_arrays_per_conn();
        let boost = b(BOOST_SLOTS) * boost_per_slot() + b(Budget::slot_bytes());
        let frag = b(frag::LIMITS.bytes);
        let ck = b(udp::CHUNKS * Udp::chunk_rec_size());
        let udp_rx = b(udp::RX_BYTES) + b(l.udp_rx_datagrams * Udp::dgram_size()) + ck.div_ceil(2);
        let udp_tx = b(udp::TX_BYTES) + b(l.udp_tx_datagrams * Udp::dgram_size()) + ck / 2;
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

/// 核が今持つ可変の保持の量です。表の固定の配列は含みません。核を閉じた後はすべて 0 です。
///
/// 核を作った直後から増えた heap の byte は、`chunk_bytes + record_bytes + interval_bytes + frag_bytes +
/// udp_rx_bytes + udp_tx_bytes + pool_bytes - lent_array_bytes` とちょうど一致します。boost の配列は `Budget` が
/// 作った時に確保し、接続が借りている間は `record_bytes` と `interval_bytes` にも数えるので、その分
/// (`lent_array_bytes`) を引きます。試験はこの式で確保の数えと会計を照らします。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// 使っている接続の枠です。
    pub conns: usize,
    /// floor の送信の記録の輪と区間の表を持つ接続の枠です。枠は初めて使う時に配列を確保して持ち続けるので、核を
    /// 作ってから使ったことのある枠の数です。
    pub slot_arrays: usize,
    /// 握手の途中の行です。
    pub syn_rows: usize,
    /// TIME_WAIT と FIN_WAIT_2 の行です。
    pub tw_rows: usize,
    /// accept の待ち行列の接続 (移している途中の行を含む) です。
    pub accept_queued: usize,
    /// 制御の輪に積んだ packet です。
    pub ctl_queued: usize,
    /// 送信と受信の輪が持つ chunk の byte です。
    pub chunk_bytes: usize,
    /// 置き場に残した chunk の数です。上限の分は上界の M_fix に入ります。
    pub pool_chunks: usize,
    /// 置き場に残した chunk の中身の byte です (`pool_chunks` × chunk の大きさ)。
    pub pool_bytes: usize,
    /// `record_bytes` と `interval_bytes` のうち、boost の枠を持つ接続が `Budget` から借りている記録の輪と区間の
    /// 表の byte です。
    pub lent_array_bytes: usize,
    /// 送信の記録の輪が持つ byte (floor の輪と、借りている boost の輪) です。
    pub record_bytes: usize,
    /// 順序外の区間の表が持つ byte (floor の表と、借りている boost の表) です。
    pub interval_bytes: usize,
    /// boost の枠を持つ接続です。
    pub boosted: usize,
    /// 使っている接続の枠の送信と受信の容量の和です。
    pub reserved: u64,
    /// 再組み立ての表が保持する断片の写しの byte です。固定の管理領域は含みません。
    pub frag_bytes: usize,
    /// UDP の受信が持つ chunk の byte と datagram の数です。
    pub udp_rx_bytes: usize,
    pub udp_rx_datagrams: usize,
    /// UDP の送信が持つ chunk の byte と datagram の数です。
    pub udp_tx_bytes: usize,
    pub udp_tx_datagrams: usize,
    /// 使っている ping の endpoint です。
    pub ping_endpoints: usize,
    /// 知らせることのある対象の数です。
    pub events: usize,
}

impl Held {
    /// すべての項が 0 かを返します。
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests;
