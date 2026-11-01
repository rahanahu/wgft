//! 上界の式と保持の量 (wgstack-rs.md の「上界の式の写し方」と「保持の量の測り方」)。
//!
//! 上界の式の項と規則は Go と同じです。項の大きさは、作成の時の設定と Rust の型の大きさだけから決め、確保した
//! 配列の要求の大きさで数えます。割り当て器の丸めの係数は含みません。上界の表は試験が生成します
//! (`docs/design/v2/wgstack-bound.md`)。
//! UDP と ping の項は、その表を作る段 (PR 6) が足します。

use crate::budget::Budget;
use crate::buf::chunk::{CHUNK_SIZE, Chunk, POOL_KEEP};
use crate::buf::records::Record;
use crate::buf::recv::Interval;
use crate::buf::{
    BOOST_INTERVALS, BOOST_RECORDS, BOOST_SIZE, BOOST_SLOTS, FLOOR_INTERVALS, FLOOR_RECORDS,
    RECV_FLOOR, SEND_FLOOR,
};
use crate::config::Limits;
use crate::frag;
use crate::index;
use crate::stack::{EventTargets, NoHook, Stack};
use crate::tcp::NUM_TIMERS;
use crate::tcp::conn;
use crate::tcp::listen::{Listener, PORTS, PortRow};
use crate::tcp::syn::SynRow;
use crate::tcp::timewait::TwRow;

/// 上界の式の値です。単位は byte です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bound {
    /// M_fix:核の構造、接続の枠、hash の表、行の表、待ち受けの表、タイマーの輪、出力の list と制御の輪、
    /// 知らせの list、chunk の置き場です。
    pub fix: u64,
    /// N_c × (f_s + f_r + r_f + h_f) です。
    pub floor_conn: u64,
    /// B × (d_s + d_r + d_rec + d_h) と枠の管理です。d_rec と d_h は boost の輪と表の全体で、`Budget` が作成の
    /// 時に確保します。floor の輪と表は枠に残るので `floor_conn` が数えます。
    pub boost: u64,
    /// M_frag:再組み立ての表の保持 byte の上限です。
    pub frag: u64,
    /// 項の和です。
    pub total: u64,
    /// 段を変える間の一時の保持で、式に含めない項です。1 本の接続の操作の中で起きるので、同時に起きる数は boost の
    /// 枠の数以下で、B × (f_s + f_r) で抑えます。
    pub transient: u64,
}

/// 項の内訳です。生成する表が使います。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FixParts {
    pub(crate) stack: u64,
    pub(crate) conn_slots: u64,
    pub(crate) conn_index: u64,
    pub(crate) syn: u64,
    pub(crate) tw: u64,
    pub(crate) listeners: u64,
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
    SEND_FLOOR
        + RECV_FLOOR
        + b(FLOOR_RECORDS * size_of::<Record>() + FLOOR_INTERVALS * size_of::<Interval>())
}

/// boost の枠 1 つの項 d_s + d_r + d_rec + d_h です。
pub(crate) fn boost_per_slot() -> u64 {
    (BOOST_SIZE - SEND_FLOOR)
        + (BOOST_SIZE - RECV_FLOOR)
        + b(BOOST_RECORDS * size_of::<Record>() + BOOST_INTERVALS * size_of::<Interval>())
}

/// 核の表の固定の項の内訳です。表の作成と同じ数で数えます。
pub(crate) fn fix_parts(l: &Limits, mtu: usize, stack_size: usize) -> FixParts {
    let n = l.conns();
    let ent = size_of::<index::IndexEnt>();
    let nodes = n * NUM_TIMERS;
    let dlist = |k: usize| b(k * (2 * size_of::<u32>() + size_of::<bool>()));
    FixParts {
        stack: b(stack_size),
        conn_slots: b(n * conn::slot_bytes()),
        conn_index: b(index::capacity_for(n) * (ent + size_of::<u64>())),
        syn: b(l.syn_rows * (size_of::<SynRow>() + size_of::<u32>())
            + index::capacity_for(l.syn_rows) * ent),
        tw: b(l.tw_rows * (size_of::<TwRow>() + 3 * size_of::<u32>())
            + index::capacity_for(l.tw_rows) * ent
            + n * size_of::<u32>()),
        listeners: b(PORTS * size_of::<PortRow<Listener>>()),
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
        Self::with_stack_size(limits, mtu, size_of::<Stack<NoHook>>())
    }

    pub(crate) fn with_stack_size(l: &Limits, mtu: usize, stack_size: usize) -> Self {
        let fix = fix_parts(l, mtu, stack_size).sum();
        let floor_conn = b(l.conns()) * floor_per_conn();
        let boost = b(BOOST_SLOTS) * boost_per_slot() + b(Budget::slot_bytes());
        let frag = b(frag::LIMITS.bytes);
        Self {
            fix,
            floor_conn,
            boost,
            frag,
            total: fix + floor_conn + boost + frag,
            transient: b(BOOST_SLOTS) * (SEND_FLOOR + RECV_FLOOR),
        }
    }
}

/// 核が今持つ可変の保持の量です。表の固定の配列は含みません。核を閉じた後はすべて 0 です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// 使っている接続の枠です。
    pub conns: usize,
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
