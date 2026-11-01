//! boost の需要と段の移し方 (Go の `boost.go` の接続の部分、wgstack.md の「boost の取得と floor への戻り」)。
//!
//! 需要のある接続は boost の枠を 1 つ取り、送信の向きを boost の段に移します。受信の向きは受信の需要で移します。
//! 枠の取り合いと hook の呼び出しは核の値が持ちます (`stack::boost`)。
//!
//! 段を移す処理は、輪の生きている範囲を新しい chunk へ写し、写す間だけ古い chunk と合わせて持ちます。Go の輪は
//! 確保に失敗しませんが、Rust の輪は chunk の確保が失敗しえます。段を移す処理は、新しい輪をすべて作ってから古い輪と
//! 替えるので、確保に失敗したら段を変えません。枠を返すときの `drop_resources` はこの処理を通らずに記録の輪と区間の
//! 表を floor のものに戻すので、段の移し方を変えるときは `drop_resources` も直します。

use super::ctx::Conn;
use super::{MS, SEC};
use crate::buf::BOOST_SIZE;
use crate::buf::records::Record;
use crate::buf::recv::Interval;
use crate::config::BoostPolicy;
use crate::fixed_vec::FixedVec;

/// 需要の区間です。
const DEMAND_WINDOW: i64 = 250 * MS;
/// 区間に読めたか受け入れた byte がこの値以上なら需要があります。
const DEMAND_BYTES: i64 = 64 << 10;
/// 需要の無い保有者を floor に戻せるまでの時間です。
pub(crate) const IDLE_RECLAIM: i64 = SEC;

/// 1 つの向きの需要の区間です。区間は入出力が成功したときに時刻で区切ります。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Demand {
    start: i64,
    n: i64,
    hit: bool,
}

impl Demand {
    /// `now` に `n` byte を記録し、この区間で初めて閾値に届いたときに真を返します。
    pub(crate) fn add(&mut self, now: i64, n: usize) -> bool {
        if now - self.start > DEMAND_WINDOW {
            (self.start, self.n, self.hit) = (now, 0, false);
        }
        self.n = self.n.saturating_add(i64::try_from(n).unwrap_or(i64::MAX));
        if self.n >= DEMAND_BYTES && !self.hit {
            self.hit = true;
            return true;
        }
        false
    }
}

/// 需要の向きです。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dir {
    Send,
    Recv,
}

impl Conn<'_> {
    /// 需要を記録します。枠を求める必要があれば真を返し、呼び手は続けて核の `try_boost` を呼びます。受信の向きの
    /// 需要で、すでに送信の向きの需要で枠を持つ接続は、同じ枠のまま受信の窓を広げます。
    pub(crate) fn note_demand(&mut self, dir: Dir, now: i64) -> bool {
        self.k.last_demand = now;
        if self.s.config.boost == BoostPolicy::Never {
            return false;
        }
        if self.b.boost.is_none() {
            return true;
        }
        if dir == Dir::Recv && !self.k.rcv_boost {
            self.grow_recv();
        }
        false
    }

    /// 枠を持つ接続の送信の向きを boost の段に移し、boost の配列を使い始めます。`iv` は受信が boost の段に移る
    /// まで控えに置きます。輪の確保に失敗したら何も変えずに配列を返します。
    pub(crate) fn enter_boost(
        &mut self,
        slot: usize,
        recs: FixedVec<Record>,
        iv: FixedVec<Interval>,
    ) -> Result<(), (FixedVec<Record>, FixedVec<Interval>)> {
        let (lo, hi) = (self.t.una_off, self.t.tail_off);
        let Ok(next) = self
            .b
            .snd
            .resized(BOOST_SIZE, &mut self.s.chunks, |f| f(lo, hi))
        else {
            return Err((recs, iv));
        };
        self.b.snd.release(&mut self.s.chunks);
        self.b.snd = next;
        self.t.snd_cap = BOOST_SIZE;
        self.b.spare_recs = self.b.recs.resize(recs);
        self.b.spare_iv = iv;
        self.b.boost = Some(slot);
        Ok(())
    }

    /// 受信の窓を floor より先へ開きます。枠を持つ接続で呼びます。広告する窓は一度に開きません。窓の上限は測定で
    /// 上がり、窓は届いた segment ごとに広がります。輪の確保に失敗したら floor の段のままにし、次の需要で試し直します。
    pub(crate) fn grow_recv(&mut self) {
        let Ok(next) = self.b.rcv.resized_ring(BOOST_SIZE, &mut self.s.chunks) else {
            return;
        };
        let boost_iv = core::mem::take(&mut self.b.spare_iv);
        match self.b.rcv.set_intervals(boost_iv) {
            Ok(floor) => self.b.spare_iv = floor,
            Err(boost_iv) => {
                // boost の表は floor の表より大きいので起きません。
                self.b.spare_iv = boost_iv;
                let mut next = next;
                next.release(&mut self.s.chunks);
                return;
            }
        }
        self.b.rcv.r.release(&mut self.s.chunks);
        self.b.rcv.r = next;
        self.t.rcv_cap = BOOST_SIZE;
        self.k.rcv_boost = true;
    }

    /// 枠を持っていれば boost の配列を `Budget` に返し、記録の輪と区間の表を floor のものに戻します。hook は
    /// 呼びません (閉じた接続の枠を返すときには呼ばない約束)。輪は呼び手が返し、容量は呼び手が戻します。
    pub(crate) fn release_boost(&mut self) {
        let Some(slot) = self.b.boost.take() else {
            return;
        };
        self.k.rcv_boost = false;
        let floor_recs = core::mem::take(&mut self.b.spare_recs);
        self.b.recs.clear();
        let recs = self.b.recs.resize(floor_recs);
        let iv = if self.b.rcv.intervals_capacity() == crate::buf::BOOST_INTERVALS {
            self.b.rcv.clear_intervals();
            let floor_iv = core::mem::take(&mut self.b.spare_iv);
            match self.b.rcv.set_intervals(floor_iv) {
                Ok(boost) => boost,
                Err(floor) => floor, // 区間を空にしたので起きません
            }
        } else {
            core::mem::take(&mut self.b.spare_iv)
        };
        self.s.budget.release(slot, recs, iv);
    }
}
