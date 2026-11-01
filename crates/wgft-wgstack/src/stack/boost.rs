//! boost の枠の取得と取り合い (Go の `boost.go` の `tryBoost`、`acquire`、`demote`)。
//!
//! 枠は `Budget` の集まりで、需要のある接続が 1 本につき 1 つを取ります。空きが無いときは、枠の順に、1 秒の間
//! どちらの向きにも需要の無い保有者を探し、floor に戻せた 1 本の枠を受け取ります。閉じた接続の枠は、接続の枠を
//! 返すときに返します。Go は保有者の錠を `TryLock` で取れなかった保有者を飛ばしますが、Rust の核は錠を持たない
//! ので、すべての保有者を調べます。

use super::{Hook, Stack};
use crate::budget::BoostArrays;
use crate::buf::ring::Ring;
use crate::buf::{FLOOR_INTERVALS, FLOOR_RECORDS, RECV_FLOOR, SEND_FLOOR};
use crate::tcp::boost::{Dir, IDLE_RECLAIM};
use crate::tcp::conn::{ConnId, State};

impl<H: Hook> Stack<H> {
    /// 接続 `id` に枠を求めます (Go の `tryBoost`)。需要の記録が真を返した操作の後に呼びます。
    pub(crate) fn try_boost(&mut self, id: ConnId, dir: Dir, now: i64) {
        if self.s.budget.held_by(id).is_some() {
            return;
        }
        let got = match self.s.budget.acquire(id) {
            Some(x) => Some(x),
            None => self.reclaim_for(id, now),
        };
        let Some((slot, arrays)) = got else {
            return;
        };
        let i = id.slot;
        let mut c = self.conn(i);
        if c.t.generation != id.generation
            || c.b.boost.is_some()
            || c.t.app_closed
            || matches!(c.t.state, State::Free | State::Closed)
        {
            c.s.budget.release(slot, arrays);
            return;
        }
        if let Err(arrays) = c.enter_boost(slot, arrays) {
            // 送信の輪の chunk を確保できませんでした。枠を返し、次の需要で求め直します。
            c.s.budget.release(slot, arrays);
            return;
        }
        c.s.stats.boost_granted += 1;
        if dir == Dir::Recv {
            c.grow_recv();
        }
        self.hook.boost_granted(id);
        let mut c = self.conn(i);
        c.signal_write();
        c.after_input(now);
    }

    /// 空きの枠が無いとき、枠の順に保有者を調べ、floor に戻せた保有者の枠を `id` に渡します。
    fn reclaim_for(&mut self, id: ConnId, now: i64) -> Option<(usize, BoostArrays)> {
        for n in 0..self.s.budget.slots() {
            let Some(h) = self.s.budget.holder(n) else {
                continue;
            };
            if h == id || !self.demote(h, now) {
                continue;
            }
            let arrays = self.s.budget.hand_over(n, id)?;
            return Some((n, arrays));
        }
        None
    }

    /// 需要の無い保有者 `h` を floor に戻せたかを返します (Go の `demote`)。戻すのは次の条件がすべて成り立つときだけ
    /// です。受信は、順序どおりの未読の byte が floor 以下であること。送信は、送信の輪の byte が floor 以下で、確認を
    /// 待つ記録の数が floor の記録の輪の容量以下であること。最後に、hook の `may_return` が真を返すことです。
    ///
    /// 戻すときに順序外のデータが floor の外にあるか、区間が floor の表に入らなければ、その分を取り消します (RFC 2018
    /// 8 節)。相手は累積の確認まで送ったデータを持つので、取り消したデータは再送で届きます。戻した後も広告した右端は
    /// 縮めず、floor の外に届いたデータは受信のバッファに入れずに捨てます (`input_data` の上限)。輪の確保に失敗した
    /// ら、取り消しの後でも boost の段のままにします。
    pub(super) fn demote(&mut self, h: ConnId, now: i64) -> bool {
        let Some(i) = self.conns.resolve(h) else {
            return false;
        };
        let c = self.conn(i);
        if c.b.boost.is_none() || now - c.k.last_demand < IDLE_RECLAIM {
            return false;
        }
        if c.b.rcv.unread() > RECV_FLOOR {
            return false;
        }
        if c.t.tail_off - c.t.una_off > SEND_FLOOR || c.b.recs.len() > FLOOR_RECORDS {
            return false;
        }
        if !self.hook.may_return(h) {
            return false;
        }
        let c = self.conn(i);
        let limit = c.b.rcv.read_off + RECV_FLOOR;
        let reneged = c.b.rcv.renege(limit, FLOOR_INTERVALS);
        c.s.stats.boost_reneged_bytes += reneged;
        let (lo, hi) = (c.t.una_off, c.t.tail_off);
        let Ok(snd) =
            c.b.snd
                .copy_into(Ring::new(SEND_FLOOR), &mut c.s.chunks, |f| f(lo, hi))
        else {
            return false;
        };
        let rcv = if c.k.rcv_boost {
            let Ok(r) = c.b.rcv.copied_ring(Ring::new(RECV_FLOOR), &mut c.s.chunks) else {
                let mut snd = snd;
                snd.release(&mut c.s.chunks);
                return false;
            };
            Some(r)
        } else {
            None
        };
        // 送信の向きを floor の段に移し、boost の段の chunk の表を取り出します。
        c.b.snd.release(&mut c.s.chunks);
        let snd_table = c.b.snd.take_table();
        c.b.snd = snd;
        c.t.snd_cap = SEND_FLOOR;
        let floor_recs = core::mem::take(&mut c.b.spare_recs);
        let boost_recs = c.b.recs.resize(floor_recs);
        // 受信の向きを floor の段に移します。受信が floor の段のままなら、Go と同じく floor の表の中で区間を入れ
        // 直します。
        let (boost_iv, rcv_table) = if let Some(r) = rcv {
            c.b.rcv.r.release(&mut c.s.chunks);
            let rcv_table = c.b.rcv.r.take_table();
            c.b.rcv.r = r;
            let floor_iv = core::mem::take(&mut c.b.spare_iv);
            let boost_iv = match c.b.rcv.set_intervals(floor_iv) {
                Ok(boost_iv) => boost_iv,
                Err(floor_iv) => floor_iv, // 取り消しの後の区間は floor の表に入るので起きません
            };
            (boost_iv, rcv_table)
        } else {
            let scratch = core::mem::take(&mut c.b.spare_iv);
            let boost_iv = c.b.rcv.rebuild_intervals(scratch);
            (boost_iv, core::mem::take(&mut c.b.spare_tbl))
        };
        c.t.rcv_cap = RECV_FLOOR;
        c.t.rcv_ssthresh = c.t.rcv_ssthresh.min(RECV_FLOOR);
        c.k.rcv_boost = false;
        if let Some(n) = c.b.boost.take() {
            let arrays = BoostArrays {
                recs: boost_recs,
                iv: boost_iv,
                snd: snd_table,
                rcv: rcv_table,
            };
            c.s.budget.release(n, arrays);
        }
        c.s.stats.boost_reclaimed += 1;
        self.hook.boost_returned(h);
        true
    }
}
