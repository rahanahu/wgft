//! 接続の view と、確立と閉じる手順 (Go の `tcb.go`)。
//!
//! [`Conn`] は 1 つの接続の枠の 3 つの部分と、核の共有の状態を同時に借ります。接続の規則はこの値のメソッドで、
//! Go の `*tcb` のメソッドと同じ名前と順で書きます。
//!
//! 枠の資源の返し方 (I3、I6) は Go と同じです。
//!
//! - `enter_closed`:プロトコルを終えた接続 (CLOSED)。タイマー、出力の節、送る予定の印、送信の輪、順序外の区間と
//!   その中身、4 つ組の hash の表の項、accept の待ち行列の節を返します。未読のデータを持つ受信の輪と boost の枠は、
//!   アプリケーションが閉じて枠を返すまで持ちます。アプリケーションが閉じていれば、続けて `release` で枠を返します
//! - `drop_resources`:枠を返す前に、タイマー、出力の節、送信と受信の輪、順序外の区間、boost の枠を返し、記録の輪と
//!   区間の表を枠と共に持つ floor のものに戻します
//! - `release`:`drop_resources` の後に、4 つ組の hash の表の項を外して枠を返します
//! - `try_retire`:`drop_resources` の後に、TIME_WAIT の表の行に移して枠を返します
//! - `free_slot`:accept の待ち行列の節を外し、世代を進め、欄を 0 に戻して空きの list に返します

use super::conn::{ConnBufs, ConnCold, ConnError, State, TMR_CLOSE, TMR_DELACK, TMR_RETRANS, Tcb};
use super::syn::SynRow;
use super::timewait::{TwRow, TwState};
use super::{
    FIN_TIMEOUT, INITIAL_WINDOW_SEGS, IP_TCP_HEADERS, NUM_TIMERS32, RCV_WINDOW_SHIFT, RTO_INIT,
    TS_OPTION_LEN, TW_TIMEOUT, listen,
};
use crate::buf::{RECV_FLOOR, SEND_FLOOR};
use crate::output::NIL;
use crate::seq;
use crate::stack::Shared;
use crate::stack::shared::{EV_CLOSED, EV_READ, EV_WRITE};
use crate::wire::{FLAG_ACK, FLAG_RST, Segment, TcpHeader};

/// 1 つの接続の view です。
#[derive(Debug)]
pub(crate) struct Conn<'a> {
    pub(crate) id: u32,
    pub(crate) t: &'a mut Tcb,
    pub(crate) k: &'a mut ConnCold,
    pub(crate) b: &'a mut ConnBufs,
    pub(crate) s: &'a mut Shared,
}

/// Go の `int` の値を `u32` の欄に入れます。値は欄に収まる範囲です。
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "matches Go's uint32 conversion"
)]
pub(crate) fn u32_of(x: i64) -> u32 {
    x as u32
}

/// Go の `uint32(x)` と同じく、64 bit の値の下位 32 bit です。
#[expect(
    clippy::cast_possible_truncation,
    reason = "matches Go's uint32 conversion"
)]
pub(crate) fn lo32(x: u64) -> u32 {
    x as u32
}

/// 相手へ送る segment の中身の上限です (SACK の block を除く option を引いた値)。
pub(crate) fn seg_mss(t: &Tcb) -> u32 {
    // PMTU は 552 以上なので、header を引いても負になりません。
    let mut m = i64::from(t.peer_mss).min(i64::from(t.pmtu) - i64::from(IP_TCP_HEADERS));
    if t.ts_ok {
        m -= i64::from(TS_OPTION_LEN);
    }
    u32_of(m.max(1))
}

impl Conn<'_> {
    fn timer_node(&self, kind: usize) -> u32 {
        self.id * NUM_TIMERS32 + u32::try_from(kind).unwrap_or(0)
    }

    /// タイマーの節 `kind` を時刻 `at` に張ります。
    pub(crate) fn arm(&mut self, kind: usize, at: i64) {
        self.t.tdl[kind] = at;
        let node = self.timer_node(kind);
        self.s.wheel.set(node, u64::try_from(at).unwrap_or(0));
    }

    /// タイマーの節 `kind` を外します。
    pub(crate) fn disarm(&mut self, kind: usize) {
        if self.t.tdl[kind] != 0 {
            self.t.tdl[kind] = 0;
            let node = self.timer_node(kind);
            self.s.wheel.cancel(node);
        }
    }

    /// 相手へ送る segment の中身の上限です ([`seg_mss`])。
    pub(crate) fn seg_mss(&self) -> u32 {
        seg_mss(self.t)
    }

    /// 相手から受ける segment の中身の大きさの見積もりです。遅延 ACK と受け手の SWS の回避に使います。
    pub(crate) fn rcv_mss(&self) -> u32 {
        let m = self.s.our_mss();
        if self.t.ts_ok { m - TS_OPTION_LEN } else { m }
    }

    pub(crate) fn data_end_seq(&self) -> u32 {
        self.t
            .iss
            .wrapping_add(1)
            .wrapping_add(lo32(self.t.tail_off))
    }

    /// 自分の FIN のシーケンス番号です。送信の向きを閉じた後だけ意味を持ちます。
    pub(crate) fn fin_seq(&self) -> u32 {
        self.data_end_seq()
    }

    pub(crate) fn fin_acked(&self) -> bool {
        self.t.fin_sent && seq::gt(self.t.snd_una, self.fin_seq())
    }

    pub(crate) fn signal_read(&mut self) {
        self.s.signal(self.id, EV_READ);
    }

    pub(crate) fn signal_write(&mut self) {
        self.s.signal(self.id, EV_WRITE);
    }

    /// 握手の途中の行 `r` と最後の ACK から接続を確立します。dial の側を足す段では、交渉した値の組から作る
    /// 入口に分けます (wgstack-rs.md の「dial の側を足す継ぎ目」)。
    pub(crate) fn establish(&mut self, r: &SynRow, seg: &Segment<'_>, now: i64) {
        let generation = self.t.generation;
        let mtu = u32::try_from(self.s.config.mtu).unwrap_or(0);
        *self.t = Tcb {
            generation,
            state: State::Established,
            tup: r.tup,
            iss: r.iss,
            irs: r.irs,
            snd_una: r.iss.wrapping_add(1),
            snd_nxt: r.iss.wrapping_add(1),
            snd_max: r.iss.wrapping_add(1),
            ws_ok: r.ws_ok,
            sack_ok: r.sack_ok,
            ts_ok: r.ts_ok,
            peer_mss: u32::from(r.peer_mss),
            pmtu: mtu,
            snd_cap: SEND_FLOOR,
            rcv_nxt: r.irs.wrapping_add(1),
            rcv_cap: RECV_FLOOR,
            rcv_ssthresh: RECV_FLOOR,
            adv_right: u64::from(r.rcv_wnd),
            ts_recent: r.ts_recent,
            ts_recent_at: now,
            ts_offset: r.ts_offset,
            rto: RTO_INIT,
            ssthresh: u32::MAX,
            recover: r.iss,
            ..Tcb::default()
        };
        *self.k = ConnCold::default();
        self.s.events.reset(self.id);
        let t = &mut *self.t;
        t.last_ack_sent = t.rcv_nxt;
        if t.ws_ok {
            (t.snd_wscale, t.rcv_wscale) = (r.snd_wscale, RCV_WINDOW_SHIFT);
        }
        t.snd_wnd = u32::from(seg.wnd) << t.snd_wscale;
        t.max_snd_wnd = t.snd_wnd;
        (t.snd_wl1, t.snd_wl2) = (seg.seq, seg.ack);
        // 区間の木の優先度の種は接続ごとの秘密で、相手が木の形を選べないようにします。
        let seed = self.s.random_below(1 << 62);
        self.b.rcv.restart(RECV_FLOOR, seed);
        self.b.recs.clear();
        if self.t.ts_ok
            && let Some((ts_val, ts_ecr)) = seg.opt.ts
        {
            (self.t.ts_recent, self.t.ts_recent_at) = (ts_val, now);
            // cookie の TSval は下位の bit に option を入れたので、RTT の標本にしません。
            if ts_ecr != 0 && !r.cookie {
                self.ts_rtt_sample(ts_ecr, now);
            }
        } else if !r.rtx && r.sent_at.as_nanos() != 0 {
            self.rtt_sample(now - crate::stack::ns(r.sent_at));
        }
        let mss = self.seg_mss();
        self.t.cwnd = if r.rtx {
            mss // RFC 5681 3.1、Linux と同じく 1 segment
        } else {
            INITIAL_WINDOW_SEGS * mss
        };
        self.t.last_send_at = now;
    }

    /// 入力、タイマー、アプリケーションの操作の後に、枠を返すか行に移すかを決め、送るものがあれば接続の組に
    /// 並べます。
    pub(crate) fn after_input(&mut self, now: i64) {
        if self.t.state == State::Free {
            return;
        }
        if self.try_retire(now) {
            return;
        }
        if self.want_output() {
            self.s.queue_conn(self.id);
        }
        // 窓が 0 で送るものがあり、確認を待つものが無ければ窓の probe を張ります。
        if self.t.snd_wnd == 0
            && !self.t.persist
            && self.pipe() == 0
            && self.has_unsent()
            && self.t.state != State::Closed
        {
            self.enter_persist(now);
        }
    }

    /// 送る予定の高速の再送、窓の probe、TLP の probe と、確認を待つ TLP の probe の印を消します。
    pub(crate) fn cancel_sends(&mut self) {
        self.cancel_tlp();
        self.t.fast_rtx = false;
        self.t.probe_pending = false;
    }

    /// 未送信のデータか未送信の FIN か、送り直しを待つ失われた記録があるかを返します。
    pub(crate) fn has_unsent(&mut self) -> bool {
        if self.pick_rule1().is_some() {
            return true;
        }
        if seq::lt(self.t.snd_nxt, self.data_end_seq()) {
            return true;
        }
        self.t.snd_shut && seq::le(self.t.snd_nxt, self.fin_seq())
    }

    /// 行に移る条件を満たした接続を TIME_WAIT の表の行に移し、プロトコルの終わった閉じた接続の枠を返します。
    /// 移したか返したかを返します。
    pub(crate) fn try_retire(&mut self, now: i64) -> bool {
        if !self.t.app_closed {
            return false;
        }
        if self.t.state == State::Closed {
            self.release();
            return true;
        }
        if !self.b.rcv.empty() || self.t.snd_una != self.t.snd_max || !self.fin_acked() {
            if self.t.state == State::FinWait2 && self.t.tdl[TMR_CLOSE] == 0 {
                // 順序外のデータを持って閉じた FIN_WAIT_2。Linux の tcp_fin_timeout の後に終えます。
                self.arm(TMR_CLOSE, now + FIN_TIMEOUT);
            }
            return false;
        }
        let (state, deadline) = match self.t.state {
            State::FinWait2 => (TwState::FinWait2, now + FIN_TIMEOUT),
            State::TimeWait => (TwState::TimeWait, self.t.tw_enter + TW_TIMEOUT),
            _ => return false,
        };
        let wnd = self.window_field();
        let row = TwRow {
            tup: self.t.tup,
            snd_nxt: self.t.snd_max,
            rcv_nxt: self.t.rcv_nxt,
            ts_recent: self.t.ts_recent,
            ts_offset: self.t.ts_offset,
            deadline: crate::stack::time(deadline),
            origin: self.id,
            generation: self.t.generation,
            wnd,
            wscale: self.t.rcv_wscale,
            state,
            ts_ok: self.t.ts_ok,
            ..TwRow::default()
        };
        let ack_now = self.t.ack_now;
        self.drop_resources();
        if self.t.in_index {
            self.unindex();
            self.s.add_tw_row(row, ack_now, now);
        }
        self.free_slot();
        true
    }

    /// 接続を CLOSED にし、4 つ組の hash の表から外します。`err` はアプリケーションの読み書きに返す誤りです
    /// (`None` なら、受けたデータの後に EOF を返します)。アプリケーションが閉じていれば枠を返します。
    pub(crate) fn enter_closed(&mut self, err: Option<ConnError>) {
        if self.t.state == State::Free {
            return;
        }
        self.t.state = State::Closed;
        if err.is_some() && self.t.err.is_none() {
            self.t.err = err;
        }
        self.stop_timers_and_output();
        self.cancel_sends();
        self.t.ack_now = false;
        // 送信の輪はもう使いません。受信の未読のデータは読ませるために残し、順序外のデータは捨てます。
        self.b.snd.release(&mut self.s.chunks);
        self.t.una_off = self.t.tail_off;
        self.b.rcv.clear_intervals();
        let (lo, hi) = (self.b.rcv.read_off, self.b.rcv.nxt_off);
        self.b.rcv.r.retain(lo, hi, &mut self.s.chunks);
        // boost の枠は、boost の大きさの未読のデータを持ちうるので、枠を返すまで持ちます。
        self.unindex();
        self.dequeue();
        self.signal_read();
        self.signal_write();
        self.s.signal(self.id, EV_CLOSED);
        if self.t.app_closed {
            self.release();
        }
    }

    /// 相手の RST で接続を終えます。accept の待ち行列にいる接続は待ち行列から外して枠を返します。
    pub(crate) fn reset_by_peer(&mut self) {
        if !self.t.accepted {
            self.release();
            return;
        }
        // Linux と同じく、RST の前に受けた順序どおりのデータは読ませ、その後に誤りを返します。
        self.enter_closed(Some(ConnError::Reset));
    }

    /// 接続の今の番号で RST を制御の輪に積みます。
    pub(crate) fn send_rst(&mut self) {
        self.s.send_ctl(TcpHeader {
            tup: self.t.tup,
            seq: self.t.snd_nxt,
            ack: self.t.rcv_nxt,
            flags: FLAG_RST | FLAG_ACK,
            wnd: 0,
        });
    }

    /// タイマーをすべて止め、接続の組の出力の list から外します。
    pub(crate) fn stop_timers_and_output(&mut self) {
        for k in [TMR_RETRANS, TMR_DELACK, TMR_CLOSE, 3] {
            self.disarm(k);
        }
        self.s.unqueue_conn(self.id);
    }

    /// 接続が 4 つ組の hash の表にあれば外します。
    pub(crate) fn unindex(&mut self) {
        if self.t.in_index {
            self.s.conn_idx.remove(self.t.tup);
            self.t.in_index = false;
        }
    }

    /// 接続が accept の待ち行列にあれば外します。
    fn dequeue(&mut self) {
        let link = self.s.qlinks[self.id as usize];
        if !link.queued {
            return;
        }
        if let Some(l) = self.s.listeners.by_port_mut(link.listener) {
            listen::dequeue(l, &mut self.s.qlinks, self.id);
        } else {
            self.s.qlinks[self.id as usize] = super::conn::QLink::default();
        }
        self.s.queued -= 1;
    }

    /// 枠のバッファ、タイマー、出力の節、boost の枠を返します。
    pub(crate) fn drop_resources(&mut self) {
        self.stop_timers_and_output();
        let pool = &mut self.s.chunks;
        self.b.snd.release(pool);
        self.b.rcv.r.release(pool);
        self.b.rcv.clear_intervals();
        self.release_boost();
        self.b.recs.clear();
    }

    /// 枠を返します。世代を進めます。
    pub(crate) fn release(&mut self) {
        if self.t.state == State::Free {
            return;
        }
        self.drop_resources();
        self.unindex();
        self.free_slot();
    }

    /// 枠を空きの list に戻します。
    fn free_slot(&mut self) {
        self.dequeue();
        if self.t.accepted {
            // Go が枠を返す時に通知の channel を閉じて待つ呼び手を起こすのと同じく、読み取りと書き込みの知らせを
            // 付けます。知らせは枠を最後に使った接続の handle で出ます。
            self.signal_read();
            self.signal_write();
        }
        let generation = self.t.generation + 1;
        *self.t = Tcb {
            generation,
            ..Tcb::default()
        };
        *self.k = ConnCold::default();
        self.b.reset_to_floor(&mut self.s.chunks);
        let pushed = self.s.conn_free.try_push(self.id);
        debug_assert!(pushed.is_ok(), "the free list holds every slot");
        debug_assert_eq!(self.s.qlinks[self.id as usize].next, NIL);
    }

    /// TCP の義務を果たせない接続を終えます。アプリケーションが閉じていれば枠を返し、閉じていなければ CLOSED に
    /// して誤りを返します。
    pub(crate) fn abort_with(&mut self, err: ConnError) {
        if self.t.app_closed || !self.t.accepted {
            self.release();
            return;
        }
        self.enter_closed(Some(err));
    }

    /// 送信の向きを閉じ、FIN を送る印を付けて状態を移します (Go の `shutdownWrite`)。
    pub(crate) fn shutdown_write(&mut self) {
        if self.t.snd_shut {
            return;
        }
        self.t.state = match self.t.state {
            State::Established => State::FinWait1,
            State::CloseWait => State::LastAck,
            _ => return,
        };
        self.t.snd_shut = true;
        self.signal_write();
    }
}
