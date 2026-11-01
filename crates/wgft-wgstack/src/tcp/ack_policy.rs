//! 受け手の ACK の送り方のうち、遅延 ACK の外で ACK を早める規則 (Go の `ackpolicy.go`)。

use super::conn::TMR_DELACK;
use super::ctx::Conn;
use crate::seq;
use crate::wire::SackBlock;

/// 相手の segment の大きさの推定の初期値の上限 (Linux の TCP_MSS_DEFAULT) です。
const MIN_RCV_MSS_EST: u32 = 536;

/// 遅らせずに返す ACK の数の上限 (Linux の TCP_MAX_QUICKACKS) です。
const QUICKACK_MAX: u64 = 16;

impl Conn<'_> {
    /// 順序どおりに受けた `n` byte の segment で相手の segment の大きさの推定を更新します (Linux の
    /// tcp_measure_rcv_mss)。
    pub(crate) fn measure_rcv_mss(&mut self, n: usize) {
        let rcv_mss = self.rcv_mss();
        if self.t.rcv_mss_est == 0 {
            self.t.rcv_mss_est = MIN_RCV_MSS_EST.min(rcv_mss);
        }
        let n = u32::try_from(n).unwrap_or(u32::MAX);
        if n >= self.t.rcv_mss_est {
            self.t.rcv_mss_est = n.min(rcv_mss);
        }
    }

    /// 接続の始めの最初のデータと、RTO より長く黙った後のデータで、遅らせずに返す ACK の数を補います (Linux の
    /// tcp_event_data_recv と tcp_incr_quickack)。
    pub(crate) fn note_quickack(&mut self, now: i64) {
        if self.t.rcvd_data && now - self.t.last_data_rcvd <= self.cur_rto() {
            return;
        }
        self.raise_quickack();
    }

    /// 遅らせずに返す ACK の数を、広告した窓の 2 MSS ごとに 1 つ、2 から上限の間の数まで上げます。進んでいる数は
    /// 下げません (Linux の tcp_incr_quickack)。
    fn raise_quickack(&mut self) {
        let q = u64::from(self.rcv_window()) / (2 * u64::from(self.t.rcv_mss_est.max(1)));
        let q = u8::try_from(q.clamp(2, QUICKACK_MAX)).unwrap_or(u8::MAX);
        self.t.quick_acks = self.t.quick_acks.max(q);
    }

    /// 既に届いていた `[seq, seq+n)` を受けたとき、その範囲を D-SACK の block として次の ACK の先頭に載せ
    /// (RFC 2883)、quickack に入って対話の印を外します (Linux の tcp_dsack_set、tcp_dsack_extend、
    /// tcp_enter_quickack_mode)。ACK を送る前に次の重複が届けば、接するか重なるときだけ block を広げます。
    pub(crate) fn note_duplicate(&mut self, seq: u32, n: u32) {
        if n == 0 {
            return;
        }
        let t = &mut *self.t;
        if t.sack_ok {
            let b = SackBlock {
                left: seq,
                right: seq.wrapping_add(n),
            };
            if !t.dsack_pending {
                (t.dsack, t.dsack_pending) = (b, true);
            } else if seq::le(b.left, t.dsack.right) && seq::le(t.dsack.left, b.right) {
                t.dsack = SackBlock {
                    left: seq::min(b.left, t.dsack.left),
                    right: seq::max(b.right, t.dsack.right),
                };
            }
        }
        self.raise_quickack();
        self.t.pingpong = false;
    }

    /// アプリケーションの読み取りが受信のバッファを空にし、遅延 ACK を待つ segment があるとき、対話の流れでなければ
    /// ACK をすぐ送ります (RFC 1122 4.2.3.2)。
    pub(crate) fn ack_on_drain(&mut self) {
        if !self.t.pingpong && self.b.rcv.unread() == 0 && self.t.tdl[TMR_DELACK] != 0 {
            self.t.ack_now = true;
        }
    }
}
