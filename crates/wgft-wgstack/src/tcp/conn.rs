//! 接続の枠 (Go の `tcb.go` の枠の部分)。
//!
//! 枠は作成の時に N_c 個を確保し、確立の時に使い、枠を返すときに世代を進めます。世代は、枠を返した後も
//! 呼び手が持ち続ける古い handle を見分けます。空きの枠は小さい番号から使い、返した枠を先に使います
//! (Go と同じ順で、枠の番号は出力の順に効くので bit の一致の条件に入ります)。
//! floor の送信の記録の輪と区間の表は、枠を初めて使う時に確保し、枠と共に持ち続けます。
//!
//! 枠の配置は CPU のキャッシュに合わせます (wgstack-rs.md の「接続の枠の配置」、所有者の 2026-11-01 の決定)。
//! 1 つの枠を 3 つの配列に分けて持ちます。
//!
//! - [`Tcb`]:segment ごとの経路が触る欄 (番号、窓、タイマーの期限、印)。キャッシュの行の境目に揃えます
//! - [`ConnCold`]:不要な再送の取り消しと boost の需要のような、まれにしか触らない欄
//! - [`ConnBufs`]:送受信の輪と記録の輪の管理。輪の chunk への pointer の配列 (1 つの輪で 2 KiB) はここにあり、
//!   [`Tcb`] の行を押し広げません
//!
//! accept の待ち行列の節は、別の接続の処理が書き換えるので、核の共有の状態 (`Shared::qlinks`) に置きます。

use crate::buf::chunk::ChunkPool;
use crate::buf::records::{Record, RecordRing};
use crate::buf::recv::{Interval, RecvBuf};
use crate::buf::ring::Ring;
use crate::buf::{
    BOOST_INTERVALS, BOOST_RECORDS, BOOST_SIZE, FLOOR_INTERVALS, FLOOR_RECORDS, RECV_FLOOR,
    SEND_FLOOR,
};
use crate::fixed_vec::{AllocError, FixedVec};
use crate::output::NIL;
use crate::wire::{SackBlock, Tuple};

/// 接続の handle です。接続の枠の番号と 64 bit の世代の組で、核への参照を持たない `Copy` の値です。
/// 枠が別の接続に使われた後の handle は、核の操作で古い handle として扱われます。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId {
    pub(crate) slot: u32,
    pub(crate) generation: u64,
}

impl ConnId {
    /// 接続の枠の番号です。呼び手が接続ごとの表を核の外に持つ時の位置に使えます。
    pub fn index(&self) -> usize {
        self.slot as usize
    }
}

/// 接続の枠の状態です。握手の途中 (SYN-RCVD) は握手の途中の表の行が、行に移った TIME_WAIT と FIN_WAIT_2 は
/// TIME_WAIT の表が持ちます。dial の側を足す段で SYN-SENT を足します。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum State {
    /// 枠は空きです。
    #[default]
    Free,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    /// プロトコルは終わりましたが、アプリケーションがまだ閉じていません。
    Closed,
}

/// 接続の読み書きに返す誤りのうち、接続に残るものです。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnError {
    /// 相手の RST で終わりました。
    Reset,
    /// 再送か窓の probe の回数を使い切りました。
    TimedOut,
    /// 会計の不整合で閉じました。
    Accounting,
}

/// 接続の枠に固定で埋め込むタイマーの節です (Go の `tmr*`)。4 つ目は用意だけの keepalive です。
pub(crate) const TMR_RETRANS: usize = 0;
pub(crate) const TMR_DELACK: usize = 1;
pub(crate) const TMR_CLOSE: usize = 2;

/// 送信の記録の list (RACK の送った時刻の順の list と損失の待ち行列)。`head` と `tail` は記録の通し番号です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecList {
    pub(crate) head: u32,
    pub(crate) tail: u32,
    pub(crate) n: i32,
}

/// segment ごとの経路が触る接続の欄です (Go の `tcbState` の大部分)。時刻は Go と同じ符号つきの ns で持ち、
/// 0 は「無し」です。確立の時に 0 から始めます。
///
/// 欄の並びは、受信と送信の経路が最初に触る欄を前に置きます。`repr(C)` は並びを保ち、64 byte の揃えは
/// 枠どうしがキャッシュの行を分け合わないようにします。
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Tcb {
    // 受信の入口と送る segment の header
    pub(crate) generation: u64,
    pub(crate) tup: Tuple,
    pub(crate) state: State,
    pub(crate) in_index: bool,
    pub(crate) ts_ok: bool,
    pub(crate) sack_ok: bool,
    pub(crate) rcv_nxt: u32,
    pub(crate) irs: u32,
    pub(crate) snd_una: u32,
    pub(crate) snd_nxt: u32,
    pub(crate) snd_max: u32,
    pub(crate) snd_wnd: u32,
    pub(crate) max_snd_wnd: u32,
    pub(crate) snd_wl1: u32,
    pub(crate) snd_wl2: u32,
    pub(crate) iss: u32,
    pub(crate) adv_right: u64,
    pub(crate) una_off: u64,
    pub(crate) tail_off: u64,
    pub(crate) ts_recent: u32,
    pub(crate) ts_offset: u32,
    pub(crate) last_ack_sent: u32,
    pub(crate) snd_wscale: u8,
    pub(crate) rcv_wscale: u8,
    pub(crate) ack_now: bool,
    pub(crate) ack_delayed: bool,
    /// 次の ACK の先頭に載せる D-SACK の block (RFC 2883) があります。ACK を作るたびに読むので、受け手の欄の
    /// 行に置きます。
    pub(crate) dsack_pending: bool,
    pub(crate) dsack: SackBlock,
    pub(crate) tdl: [i64; crate::tcp::NUM_TIMERS],

    // 受け手の ACK と窓
    pub(crate) rcv_cap: u64,
    pub(crate) rcv_ssthresh: u64,
    pub(crate) rcv_want: u64,
    pub(crate) rcv_since_ack: i64,
    pub(crate) rcv_mss_est: u32,
    pub(crate) quick_acks: u8,
    pub(crate) pingpong: bool,
    pub(crate) rcvd_data: bool,
    pub(crate) fin_rcvd: bool,
    pub(crate) last_data_rcvd: i64,
    pub(crate) rcv_rtt: i64,
    pub(crate) rtt_win_seq: u64,
    pub(crate) rtt_win_time: i64,
    pub(crate) rtt_tsecr: u32,
    pub(crate) ooo_fin: bool,
    pub(crate) accepted: bool,
    pub(crate) app_closed: bool,
    pub(crate) snd_shut: bool,
    pub(crate) ooo_fin_off: u64,
    pub(crate) ts_recent_at: i64,
    pub(crate) last_oow: i64,
    pub(crate) rs_time: i64,
    pub(crate) rs_seq: u64,
    pub(crate) rs_space: u64,

    // 送り手:RTT、輻輳の窓、再送のタイマー
    pub(crate) snd_cap: u64,
    pub(crate) srtt: i64,
    pub(crate) rttvar: i64,
    pub(crate) rto: i64,
    pub(crate) min_rtt: i64,
    pub(crate) retrans_start: i64,
    pub(crate) last_send_at: i64,
    pub(crate) rto_at: i64,
    pub(crate) reo_at: i64,
    pub(crate) tlp_at: i64,
    pub(crate) tw_enter: i64,
    pub(crate) dup_acks: i64,
    pub(crate) probes_out: i64,
    pub(crate) backoff: u32,
    pub(crate) cwnd: u32,
    pub(crate) ssthresh: u32,
    pub(crate) recover: u32,
    pub(crate) ca_acc: u32,
    pub(crate) max_flight: u32,
    pub(crate) cwnd_usage_seq: u32,
    pub(crate) peer_mss: u32,
    pub(crate) pmtu: u32,
    pub(crate) has_rtt: bool,
    pub(crate) has_min_rtt: bool,
    pub(crate) persist: bool,
    pub(crate) in_recovery: bool,
    pub(crate) cwnd_blocked: bool,
    pub(crate) cwnd_limited: bool,
    pub(crate) fast_rtx: bool,
    pub(crate) probe_pending: bool,
    pub(crate) fin_sent: bool,
    pub(crate) ws_ok: bool,
    pub(crate) rto_episode: bool,
    pub(crate) tlp_active: bool,
    pub(crate) tlp_retrans: bool,
    pub(crate) tlp_probe: bool,
    pub(crate) tlp_sampled: bool,
    pub(crate) rtx_cause: u8,
    pub(crate) resend_cause: u8,
    pub(crate) frto: u8,
    pub(crate) frto_new: u8,
    pub(crate) err: Option<ConnError>,
    pub(crate) hs: crate::tcp::cc::Hystart,

    // 送信の記録の scoreboard (Go の scoreboard.go と rack.go の欄。SACK の無い接続も pipe と再送に使います)
    pub(crate) sack_gen: u8,
    pub(crate) rtx_gen: u8,
    pub(crate) rxt_mid: bool,
    pub(crate) q_mid: bool,
    pub(crate) sacked: u32,
    pub(crate) beyond_bytes: u32,
    pub(crate) beyond_cnt: i32,
    pub(crate) loss_idx: i32,
    pub(crate) rxt_idx: i32,
    pub(crate) rxt_off: u32,
    pub(crate) high_sack: u32,
    pub(crate) rec_base: u32,
    pub(crate) rack_lost_beyond: u32,
    pub(crate) q_off: u32,
    pub(crate) sacked_recs: i32,
    pub(crate) rtx_bytes: u32,
    pub(crate) t_list: RecList,
    pub(crate) lost_q: RecList,

    // SACK による回復と RACK-TLP (Go の scoreboard.go、rack.go の欄)。ACK ごとに触ります。
    pub(crate) prior_una: u32,
    pub(crate) prior_cwnd: u32,
    pub(crate) rack_end: u32,
    pub(crate) rack_fack: u32,
    pub(crate) tlp_end: u32,
    pub(crate) tlp_cut_seq: u32,
    pub(crate) rack_xmit: i64,
    pub(crate) rack_rtt: i64,
    /// RACK の並べ替えの窓の倍率 (RFC 8985 6.2 の reo_wnd_mult) です。上限は 255 です。
    pub(crate) reo_wnd_mult: u8,
    pub(crate) rack_ok: bool,
    pub(crate) rack_fack_ok: bool,
    pub(crate) reorder_seen: bool,
    pub(crate) orig_delivered: bool,
    pub(crate) tlp_cut: bool,

    /// CUBIC の状態です。NewReno を選んだ核では使いません。輻輳の回避の ACK ごとに触るので、ここに置きます。
    pub(crate) cubic: crate::tcp::cc::Cubic,
}

/// まれにしか触らない接続の欄です。確立の時に 0 から始めます。
#[derive(Clone, Copy, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the fields follow the Go code"
)]
pub(crate) struct ConnCold {
    // 不要な再送の取り消し (Go の undo.go)
    pub(crate) undo_marker: bool,
    pub(crate) retrans_ts_ok: bool,
    pub(crate) undo_seq: u32,
    pub(crate) undo_cwnd: u32,
    pub(crate) undo_ssthresh: u32,
    pub(crate) undo_retrans: i32,
    pub(crate) retrans_ts: u32,
    pub(crate) total_retrans: u32,
    /// D-SACK で知らされた重複の累計 (Linux の dsack_dups) です。
    pub(crate) dsack_dups: u32,
    // PRR (RFC 6937)。SACK による回復の間だけ触ります。
    pub(crate) prr_delivered: u32,
    pub(crate) prr_out: u32,
    pub(crate) recover_fs: u32,
    // RACK の並べ替えの窓の倍率を保つ回復の数と、倍率を上げた往復の終わり (Go の rack.go)
    pub(crate) dsack_round: u32,
    pub(crate) reo_persist: u8,
    pub(crate) dsack_round_on: bool,
    // boost (Go の boost.go)
    /// 受信の向きも boost の段に移しました。
    pub(crate) rcv_boost: bool,
    pub(crate) last_demand: i64,
    pub(crate) rdem: crate::tcp::boost::Demand,
    pub(crate) wdem: crate::tcp::boost::Demand,
}

/// 接続の送受信の輪と記録の輪です。`repr(C)` で小さな管理の欄を前に、輪の chunk の pointer の配列を後ろに
/// 置きます。受信の経路は受信のバッファの管理の行と、使う chunk の pointer の行だけを触ります。
#[derive(Debug)]
#[repr(C)]
pub(crate) struct ConnBufs {
    pub(crate) recs: RecordRing,
    /// 使っていない方の配列の控えです。boost の間の floor の記録の輪と、受信が boost の段に移るまでの boost の
    /// 区間の表 (移った後は floor の区間の表) を置きます。
    pub(crate) spare_recs: FixedVec<Record>,
    pub(crate) spare_iv: FixedVec<Interval>,
    /// 借りている boost の枠の番号です。
    pub(crate) boost: Option<usize>,
    pub(crate) rcv: RecvBuf,
    pub(crate) snd: Ring,
}

impl ConnBufs {
    fn new() -> Self {
        Self {
            recs: RecordRing::default(),
            spare_recs: FixedVec::new(),
            spare_iv: FixedVec::new(),
            boost: None,
            rcv: RecvBuf::new(RECV_FLOOR, FixedVec::new(), 0),
            snd: Ring::new(SEND_FLOOR),
        }
    }

    /// 枠が持つ floor の記録の輪と区間の表の byte 数です。使っている配列が boost のものなら、それも数えます。
    pub(crate) fn array_bytes(&self) -> (usize, usize) {
        (
            self.recs.heap_bytes() + self.spare_recs.heap_bytes(),
            self.rcv.intervals_heap_bytes() + self.spare_iv.heap_bytes(),
        )
    }

    /// boost の配列を取り出し、boost の印を外します。受信が boost の段に移っていれば、使っている区間の表が boost
    /// のもので、移っていなければ控えが boost のものです。輪の中身は移さないので、呼び手は続けて枠を返します。
    pub(crate) fn take_boost_arrays(&mut self) -> (FixedVec<Record>, FixedVec<Interval>) {
        self.boost = None;
        let recs = self.recs.take();
        let iv = if self.rcv.intervals_capacity() == BOOST_INTERVALS {
            self.rcv.take_intervals()
        } else {
            core::mem::take(&mut self.spare_iv)
        };
        (recs, iv)
    }

    /// 送受信の輪が持つ chunk の数です。
    pub(crate) fn held_chunks(&self) -> usize {
        self.snd.held_chunks() + self.rcv.r.held_chunks()
    }

    /// 輪の chunk を置き場に返し、記録と区間を空にし、容量を floor に戻します。floor の配列は持ち続けます。
    pub(crate) fn reset_to_floor(&mut self, pool: &mut ChunkPool) {
        self.snd.release(pool);
        self.rcv.r.release(pool);
        self.rcv.clear_intervals();
        self.recs.clear();
        self.snd = Ring::new(SEND_FLOOR);
        self.rcv.r = Ring::new(RECV_FLOOR);
        (self.rcv.read_off, self.rcv.nxt_off) = (0, 0);
    }
}

/// accept の待ち行列の節です。`listener` は待ち受けのポートです。
#[derive(Clone, Copy, Debug)]
pub(crate) struct QLink {
    pub(crate) queued: bool,
    pub(crate) listener: u16,
    pub(crate) prev: u32,
    pub(crate) next: u32,
}

impl Default for QLink {
    fn default() -> Self {
        Self {
            queued: false,
            listener: 0,
            prev: NIL,
            next: NIL,
        }
    }
}

/// 接続の枠の表です。3 つの配列は同じ番号で 1 つの枠を表します。
#[derive(Debug)]
pub(crate) struct ConnSlots {
    hot: FixedVec<Tcb>,
    cold: FixedVec<ConnCold>,
    bufs: FixedVec<ConnBufs>,
}

/// 空きの枠の list を作ります。小さい番号から使います。
pub(crate) fn new_free_list(n: usize) -> Result<FixedVec<u32>, AllocError> {
    let last = u32::try_from(n).map_err(|_| AllocError)?;
    FixedVec::try_filled(n, |i| last - 1 - u32::try_from(i).unwrap_or(0))
}

/// 枠 1 つが表に持つ byte 数です (3 つの配列と空きの list と accept の待ち行列の節)。
pub(crate) const fn slot_bytes() -> usize {
    size_of::<Tcb>()
        + size_of::<ConnCold>()
        + size_of::<ConnBufs>()
        + size_of::<u32>()
        + size_of::<QLink>()
}

impl ConnSlots {
    pub(crate) fn new(n: usize) -> Result<Self, AllocError> {
        Ok(Self {
            hot: FixedVec::try_filled(n, |_| Tcb::default())?,
            cold: FixedVec::try_filled(n, |_| ConnCold::default())?,
            bufs: FixedVec::try_filled(n, |_| ConnBufs::new())?,
        })
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.hot.heap_bytes() + self.cold.heap_bytes() + self.bufs.heap_bytes()
    }

    pub(crate) fn len(&self) -> usize {
        self.hot.len()
    }

    /// 枠 `i` の segment ごとの欄です。
    pub(crate) fn tcb(&self, i: u32) -> &Tcb {
        &self.hot[i as usize]
    }

    pub(crate) fn tcb_mut(&mut self, i: u32) -> &mut Tcb {
        &mut self.hot[i as usize]
    }

    pub(crate) fn bufs(&self, i: u32) -> &ConnBufs {
        &self.bufs[i as usize]
    }

    pub(crate) fn bufs_mut(&mut self, i: u32) -> &mut ConnBufs {
        &mut self.bufs[i as usize]
    }

    /// 枠 `i` の 3 つの部分です。
    pub(crate) fn parts_mut(&mut self, i: u32) -> (&mut Tcb, &mut ConnCold, &mut ConnBufs) {
        let i = i as usize;
        (&mut self.hot[i], &mut self.cold[i], &mut self.bufs[i])
    }

    /// 空きの枠を 1 つ取り、使う枠にします。floor の配列をまだ持たない枠では確保します。確保に失敗したら
    /// 枠を空きに戻して誤りを返します。欄は呼び手が確立の時に決めます。
    pub(crate) fn alloc(&mut self, free: &mut FixedVec<u32>) -> Result<Option<u32>, AllocError> {
        let Some(i) = free.pop() else {
            return Ok(None);
        };
        let s = &mut self.bufs[i as usize];
        if s.recs.capacity() == 0 && s.spare_recs.capacity() == 0 {
            let (Ok(recs), Ok(iv)) = (
                FixedVec::try_filled(FLOOR_RECORDS, |_| Record::default()),
                FixedVec::try_filled(FLOOR_INTERVALS, |_| Interval::default()),
            ) else {
                let _ = free.try_push(i);
                return Err(AllocError);
            };
            s.recs = RecordRing::new(recs);
            if let Err(e) = s.rcv.set_intervals(iv) {
                debug_assert!(e.is_empty(), "an unused slot holds no intervals");
            }
        }
        self.hot[i as usize].state = State::Established;
        Ok(Some(i))
    }

    /// 使っている枠を空きの list に返します。世代を進め、欄を 0 に戻し、輪の chunk を置き場に返します。
    /// floor の配列は持ち続けます。呼び手は先に表と待ち行列と boost の枠から外します。
    pub(crate) fn release(&mut self, i: u32, free: &mut FixedVec<u32>, pool: &mut ChunkPool) {
        let t = &mut self.hot[i as usize];
        if t.state == State::Free {
            return;
        }
        debug_assert!(!t.in_index && self.bufs[i as usize].boost.is_none());
        *t = Tcb {
            generation: t.generation + 1,
            ..Tcb::default()
        };
        self.cold[i as usize] = ConnCold::default();
        self.bufs[i as usize].reset_to_floor(pool);
        let pushed = free.try_push(i);
        debug_assert!(pushed.is_ok(), "the free list holds every slot");
    }

    /// 今の世代の handle です。
    pub(crate) fn id(&self, i: u32) -> ConnId {
        ConnId {
            slot: i,
            generation: self.hot[i as usize].generation,
        }
    }

    /// handle が今使っている枠を指していれば、その番号を返します。
    pub(crate) fn resolve(&self, id: ConnId) -> Option<u32> {
        let s = self.hot.get(id.slot as usize)?;
        (s.state != State::Free && s.generation == id.generation).then_some(id.slot)
    }

    /// 使っている枠の番号です。
    pub(crate) fn in_use(&self) -> impl Iterator<Item = u32> + '_ {
        self.hot
            .iter()
            .enumerate()
            .filter(|(_, t)| t.state != State::Free)
            .filter_map(|(i, _)| u32::try_from(i).ok())
    }

    /// すべての枠の番号と欄と輪です。
    pub(crate) fn iter_bufs(&self) -> impl Iterator<Item = (u32, &Tcb, &ConnBufs)> {
        self.hot
            .iter()
            .zip(self.bufs.iter())
            .enumerate()
            .filter_map(|(i, (t, b))| Some((u32::try_from(i).ok()?, t, b)))
    }

    /// 枠をすべて返し、floor の配列も解放します。核を閉じる時に呼びます。
    pub(crate) fn free_all(&mut self, pool: &mut ChunkPool) {
        for (t, b) in self.hot.iter_mut().zip(self.bufs.iter_mut()) {
            b.snd.release(pool);
            b.rcv.r.release(pool);
            b.rcv.take_intervals().free();
            b.recs.take().free();
            b.spare_recs.free();
            b.spare_iv.free();
            t.state = State::Free;
            t.in_index = false;
        }
    }

    /// 空きの list `free` と使っている印が一致し、輪と段が合うことを確かめます。
    pub(crate) fn check(&self, free: &[u32], links: &[QLink]) -> Result<(), &'static str> {
        // 印は 1 枠 1 bit で、検査の間だけ確保します (wgstack-rs.md の「不変条件の検査の手間」)。
        let mut seen = crate::output::BitSet::new(self.hot.len())
            .map_err(|_| "allocation failed while checking")?;
        for &i in free {
            let t = self
                .hot
                .get(i as usize)
                .ok_or("a free slot number is out of range")?;
            if seen.get(i) {
                return Err("a slot is twice in the free list");
            }
            seen.set(i);
            let b = &self.bufs[i as usize];
            if t.state != State::Free
                || t.in_index
                || links.get(i as usize).is_some_and(|l| l.queued)
                || b.boost.is_some()
            {
                return Err("a free slot is still in use");
            }
            if b.held_chunks() != 0 {
                return Err("a free slot holds chunks");
            }
        }
        let used = self.hot.iter().filter(|t| t.state != State::Free).count();
        if free.len() + used != self.hot.len() {
            return Err("the free slots and the used slots do not add up");
        }
        for (_, t, b) in self.iter_bufs() {
            b.snd.check()?;
            b.rcv.r.check()?;
            b.rcv.check()?;
            check_stage(t, b)?;
        }
        Ok(())
    }
}

/// 枠の段と配列が合うことを確かめます。boost の無い枠は floor の容量と floor の長さの配列を持ちます。boost の
/// 枠は送信が boost の段で、使っていない floor の記録の輪を控えに持ちます。受信は floor か boost の段で、使って
/// いない方の区間の表を控えに持ちます。使っていない枠は floor の配列を持つか、まだ何も持ちません。
fn check_stage(t: &Tcb, s: &ConnBufs) -> Result<(), &'static str> {
    let in_use = t.state != State::Free;
    let ivs = s.rcv.intervals_capacity();
    if !in_use || s.boost.is_none() {
        let arrays = (s.recs.capacity(), ivs);
        let fresh = !in_use && arrays == (0, 0);
        if s.snd.cap() != SEND_FLOOR
            || s.rcv.r.cap() != RECV_FLOOR
            || !(fresh || arrays == (FLOOR_RECORDS, FLOOR_INTERVALS))
            || s.spare_recs.capacity() != 0
            || s.spare_iv.capacity() != 0
        {
            return Err("a slot without boost is not at the floor stage");
        }
        return Ok(());
    }
    let recv_ok = match (ivs, s.spare_iv.len()) {
        (FLOOR_INTERVALS, BOOST_INTERVALS) => s.rcv.r.cap() == RECV_FLOOR,
        (BOOST_INTERVALS, FLOOR_INTERVALS) => s.rcv.r.cap() == BOOST_SIZE,
        _ => false,
    };
    if s.snd.cap() != BOOST_SIZE
        || s.recs.capacity() != BOOST_RECORDS
        || s.spare_recs.len() != FLOOR_RECORDS
        || !recv_ok
    {
        return Err("a boosted slot's stage disagrees with its arrays");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_used_lowest_first_and_returned_first() {
        let mut p = ChunkPool::new().unwrap();
        let mut t = ConnSlots::new(4).unwrap();
        let mut free = new_free_list(4).unwrap();
        assert_eq!(t.alloc(&mut free).unwrap(), Some(0));
        assert_eq!(t.alloc(&mut free).unwrap(), Some(1));
        let old = t.id(0);
        t.release(0, &mut free, &mut p);
        assert_eq!(
            t.resolve(old),
            None,
            "a released slot invalidates its handle"
        );
        assert_eq!(
            t.alloc(&mut free).unwrap(),
            Some(0),
            "a returned slot is used first"
        );
        assert_eq!(t.id(0).generation, old.generation + 1);
        assert_eq!(t.alloc(&mut free).unwrap(), Some(2));
        assert_eq!(t.alloc(&mut free).unwrap(), Some(3));
        assert_eq!(t.alloc(&mut free).unwrap(), None);
        assert_eq!(t.in_use().count(), 4);
        t.check(&free, &[]).unwrap();
    }

    #[test]
    fn check_catches_broken_free_lists_and_stages() {
        let mut p = ChunkPool::new().unwrap();
        let mut t = ConnSlots::new(3).unwrap();
        let mut free = new_free_list(3).unwrap();
        t.check(&free, &[]).unwrap();
        let i = t.alloc(&mut free).unwrap().unwrap();
        t.check(&free, &[]).unwrap();
        // 同じ枠を 2 度 free list に入れる。
        let _ = free.try_push(1);
        assert_eq!(t.check(&free, &[]), Err("a slot is twice in the free list"));
        free.pop();
        free[0] = 99;
        assert_eq!(
            t.check(&free, &[]),
            Err("a free slot number is out of range")
        );
        free[0] = 2;
        t.check(&free, &[]).unwrap();
        // 使っている枠が floor でない段を持つ。
        t.bufs_mut(i).snd = Ring::new(BOOST_SIZE);
        assert_eq!(
            t.check(&free, &[]),
            Err("a slot without boost is not at the floor stage")
        );
        t.bufs_mut(i).boost = Some(0);
        assert_eq!(
            t.check(&free, &[]),
            Err("a boosted slot's stage disagrees with its arrays")
        );
        t.bufs_mut(i).boost = None;
        t.bufs_mut(i).snd = Ring::new(SEND_FLOOR);
        t.check(&free, &[]).unwrap();
        // 数が合わない:使っている印だけを消す。
        t.tcb_mut(i).state = State::Free;
        assert_eq!(
            t.check(&free, &[]),
            Err("the free slots and the used slots do not add up")
        );
        t.tcb_mut(i).state = State::Established;
        t.release(i, &mut free, &mut p);
        t.check(&free, &[]).unwrap();
    }

    #[test]
    fn floor_arrays_stay_with_the_slot() {
        let mut p = ChunkPool::new().unwrap();
        let mut t = ConnSlots::new(1).unwrap();
        let mut free = new_free_list(1).unwrap();
        assert_eq!(
            t.bufs(0).array_bytes(),
            (0, 0),
            "arrays are allocated on first use"
        );
        t.alloc(&mut free).unwrap();
        let bytes = t.bufs(0).array_bytes();
        assert_eq!(
            bytes,
            (
                FLOOR_RECORDS * size_of::<Record>(),
                FLOOR_INTERVALS * size_of::<Interval>()
            )
        );
        t.bufs_mut(0).snd.write(0, &[1; 100], &mut p).unwrap();
        t.release(0, &mut free, &mut p);
        assert_eq!(t.bufs(0).array_bytes(), bytes);
        assert_eq!((t.bufs(0).held_chunks(), p.held()), (0, 0));
        t.free_all(&mut p);
        assert_eq!(t.bufs(0).array_bytes(), (0, 0));
        assert!(!free.is_empty() && t.len() == 1);
        assert!(t.heap_bytes() >= size_of::<Tcb>() + size_of::<ConnBufs>());
    }

    /// 枠どうしは segment ごとの欄のキャッシュの行を分け合いません。
    #[test]
    fn tcb_is_cache_line_aligned() {
        assert_eq!(align_of::<Tcb>(), 64);
        assert_eq!(size_of::<Tcb>() % 64, 0);
    }
}
