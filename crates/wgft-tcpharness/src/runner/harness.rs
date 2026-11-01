//! 台本の 1 回の実行の文脈です。Go の harness (`harness.go`) の `H` と `Peer` のうち、手で進める時計の DUT で
//! 使う部分を写します。DUT への呼び出しは Go の harness と同じ順で、同じ数だけ行います。

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::time::Duration;

use crate::dut::{ClockedDut, DutError};
use crate::frame::Handle;
use crate::packet::{self, ACK, FIN, Options, PSH, SYN, Segment, Timestamps};
use crate::rng::ScriptRng;

use super::gofmt;
use super::value::{ListenerV, UdpConnV};
use super::{CheckRecord, KnownList};

/// 台本を止める理由です。失敗の文はすでに記録してあります。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// Go の `FailNow` と `Fatalf`
    Fail,
    /// Go の `SkipNow`。期待した差で `require` が落ちた時
    Skip,
}

pub(crate) type R<T> = Result<T, Stop>;

/// 1 ms です。Go の `clockStep` で、待つ文が出力の間に時計を進める量です。
pub(crate) const MS: i64 = 1_000_000;
pub(crate) const SECOND: i64 = 1_000 * MS;

/// 台本の終わりに逆の順で動かす後始末です。Go の `T.Cleanup` です。
#[derive(Debug)]
pub(crate) enum Cleanup {
    CloseListener(Rc<RefCell<ListenerV>>),
    AbortConn(Handle),
    CloseUdp(Rc<RefCell<UdpConnV>>),
}

/// 試験台の 1 つの接続の端です。sequence の番号は絶対の値です。Go の `Peer` です。
#[derive(Debug, Clone)]
pub(crate) struct Peer {
    pub(crate) local: SocketAddrV4,
    pub(crate) remote: SocketAddrV4,
    pub(crate) iss: u32,
    pub(crate) snd_nxt: u32,
    pub(crate) dut_iss: u32,
    pub(crate) rcv_nxt: u32,
    pub(crate) ws: i64,
    pub(crate) window: u16,
    pub(crate) dut_ws: i64,
    pub(crate) sack: bool,
    pub(crate) ts: bool,
    pub(crate) ts_start: i64,
    pub(crate) ts_base: u32,
    pub(crate) ts_recent: u32,
    pub(crate) syn_ts_val: u32,
    pub(crate) ack_held: i64,
    pub(crate) dut_ack: u32,
    pub(crate) dut_window: i64,
    pub(crate) last_ts: u32,
}

impl Peer {
    /// 接続の値を、相手の送った SYN の option と SYN-ACK から取ります。Go の `adopt` です。
    pub(crate) fn adopt(&mut self, syn: &Options, synack: &Segment) {
        self.snd_nxt = self.iss.wrapping_add(1);
        self.dut_iss = synack.seq;
        self.rcv_nxt = synack.seq.wrapping_add(1);
        self.dut_ws = synack.opts.ws;
        self.sack = syn.sack_permitted && synack.opts.sack_permitted;
        self.ts = syn.ts.is_some() && synack.opts.ts.is_some();
        if self.ws < 0 || self.dut_ws < 0 {
            self.ws = -1;
            self.dut_ws = -1;
        }
        if self.ts {
            self.ts_recent = synack.opts.ts.map_or(0, |t| t.val);
        }
    }
}

/// i64 を Go の `uint32(...)` と同じく下位 32 bit に切ります。
pub(crate) fn trunc32(v: i64) -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Go's uint32 conversion"
    )]
    let r = v as u32;
    r
}

/// Go の `uint16(...)` です。
pub(crate) fn trunc16(v: i64) -> u16 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Go's uint16 conversion"
    )]
    let r = v as u16;
    r
}

/// Go の `byte(...)` です。
pub(crate) fn trunc8(v: i64) -> u8 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Go's byte conversion"
    )]
    let r = v as u8;
    r
}

pub(crate) fn len64(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn nanos(d: Duration) -> i64 {
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}

/// 1 回の実行の文脈です。
pub(crate) struct H<'a> {
    dut: &'a mut dyn ClockedDut,
    pub(crate) engine: String,
    pub(crate) scenario: String,
    known: &'a KnownList,
    pub(crate) dut_addr: Ipv4Addr,
    pub(crate) mtu: usize,
    rng: ScriptRng,
    pub(crate) outcome: BTreeMap<String, Vec<&'static str>>,
    pub(crate) checks: Vec<CheckRecord>,
    pub(crate) lines: Vec<String>,
    pub(crate) failures: Vec<String>,
    pub(crate) failed: bool,
    pub(crate) skipped: bool,
    last_now: i64,
    pub(crate) cleanups: Vec<Cleanup>,
}

impl<'a> H<'a> {
    pub(crate) fn new(
        dut: &'a mut dyn ClockedDut,
        engine: &str,
        scenario: &str,
        known: &'a KnownList,
        dut_addr: Ipv4Addr,
        mtu: usize,
        seed: u64,
    ) -> Self {
        Self {
            dut,
            engine: engine.to_owned(),
            scenario: scenario.to_owned(),
            known,
            dut_addr,
            mtu,
            rng: ScriptRng::new(seed),
            outcome: BTreeMap::new(),
            checks: Vec::new(),
            lines: Vec::new(),
            failures: Vec::new(),
            failed: false,
            skipped: false,
            last_now: 0,
            cleanups: Vec::new(),
        }
    }

    pub(crate) fn dut(&mut self) -> &mut dyn ClockedDut {
        self.dut
    }

    /// log の行です。Go の recorder と同じく、最後に知った DUT の時刻を頭に付けます。
    pub(crate) fn logf(&mut self, line: impl AsRef<str>) {
        self.lines.push(format!(
            "{} {}",
            gofmt::duration(self.last_now),
            line.as_ref()
        ));
    }

    /// 失敗を記録して続けます。Go の recorder の `Errorf` です。
    pub(crate) fn errorf(&mut self, msg: String) {
        self.logf(format!("recorded: {msg}"));
        self.failures.push(msg);
        self.failed = true;
    }

    /// 失敗を記録して止めます。Go の `Fatalf` です。
    pub(crate) fn fatalf(&mut self, msg: String) -> Stop {
        self.errorf(msg);
        Stop::Fail
    }

    /// DUT が壊れた誤りで止めます。
    pub(crate) fn broken(&mut self, e: &DutError) -> Stop {
        self.fatalf(format!("rustdut: {e}"))
    }

    /// 台本の時計です。Go の `H.Now` です。
    pub(crate) fn now(&mut self) -> R<i64> {
        match self.dut.now() {
            Ok(t) => {
                self.last_now = nanos(t);
                Ok(self.last_now)
            }
            Err(e) => Err(self.broken(&e)),
        }
    }

    pub(crate) fn advance(&mut self, d: i64) -> R<()> {
        let d = Duration::from_nanos(u64::try_from(d).unwrap_or(0));
        match self.dut.advance(d) {
            Ok(t) => {
                self.last_now = nanos(t);
                Ok(())
            }
            Err(e) => Err(self.broken(&e)),
        }
    }

    /// 1 つの packet を渡します。
    pub(crate) fn inject(&mut self, pkt: &[u8]) -> Result<(), DutError> {
        self.dut.inject(&[pkt])
    }

    /// 手で進める時計の `ClockedDUT.Poll` です。1 つずつ引き取ります。
    pub(crate) fn poll(&mut self) -> R<Option<Vec<u8>>> {
        match self.dut.poll(1) {
            Ok(mut ps) => Ok(if ps.is_empty() {
                None
            } else {
                Some(ps.swap_remove(0))
            }),
            Err(DutError::Engine(_)) => Ok(None),
            Err(e) => Err(self.broken(&e)),
        }
    }

    /// DUT の次の packet を台本の時計で `d` の内に返します。Go の `H.next` です。
    pub(crate) fn next(&mut self, d: i64) -> R<Option<Vec<u8>>> {
        let deadline = self.now()?.saturating_add(d);
        loop {
            if let Some(p) = self.poll()? {
                return Ok(Some(p));
            }
            if self.now()? >= deadline {
                return Ok(None);
            }
            self.advance(MS)?;
        }
    }

    /// 1 つの確かめを期待した差の一覧と照らします。Go の `H.Check` です。
    pub(crate) fn check(&mut self, id: &str, ok: bool, what: &str, got: &str) -> bool {
        let key = format!("{}/{id}", self.scenario);
        let engine = self.engine.clone();
        let known = self.known.get(&key).cloned();
        let outcome = match (ok, known) {
            (true, None) => {
                self.logf(format!("PASS  {key}: {what}; got: {got}"));
                super::OUTCOME_PASS
            }
            (true, Some(k)) => {
                self.errorf(format!(
                    "UNEXPECTED PASS  {key} on {engine}: {what}; got: {got}; the list says: {}; remove the entry",
                    k.observed
                ));
                super::OUTCOME_UNEXPECTED
            }
            (false, Some(k)) if k.sometimes => {
                self.errorf(format!(
                    "CHANGED DIFFERENCE  {key} on {engine}: {what}; got: {got}; the list marks it as shown only on some runs, which a DUT on the harness's clock cannot be"
                ));
                super::OUTCOME_CHANGED
            }
            (false, Some(k)) if got == k.observed => {
                self.logf(format!(
                    "KNOWN DIFFERENCE  {key} on {engine}: {what}; got: {got}; reason: {}",
                    k.reason
                ));
                super::OUTCOME_KNOWN
            }
            (false, Some(k)) => {
                self.errorf(format!(
                    "CHANGED DIFFERENCE  {key} on {engine}: {what}; got: {got}; the list says: {}",
                    k.observed
                ));
                super::OUTCOME_CHANGED
            }
            (false, None) => {
                self.errorf(format!("FAIL  {key} on {engine}: {what}; got: {got}"));
                super::OUTCOME_FAIL
            }
        };
        self.outcome.entry(key.clone()).or_default().push(outcome);
        self.checks.push(CheckRecord {
            key,
            outcome: outcome.to_owned(),
            got: got.to_owned(),
        });
        ok
    }

    /// `check` で、落ちた時に台本を止めます。期待した差なら skip、ほかは失敗です。
    pub(crate) fn require(&mut self, id: &str, ok: bool, what: &str, got: &str) -> R<()> {
        if self.check(id, ok, what, got) {
            return Ok(());
        }
        let key = format!("{}/{id}", self.scenario);
        if self.outcome.get(&key).and_then(|o| o.last()) == Some(&super::OUTCOME_KNOWN) {
            self.skipped = true;
            return Err(Stop::Skip);
        }
        self.failed = true;
        Err(Stop::Fail)
    }

    /// 比べるための値を出します。何も確かめません。
    pub(crate) fn measure(&mut self, name: &str, v: &str) {
        let key = format!("{}/{name}", self.scenario);
        self.checks.push(CheckRecord {
            key,
            outcome: "measure".to_owned(),
            got: v.to_owned(),
        });
        let line = format!(
            "MEASURE engine={} {}/{name}={v}",
            self.engine, self.scenario
        );
        self.logf(line);
    }

    /// DUT の `port` への試験台の端を、台本の種からの新しいポートと ISS で作ります。Go の `NewPeer` です。
    pub(crate) fn new_peer(&mut self, port: u16) -> R<Peer> {
        let draw = self.rng.new_peer();
        let ts_start = self.now()?;
        Ok(Peer {
            local: SocketAddrV4::new(super::PEER_ADDR, draw.port),
            remote: SocketAddrV4::new(self.dut_addr, port),
            iss: draw.iss,
            snd_nxt: 0,
            dut_iss: 0,
            rcv_nxt: 0,
            ws: -1,
            window: 65535,
            dut_ws: -1,
            sack: false,
            ts: false,
            ts_start,
            ts_base: draw.ts_base,
            ts_recent: 0,
            syn_ts_val: 0,
            ack_held: 0,
            dut_ack: 0,
            dut_window: 0,
            last_ts: 0,
        })
    }

    /// `p` と同じ 4 つ組の新しい相手です。Go の `Reincarnate` です。
    pub(crate) fn reincarnate(&mut self, p: &Peer, iss: u32) -> R<Peer> {
        let ts_start = self.now()?;
        let ts_base = self.ts_val(p)?.wrapping_add(1000);
        Ok(Peer {
            local: p.local,
            remote: p.remote,
            iss,
            snd_nxt: 0,
            dut_iss: 0,
            rcv_nxt: 0,
            ws: -1,
            window: 65535,
            dut_ws: -1,
            sack: false,
            ts: false,
            ts_start,
            ts_base,
            ts_recent: 0,
            syn_ts_val: 0,
            ack_held: 0,
            dut_ack: 0,
            dut_window: 0,
            last_ts: 0,
        })
    }

    /// 試験台の timestamp の時計です。1 ms で 1 進みます。
    pub(crate) fn ts_val(&mut self, p: &Peer) -> R<u32> {
        let now = self.now()?;
        Ok(p.ts_base
            .wrapping_add(trunc32(now.saturating_sub(p.ts_start) / MS)))
    }

    /// この流れの segment を作ります。timestamps を合意していれば付けます。Go の `Peer.Segment` です。
    pub(crate) fn segment(
        &mut self,
        p: &Peer,
        flags: u8,
        seq: u32,
        payload: Vec<u8>,
    ) -> R<Segment> {
        let mut o = Options::none();
        if p.ts {
            o.ts = Some(Timestamps {
                val: self.ts_val(p)?,
                ecr: p.ts_recent,
            });
        }
        Ok(Segment {
            src: p.local,
            dst: p.remote,
            seq,
            ack: p.rcv_nxt,
            flags,
            window: p.window,
            opts: o,
            payload,
            ..Segment::default()
        })
    }

    /// `s` を DUT に渡します。Go の `Peer.Send` です。
    pub(crate) fn send(&mut self, p: &mut Peer, s: &Segment) -> R<()> {
        if let Some(ts) = s.opts.ts {
            p.last_ts = ts.val;
        }
        self.logf(format!("-> {s}"));
        if let Err(e) = self.inject(&s.marshal()) {
            return Err(self.fatalf(format!("inject {s}: {e}")));
        }
        Ok(())
    }

    pub(crate) fn send_data(&mut self, p: &mut Peer, payload: Vec<u8>) -> R<()> {
        let n = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let s = self.segment(p, ACK | PSH, p.snd_nxt, payload)?;
        self.send(p, &s)?;
        p.snd_nxt = p.snd_nxt.wrapping_add(n);
        Ok(())
    }

    pub(crate) fn send_ack(&mut self, p: &mut Peer) -> R<()> {
        let s = self.segment(p, ACK, p.snd_nxt, Vec::new())?;
        self.send(p, &s)
    }

    pub(crate) fn send_fin(&mut self, p: &mut Peer, payload: Vec<u8>) -> R<()> {
        let n = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let s = self.segment(p, FIN | ACK | PSH, p.snd_nxt, payload)?;
        self.send(p, &s)?;
        p.snd_nxt = p.snd_nxt.wrapping_add(n).wrapping_add(1);
        Ok(())
    }

    /// 前に送ったどの TSval より大きい TSval の ACK を送り、その TSval を返します。Go の `SendFreshAck` です。
    pub(crate) fn send_fresh_ack(&mut self, p: &mut Peer) -> R<u32> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Go's int32 of a sequence difference"
        )]
        while p.ts && (self.ts_val(p)?.wrapping_sub(p.last_ts) as i32) <= 0 {
            self.advance(MS)?;
        }
        self.send_ack(p)?;
        Ok(p.last_ts)
    }

    /// この流れの次の segment を `d` の内に返します。待ちの log の行を書きません。Go の `Peer.next` です。
    pub(crate) fn peer_next(&mut self, p: &mut Peer, d: i64) -> R<Option<Segment>> {
        let deadline = self.now()?.saturating_add(d);
        loop {
            let wait = deadline.saturating_sub(self.now()?).max(0);
            let Some(pkt) = self.next(wait)? else {
                return Ok(None);
            };
            if pkt.len() > self.mtu {
                let msg = format!(
                    "FAIL  emitted packet on {}: at most the MTU of {} bytes; got: {} bytes",
                    self.engine,
                    self.mtu,
                    pkt.len()
                );
                self.errorf(msg);
            }
            let s = match packet::parse(&pkt) {
                Ok(s) => s,
                Err(e) => {
                    self.logf(format!(
                        "emitted packet ignored: {e}: {}",
                        gofmt::hex_spaced(&pkt[..pkt.len().min(40)])
                    ));
                    continue;
                }
            };
            if s.src != p.remote || s.dst != p.local {
                self.logf(format!("segment of another flow ignored: {s}"));
                continue;
            }
            if let Some(ts) = s.opts.ts {
                p.ts_recent = ts.val;
            }
            if s.has(ACK) {
                p.dut_ack = s.ack;
                p.dut_window = i64::from(s.window);
                if p.dut_ws >= 0 && !s.has(SYN) {
                    p.dut_window <<= p.dut_ws;
                }
            }
            self.logf(format!("<- {s}"));
            return Ok(Some(s));
        }
    }

    /// `Peer.Next` です。
    pub(crate) fn peer_next_logged(&mut self, p: &mut Peer, d: i64) -> R<Option<Segment>> {
        self.logf(format!("wait up to {} for a segment", gofmt::duration(d)));
        self.peer_next(p, d)
    }

    /// この流れで DUT が `d` の間何も送らないかどうかです。Go の `Peer.Quiet` です。
    pub(crate) fn quiet(&mut self, p: &mut Peer, d: i64) -> R<Option<Segment>> {
        self.logf(format!("expect quiet for {}", gofmt::duration(d)));
        self.peer_next(p, d)
    }

    /// DUT が `d` の内に送るすべての流れの TCP の segment です。Go の `H.Collect` です。
    pub(crate) fn collect(&mut self, d: i64) -> R<Vec<Segment>> {
        let mut out = Vec::new();
        let deadline = self.now()?.saturating_add(d);
        loop {
            let wait = deadline.saturating_sub(self.now()?).max(0);
            let Some(pkt) = self.next(wait)? else {
                return Ok(out);
            };
            if let Ok(s) = packet::parse(&pkt) {
                self.logf(format!("<- {s}"));
                out.push(s);
            }
        }
    }
}
