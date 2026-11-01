//! 台本の解釈器です。Go の runner (`script_run.go`、`script_lib.go`、`script_net.go`) の写しで、文ごとに
#![expect(
    clippy::many_single_char_names,
    reason = "the names follow the Go runner, so the two read side by side"
)]
//! Go の runner と同じ順で DUT を呼びます。手で進める時計の DUT だけを扱います。

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

use crate::dut::{DutError, Op};
use crate::frame::Handle;
use crate::ip::{self, Icmp, Ipv4, Reassembler};
use crate::packet::{self, ACK, FIN, Options, PSH, RST, SYN, SackBlock, Segment, Timestamps};
use crate::script::{Expr, Script, Stmt, TmplPart};

use super::gofmt;
use super::harness::{Cleanup, H, MS, Peer, R, SECOND, len64, trunc8, trunc16, trunc32};
use super::value::{GoErr, IpV, ListenerV, PeerV, SegV, UdpConnV, V, ZERO_TIME};
use super::{MTU, PEER_ADDR};

/// rustdut が 1 回の `READ` と `WRITE` で扱う上限です。
const MAX_READ: usize = 1 << 20;

/// 台本の述語です。文を始めた時の名前の値で評価します。
struct Pred {
    expr: Expr,
    frozen: Rc<HashMap<String, V>>,
}

pub(crate) struct Interp<'h, 'a> {
    pub(crate) h: &'h mut H<'a>,
    file: String,
    vars: Rc<HashMap<String, V>>,
    line: usize,
}

fn is_data(s: &Segment) -> bool {
    !s.payload.is_empty()
}

fn is_pure_ack(s: &Segment) -> bool {
    s.flags & (SYN | FIN | RST) == 0 && s.has(ACK) && s.payload.is_empty()
}

fn seg_desc(s: &Segment, ok: bool) -> String {
    if ok {
        format!("{} len={}", packet::flag_string(s.flags), s.payload.len())
    } else {
        "no segment".to_owned()
    }
}

#[expect(
    clippy::cast_possible_wrap,
    reason = "Go's int32 of a sequence difference"
)]
fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

fn ack_desc(s: &Segment, ok: bool, base: u32) -> String {
    if ok {
        format!("ACK of base+{}", seq_diff(s.ack, base))
    } else {
        "no ACK in time".to_owned()
    }
}

fn sack_desc(s: &Segment, ok: bool, base: u32) -> String {
    if !ok {
        return "no ACK in time".to_owned();
    }
    let parts: Vec<String> = s
        .opts
        .sack
        .iter()
        .map(|b| {
            format!(
                "[base+{},base+{})",
                seq_diff(b.left, base),
                seq_diff(b.right, base)
            )
        })
        .collect();
    if parts.is_empty() {
        "no SACK block".to_owned()
    } else {
        parts.join(" ")
    }
}

fn synack_string(p: &Peer, s: &Segment, ok: bool) -> String {
    if !ok {
        "no SYN-ACK".to_owned()
    } else if s.ack != p.iss.wrapping_add(1) {
        "a SYN-ACK acknowledging another number".to_owned()
    } else {
        "a SYN-ACK acknowledging ISS+1".to_owned()
    }
}

fn err_kind(e: Option<&GoErr>) -> &'static str {
    e.map_or("nil", GoErr::err_kind)
}

fn err_string(e: Option<&GoErr>) -> String {
    e.map_or_else(|| "nil".to_owned(), GoErr::err_string)
}

fn yes_no<'s>(ok: bool, yes: &'s str, no: &'s str) -> &'s str {
    if ok { yes } else { no }
}

/// Go の `pattern` です。
pub(crate) fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            #[expect(clippy::cast_possible_truncation, reason = "Go's byte(i*7)")]
            let b = i.wrapping_mul(7) as u8;
            b ^ salt
        })
        .collect()
}

fn standard_syn() -> Options {
    Options {
        mss: Some(u16::try_from(MTU - 40).expect("small MTU")),
        ws: 7,
        sack_permitted: true,
        ts: Some(Timestamps { val: 0, ecr: 0 }),
        sack: Vec::new(),
    }
}

/// Go の zero の `Options` です。WS は 0 で、window scale の option を持ちます。
fn zero_options() -> Options {
    Options {
        ws: 0,
        ..Options::none()
    }
}

fn seg_size(p: &Peer) -> i64 {
    let mut n = len64(MTU) - 40;
    if p.ts {
        n -= 12;
    }
    n
}

fn after(a: u32, b: u32) -> bool {
    seq_diff(a, b) > 0
}

fn to_peer(p: &Ipv4) -> bool {
    p.src == super::DUT_ADDR && p.dst == PEER_ADDR
}

/// Go の `net.OpError` の文です。
fn op_error(op: &str, net: &str, src: SocketAddrV4, addr: &str, err: &str) -> String {
    format!("{op} {net} {src}->{addr}: {err}")
}

impl<'h, 'a> Interp<'h, 'a> {
    pub(crate) fn new(h: &'h mut H<'a>, file: &str) -> Self {
        Self {
            h,
            file: file.to_owned(),
            vars: Rc::new(HashMap::new()),
            line: 0,
        }
    }

    pub(crate) fn run(&mut self, s: &Script) -> R<()> {
        self.block(&s.body).map(|_| ())
    }

    /// 台本の誤りで止めます。Go の `failf` と、`runScript` の `script <file>:<line>: ` の頭です。
    fn failf<T>(&mut self, msg: impl AsRef<str>) -> R<T> {
        let m = format!("script {}:{}: {}", self.file, self.line, msg.as_ref());
        Err(self.h.fatalf(m))
    }

    fn set_var(&mut self, k: &str, v: V) {
        Rc::make_mut(&mut self.vars).insert(k.to_owned(), v);
    }

    fn block(&mut self, body: &[Stmt]) -> R<bool> {
        for st in body {
            self.line = st.line;
            if !self.stmt(st)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn arg(&mut self, st: &Stmt, i: usize) -> R<V> {
        let Some(e) = st.args.get(i) else {
            return self.failf(format!("{} needs at least {} arguments", st.verb, i + 1));
        };
        self.eval(e, None)
    }

    fn named(&mut self, st: &Stmt, k: &str) -> R<Option<V>> {
        match st.named.get(k) {
            Some(e) => self.eval(e, None).map(Some),
            None => Ok(None),
        }
    }

    fn bind(&mut self, st: &Stmt, v: V) {
        if let Some(b) = &st.bind {
            self.set_var(b, v);
        }
    }

    fn first_name(st: &Stmt) -> String {
        match st.args.first() {
            Some(Expr::Name(n)) => n.clone(),
            _ => String::new(),
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per statement, as the Go runner's switch"
    )]
    fn stmt(&mut self, st: &Stmt) -> R<bool> {
        match st.verb.as_str() {
            "stop" => return Ok(false),
            "if" => {
                let c = self.arg(st, 0)?;
                let c = self.truth(&c)?;
                return if c {
                    self.block(&st.then)
                } else {
                    self.block(&st.els)
                };
            }
            "let" => {
                let v = self.arg(st, 0)?;
                let b = st.bind.clone().unwrap_or_default();
                self.set_var(&b, v);
            }
            "set" => {
                let b = st.bind.clone().unwrap_or_default();
                let (obj, field) = b.split_once('.').unwrap_or((&b, ""));
                let target = self.vars.get(obj).cloned().unwrap_or(V::None);
                let V::Peer(pv) = target else {
                    return self.failf(format!(
                        "set works on a peer's fields; {obj} is {}",
                        target.type_name()
                    ));
                };
                let v = self.arg(st, 0)?;
                self.set_peer(&pv, field, &v)?;
            }
            "listen" => {
                let v = self.arg(st, 1)?;
                let port = self.port(&v)?;
                let r = self.h.dut().tcp_listen(port);
                let first = Self::first_name(st);
                match r {
                    Ok(l) => {
                        let lv = Rc::new(RefCell::new(ListenerV {
                            h: l,
                            closed: false,
                        }));
                        self.h.cleanups.push(Cleanup::CloseListener(lv.clone()));
                        self.set_var(&first, V::Listener(lv));
                        self.bind(st, V::None);
                    }
                    Err(DutError::Engine(e)) => {
                        let e = GoErr::from_engine(e);
                        if st.bind.is_none() {
                            return Err(self
                                .h
                                .fatalf(format!("listen on {port}: {}", e.err_string())));
                        }
                        self.set_var(&first, V::None);
                        self.bind(st, V::err(Some(e)));
                    }
                    Err(e) => return Err(self.h.broken(&e)),
                }
            }
            "connect" | "handshake" => {
                let d = self.dial(st)?;
                let pv = if st.verb == "connect" {
                    let lv = self.arg(st, 1)?;
                    let l = self.listener(&lv)?;
                    let pa = self.arg(st, 2)?;
                    let port = self.port(&pa)?;
                    let (p, sa) = self.handshake(port, &d)?;
                    let c = self.accept(&l)?;
                    let at = self.h.now()?;
                    PeerV {
                        p: RefCell::new(p),
                        synack: Some(Rc::new(SegV {
                            seg: sa,
                            ok: true,
                            at,
                        })),
                        conn: Some(c),
                    }
                } else {
                    let pa = self.arg(st, 1)?;
                    let port = self.port(&pa)?;
                    let (p, sa) = self.handshake(port, &d)?;
                    let at = self.h.now()?;
                    PeerV {
                        p: RefCell::new(p),
                        synack: Some(Rc::new(SegV {
                            seg: sa,
                            ok: true,
                            at,
                        })),
                        conn: None,
                    }
                };
                self.set_var(&Self::first_name(st), V::Peer(Rc::new(pv)));
            }
            "accept" => {
                let lv = self.arg(st, 1)?;
                let l = self.listener(&lv)?;
                let c = self.accept(&l)?;
                self.set_var(&Self::first_name(st), V::Conn(c));
            }
            "peer" => {
                let pa = self.arg(st, 1)?;
                let port = self.port(&pa)?;
                let p = self.h.new_peer(port)?;
                self.set_var(
                    &Self::first_name(st),
                    V::Peer(Rc::new(PeerV {
                        p: RefCell::new(p),
                        synack: None,
                        conn: None,
                    })),
                );
            }
            "reincarnate" => {
                let ov = self.arg(st, 1)?;
                let old = self.peer(&ov)?;
                let Some(iss) = self.named(st, "iss")? else {
                    return self.failf("reincarnate needs iss=");
                };
                let iss = self.seq(&iss)?;
                let old_p = old.p.borrow().clone();
                let mut q = self.h.reincarnate(&old_p, iss)?;
                if let Some(v) = self.named(st, "ts_base")? {
                    q.ts_base = self.seq(&v)?;
                }
                self.set_var(
                    &Self::first_name(st),
                    V::Peer(Rc::new(PeerV {
                        p: RefCell::new(q),
                        synack: None,
                        conn: None,
                    })),
                );
            }
            "adopt" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let o = self.arg(st, 1)?;
                let o = self.opts(&o)?;
                let s = self.arg(st, 2)?;
                let s = self.seg(&s)?;
                pv.p.borrow_mut().adopt(&o, &s.seg);
            }
            "send" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let s = self.arg(st, 1)?;
                let s = self.seg(&s)?;
                self.h.send(&mut pv.p.borrow_mut(), &s.seg)?;
            }
            "send_data" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let b = self.arg(st, 1)?;
                let b = self.bytes(&b)?;
                self.h.send_data(&mut pv.p.borrow_mut(), b)?;
            }
            "send_ack" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                self.h.send_ack(&mut pv.p.borrow_mut())?;
            }
            "send_fin" => {
                let b = if st.args.len() > 1 {
                    let v = self.arg(st, 1)?;
                    self.bytes(&v)?
                } else {
                    Vec::new()
                };
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                self.h.send_fin(&mut pv.p.borrow_mut(), b)?;
            }
            "send_fresh_ack" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let ts = self.h.send_fresh_ack(&mut pv.p.borrow_mut())?;
                self.bind(st, V::Seq(ts));
            }
            "await" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let d = self.arg(st, 1)?;
                let d = self.dur(&d)?;
                let got = if let Some(e) = st.named.get("match") {
                    let pred = self.predicate(e);
                    self.await_seg(&pv, d, &mut |me, s| {
                        let v = V::seg(s.clone(), true, ZERO_TIME);
                        me.pred_true(&pred, v)
                    })?
                } else {
                    self.h.peer_next_logged(&mut pv.p.borrow_mut(), d)?
                };
                let at = self.h.now()?;
                let v = Self::capture(got, at);
                self.bind(st, v);
            }
            "quiet" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let d = self.arg(st, 1)?;
                let d = self.dur(&d)?;
                let got = self.h.quiet(&mut pv.p.borrow_mut(), d)?;
                let quiet = got.is_none();
                let at = self.h.now()?;
                let seg = Self::capture(got, at);
                self.bind(
                    st,
                    V::record("quiet", vec![("quiet", V::Bool(quiet)), ("seg", seg)]),
                );
            }
            "quiet_since" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let f = self.arg(st, 3)?;
                let f = self.seg(&f)?;
                let d = self.arg(st, 1)?;
                let d = self.dur(&d)?;
                let ts = self.arg(st, 2)?;
                self.seq(&ts)?;
                let c = self.arg(st, 4)?;
                self.conn(&c)?;
                let _ = f;
                // 手で進める時計では Delivered を待たず、何も見送りません (Go の QuietSince)
                let got = {
                    let mut p = pv.p.borrow_mut();
                    self.h.logf(format!(
                        "expect quiet for {} after the ACK",
                        gofmt::duration(d)
                    ));
                    let _settle_by = self.h.now()?.saturating_add(3 * SECOND);
                    let deadline = self.h.now()?.saturating_add(d);
                    let wait = deadline.saturating_sub(self.h.now()?).max(0);
                    self.h.peer_next(&mut p, wait)?
                };
                let quiet = got.is_none();
                let desc = match &got {
                    Some(s) => seg_desc(s, true),
                    None => seg_desc(&Segment::default(), false),
                };
                let at = self.h.now()?;
                let seg = Self::capture(got, at);
                self.bind(
                    st,
                    V::record(
                        "quiet_since",
                        vec![
                            ("quiet", V::Bool(quiet)),
                            ("stale", V::Int(0)),
                            ("timed_out", V::Bool(false)),
                            ("seg", seg),
                            ("desc", V::Bytes(desc.into_bytes())),
                        ],
                    ),
                );
            }
            "collect" => {
                let d = self.arg(st, 0)?;
                let d = self.dur(&d)?;
                let segs = self.h.collect(d)?;
                let out = segs
                    .into_iter()
                    .map(|s| V::seg(s, true, ZERO_TIME))
                    .collect();
                self.bind(st, V::list(out));
            }
            "write" => {
                let c = self.arg(st, 0)?;
                let c = self.conn(&c)?;
                let b = self.arg(st, 1)?;
                let b = self.bytes(&b)?;
                let (n, err) = self.conn_write(c, &b)?;
                if st.bind.is_none()
                    && let Some(e) = &err
                {
                    return Err(self.h.fatalf(format!("write: {}", e.err_string())));
                }
                self.bind(
                    st,
                    V::record("write", vec![("n", V::Int(len64(n))), ("err", V::err(err))]),
                );
            }
            "read" => {
                let c = self.arg(st, 0)?;
                let c = self.conn(&c)?;
                let n = self.arg(st, 1)?;
                let n = self.count(&n)?;
                let d = self.arg(st, 2)?;
                let d = self.dur(&d)?;
                let (got, err) = self.read_full(c, usize::try_from(n).unwrap_or(usize::MAX), d)?;
                self.bind(
                    st,
                    V::record("read", vec![("data", V::Bytes(got)), ("err", V::err(err))]),
                );
            }
            "close" => match self.arg(st, 0)? {
                V::Listener(l) => {
                    l.borrow_mut().closed = true;
                    let h = l.borrow().h;
                    self.ignore(|d| d.close(h))?;
                }
                V::Conn(c) => self.ignore(|d| d.close(c))?,
                V::UdpConn(u) => {
                    u.borrow_mut().closed = true;
                    let h = u.borrow().h;
                    self.ignore(|d| d.close(h))?;
                }
                v => {
                    return self.failf(format!(
                        "close takes a listener, a connection or a UDP socket, not {}",
                        v.type_name()
                    ));
                }
            },
            "close_write" => {
                let c = self.arg(st, 0)?;
                let c = self.conn(&c)?;
                match self.h.dut().close_write(c) {
                    Ok(()) => {}
                    Err(DutError::Engine(e)) => {
                        let e = GoErr::from_engine(e);
                        return Err(self.h.fatalf(format!("CloseWrite: {}", e.err_string())));
                    }
                    Err(e) => return Err(self.h.broken(&e)),
                }
            }
            "abort" => {
                let c = self.arg(st, 0)?;
                let c = self.conn(&c)?;
                self.ignore(|d| d.abort(c))?;
            }
            "check" | "require" => {
                let c = self.arg(st, 0)?;
                let ok = self.truth(&c)?;
                let what = self.template(&st.what)?;
                let got = self.template(&st.got)?;
                let id = st.id.clone().unwrap_or_default();
                if st.verb == "check" {
                    self.h.check(&id, ok, &what, &got);
                } else {
                    self.h.require(&id, ok, &what, &got)?;
                }
            }
            "measure" => {
                let v = self.arg(st, 0)?;
                let s = self.measure_value(&v)?;
                let id = st.id.clone().unwrap_or_default();
                self.h.measure(&id, &s);
            }
            "log" => {
                let t = self.template(&st.what)?;
                self.h.logf(t);
            }
            "alive" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let c = self.arg(st, 1)?;
                let c = self.conn(&c)?;
                let id = st.id.clone().unwrap_or_default();
                self.alive(&id, &pv, c)?;
            }
            "delivered" => {
                let c = self.arg(st, 0)?;
                let c = self.conn(&c)?;
                let id = st.id.clone().unwrap_or_default();
                // rustdut の Delivered は問い合わせで、Go の待ちの間の問い合わせは送り直されない
                let d = match self.h.dut().delivered(c) {
                    Ok(v) => v,
                    Err(DutError::Engine(_)) => false,
                    Err(e) => return Err(self.h.broken(&e)),
                };
                self.h.check(
                    &id,
                    d,
                    "Delivered reports the closed connection as delivered",
                    yes_no(d, "delivered", "not delivered"),
                );
            }
            "recv" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let n = self.arg(st, 1)?;
                let n = self.count(&n)?;
                let d = self.arg(st, 2)?;
                let d = self.dur(&d)?;
                let (got, dups, max_len) =
                    self.receive_max(&pv, usize::try_from(n).unwrap_or(usize::MAX), d)?;
                self.bind(
                    st,
                    V::record(
                        "recv",
                        vec![
                            ("data", V::Bytes(got)),
                            ("dups", V::Int(dups)),
                            ("max_len", V::Int(max_len)),
                        ],
                    ),
                );
            }
            _ => {
                if !self.net_stmt(st)? {
                    return self.failf(format!("statement {} is not implemented", st.verb));
                }
            }
        }
        Ok(true)
    }

    /// 結果を見ない操作です。DUT が壊れた時だけ止めます。
    fn ignore(
        &mut self,
        f: impl FnOnce(&mut dyn crate::dut::ClockedDut) -> Result<(), DutError>,
    ) -> R<()> {
        match f(self.h.dut()) {
            Ok(()) | Err(DutError::Engine(_)) => Ok(()),
            Err(e) => Err(self.h.broken(&e)),
        }
    }

    fn capture(got: Option<Segment>, at: i64) -> V {
        match got {
            Some(s) => V::seg(s, true, at),
            None => V::seg(Segment::default(), false, at),
        }
    }

    fn dial(&mut self, st: &Stmt) -> R<Dial> {
        let mut d = Dial {
            syn: Options::none(),
            window: 0,
            syn_window: 0,
            ack_delay: 0,
        };
        for (k, e) in &st.named {
            let v = self.eval(e, None)?;
            match k.as_str() {
                "syn" => d.syn = self.opts(&v)?,
                "window" => d.window = trunc16(self.int(&v)?),
                "syn_window" => d.syn_window = trunc16(self.int(&v)?),
                "ack_delay" => d.ack_delay = self.dur(&v)?,
                _ => {}
            }
        }
        Ok(d)
    }

    fn set_peer(&mut self, pv: &PeerV, field: &str, v: &V) -> R<()> {
        match field {
            "snd_nxt" => {
                let s = self.seq(v)?;
                pv.p.borrow_mut().snd_nxt = s;
            }
            "rcv_nxt" => {
                let s = self.seq(v)?;
                pv.p.borrow_mut().rcv_nxt = s;
            }
            "window" => {
                let w = trunc16(self.int(v)?);
                pv.p.borrow_mut().window = w;
            }
            "ws" => {
                let w = self.int(v)?;
                pv.p.borrow_mut().ws = w;
            }
            _ => return self.failf(format!("set does not write a peer's {field}")),
        }
        Ok(())
    }

    /// この流れで `m` が受け入れる最初の segment を `d` の内に返します。Go の `Peer.Await` です。
    fn await_seg(
        &mut self,
        pv: &Rc<PeerV>,
        d: i64,
        m: &mut dyn FnMut(&mut Self, &Segment) -> R<bool>,
    ) -> R<Option<Segment>> {
        self.h.logf(format!(
            "wait up to {} for a matching segment",
            gofmt::duration(d)
        ));
        let deadline = self.h.now()?.saturating_add(d);
        loop {
            let wait = deadline.saturating_sub(self.h.now()?).max(0);
            let got = self.h.peer_next(&mut pv.p.borrow_mut(), wait)?;
            let Some(s) = got else { return Ok(None) };
            if m(self, &s)? {
                return Ok(Some(s));
            }
        }
    }

    /// 新しい相手から `port` へ 3 方向の handshake をします。Go の `H.Handshake` と `HandshakeFrom` です。
    fn handshake(&mut self, port: u16, d: &Dial) -> R<(Peer, Segment)> {
        let p = self.h.new_peer(port)?;
        let pv = Rc::new(PeerV {
            p: RefCell::new(p),
            synack: None,
            conn: None,
        });
        let synack = self.handshake_from(&pv, d)?;
        let p = pv.p.borrow().clone();
        Ok((p, synack))
    }

    fn handshake_from(&mut self, pv: &Rc<PeerV>, d: &Dial) -> R<Segment> {
        let mut syn_opts = d.syn.clone();
        let syn = {
            let mut p = pv.p.borrow_mut();
            p.window = if d.window == 0 { 65535 } else { d.window };
            let syn_win = if d.syn_window == 0 {
                p.window
            } else {
                d.syn_window
            };
            p.ws = d.syn.ws;
            if syn_opts.ts.is_some() {
                let val = self.h.ts_val(&p)?;
                syn_opts.ts = Some(Timestamps { val, ecr: 0 });
                p.syn_ts_val = val;
            }
            Segment {
                src: p.local,
                dst: p.remote,
                seq: p.iss,
                flags: SYN,
                window: syn_win,
                opts: syn_opts.clone(),
                ..Segment::default()
            }
        };
        self.h.send(&mut pv.p.borrow_mut(), &syn)?;
        let got = self.await_seg(pv, 2 * SECOND, &mut |_, s| Ok(s.has(SYN | ACK)))?;
        let (synack, ok) = match got {
            Some(s) => (s, true),
            None => (Segment::default(), false),
        };
        let iss = pv.p.borrow().iss;
        let desc = synack_string(&pv.p.borrow(), &synack, ok);
        self.h.require(
            "handshake.synack",
            ok && synack.ack == iss.wrapping_add(1),
            "a SYN-ACK acknowledging ISS+1 within 2 s",
            &desc,
        )?;
        pv.p.borrow_mut().adopt(&syn_opts, &synack);
        if d.ack_delay > 0 {
            let start = self.h.now()?;
            self.h.quiet(&mut pv.p.borrow_mut(), d.ack_delay)?;
            let held = self.h.now()?.saturating_sub(start);
            pv.p.borrow_mut().ack_held = held;
        }
        self.h.send_ack(&mut pv.p.borrow_mut())?;
        Ok(synack)
    }

    /// 次の接続を 2 秒の内に受け入れ、台本の終わりに abort します。Go の `H.Accept` と rustdut の `Accept` です。
    /// 待つ必要がある時、Go は締め切りまで待って待ち受けを閉じます。手で進める時計の DUT では待つ間に何も
    /// 変わらないので、すぐに同じことをします。
    fn accept(&mut self, l: &Rc<RefCell<ListenerV>>) -> R<Handle> {
        let lh = l.borrow().h;
        let res = match self.h.dut().accept(lh) {
            Op::Ready(a) => Ok(a.conn),
            Op::WouldBlock => {
                self.ignore(|d| d.close(lh))?;
                Err(GoErr::Timeout)
            }
            Op::Failed(DutError::Engine(e)) => Err(GoErr::from_engine(e)),
            Op::Failed(e) => return Err(self.h.broken(&e)),
        };
        let err = res.as_ref().err().cloned();
        self.h.require(
            "handshake.accept",
            err.is_none(),
            "accept within 2 s after the final ACK",
            &format!("error {}", err_string(err.as_ref())),
        )?;
        let c = res.unwrap_or(Handle(0));
        self.h.cleanups.push(Cleanup::AbortConn(c));
        Ok(c)
    }

    /// 接続から `n` byte を読みます。Go の `readFull` と rustdut の `Read` です。Go は待つ必要があると締め切りまで
    /// 壁時計で待ち、締め切りの後は最大 0 の `READ` で誤りを確かめます。待つ間に DUT は変わらないので、すぐに
    /// 同じ要求を送ります。
    fn read_full(&mut self, c: Handle, n: usize, d: i64) -> R<(Vec<u8>, Option<GoErr>)> {
        let mut got = Vec::new();
        let mut expired = d <= 0;
        while got.len() < n {
            if expired {
                return match self.h.dut().read(c, 0) {
                    Op::Ready(_) => Ok((got, Some(GoErr::Timeout))),
                    Op::WouldBlock => Ok((
                        got,
                        Some(GoErr::Other(
                            "rustdut: read answered WOULD_BLOCK".to_owned(),
                        )),
                    )),
                    Op::Failed(DutError::Engine(e)) => Ok((got, Some(GoErr::from_engine(e)))),
                    Op::Failed(e) => Err(self.h.broken(&e)),
                };
            }
            let want = (n - got.len()).min(MAX_READ);
            match self.h.dut().read(c, want) {
                Op::Ready(b) if b.is_empty() => expired = true,
                Op::Ready(b) => got.extend_from_slice(&b[..b.len().min(want)]),
                Op::WouldBlock => expired = true,
                Op::Failed(DutError::Engine(e)) => return Ok((got, Some(GoErr::from_engine(e)))),
                Op::Failed(e) => return Err(self.h.broken(&e)),
            }
        }
        Ok((got, None))
    }

    /// 接続に書きます。Go の rustdut の `Write` です。締め切りの無い書き込みが待つ必要を返すと Go は待ち続けるので、
    /// 台本を誤りで止めます。
    fn conn_write(&mut self, c: Handle, b: &[u8]) -> R<(usize, Option<GoErr>)> {
        let mut total = 0;
        loop {
            let chunk = &b[total..b.len().min(total + MAX_READ)];
            match self.h.dut().write(c, chunk) {
                Op::Ready(0) | Op::WouldBlock => {
                    if b.is_empty() {
                        return Ok((0, None));
                    }
                    return Err(self.h.fatalf(
                        "rustdut: a write without a deadline would wait for ever: the DUT takes nothing".to_owned(),
                    ));
                }
                Op::Ready(k) => {
                    total += k;
                    if total >= b.len() {
                        return Ok((total, None));
                    }
                }
                Op::Failed(DutError::Engine(e)) => return Ok((total, Some(GoErr::from_engine(e)))),
                Op::Failed(e) => return Err(self.h.broken(&e)),
            }
        }
    }

    /// Go の `alive` です。
    fn alive(&mut self, id: &str, pv: &Rc<PeerV>, c: Handle) -> R<()> {
        let (_, werr) = self.conn_write(c, b"ping")?;
        let got = self.await_seg(pv, 2 * SECOND, &mut |_, s| Ok(is_data(s)))?;
        let ok = got.is_some();
        let s = got.unwrap_or_default();
        let rcv = pv.p.borrow().rcv_nxt;
        let arrived = werr.is_none() && ok && s.payload == b"ping";
        let observed = if arrived {
            "ping arrived".to_owned()
        } else {
            format!(
                "write error {}; {}",
                err_kind(werr.as_ref()),
                seg_desc(&s, ok)
            )
        };
        self.h.check(
            &format!("{id}.dut-sends"),
            werr.is_none() && ok && s.seq == rcv && s.payload == b"ping",
            "the application's write reaches the testbench",
            &observed,
        );
        if ok {
            pv.p.borrow_mut().rcv_nxt = s.seq.wrapping_add(s.seq_len());
        }
        self.h.send_data(&mut pv.p.borrow_mut(), b"pong".to_vec())?;
        let (got, err) = self.read_full(c, 4, 2 * SECOND)?;
        self.h.check(
            &format!("{id}.dut-receives"),
            err.is_none() && got == b"pong",
            "the application reads the testbench's data",
            &format!("{} bytes, error {}", got.len(), err_kind(err.as_ref())),
        );
        Ok(())
    }

    /// Go の `receiveMax` です。
    fn receive_max(&mut self, pv: &Rc<PeerV>, n: usize, d: i64) -> R<(Vec<u8>, i64, i64)> {
        let mut got = Vec::new();
        let (mut dups, mut max_len) = (0, 0);
        while got.len() < n {
            let Some(s) = self.await_seg(pv, d, &mut |_, s| Ok(is_data(s)))? else {
                break;
            };
            max_len = max_len.max(len64(s.payload.len()));
            let rcv = pv.p.borrow().rcv_nxt;
            if s.seq == rcv {
                got.extend_from_slice(&s.payload);
                let mut p = pv.p.borrow_mut();
                p.rcv_nxt = p
                    .rcv_nxt
                    .wrapping_add(u32::try_from(s.payload.len()).unwrap_or(0));
                self.h.send_ack(&mut p)?;
            } else if seq_diff(s.seq, rcv) < 0 {
                dups += 1;
            }
        }
        Ok((got, dups, max_len))
    }

    /// Go の `burstUntil` です。
    fn burst_until(&mut self, pv: &Rc<PeerV>, n: usize) -> R<(Vec<Segment>, usize)> {
        let mut segs = Vec::new();
        let mut sent = 0;
        let mut high = pv.p.borrow().rcv_nxt;
        while n == 0 || sent < n {
            let Some(s) = self.await_seg(pv, 30 * MS, &mut |_, s| Ok(is_data(s)))? else {
                return Ok((segs, sent));
            };
            if after(high, s.seq) {
                self.h.logf(format!(
                    "a retransmission during the initial burst is left out: {s}"
                ));
                continue;
            }
            sent += s.payload.len();
            high = s
                .seq
                .wrapping_add(u32::try_from(s.payload.len()).unwrap_or(0));
            segs.push(s);
        }
        Ok((segs, sent))
    }

    // 述語。

    fn predicate(&self, e: &Expr) -> Pred {
        let frozen = self
            .vars
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    V::Peer(pv) => V::Peer(Rc::new(PeerV {
                        p: RefCell::new(pv.p.borrow().clone()),
                        synack: pv.synack.clone(),
                        conn: pv.conn,
                    })),
                    v => v.clone(),
                };
                (k.clone(), v)
            })
            .collect();
        Pred {
            expr: e.clone(),
            frozen: Rc::new(frozen),
        }
    }

    fn pred_true(&mut self, p: &Pred, s: V) -> R<bool> {
        let saved = std::mem::replace(&mut self.vars, p.frozen.clone());
        let mut local = HashMap::new();
        local.insert("s".to_owned(), s);
        let r = self
            .eval(&p.expr, Some(&local))
            .and_then(|v| self.truth(&v));
        self.vars = saved;
        r
    }

    fn template(&mut self, t: &[TmplPart]) -> R<String> {
        let mut out = String::new();
        for p in t {
            match p {
                TmplPart::Text(s) => out.push_str(s),
                TmplPart::Expr(e) => {
                    let v = self.eval(e, None)?;
                    out.push_str(&self.text(&v)?);
                }
            }
        }
        Ok(out)
    }

    fn text(&mut self, v: &V) -> R<String> {
        match v {
            V::Int(i) => Ok(i.to_string()),
            V::Seq(s) => Ok(s.to_string()),
            V::Bool(b) => Ok(b.to_string()),
            V::Bytes(b) => Ok(String::from_utf8_lossy(b).into_owned()),
            v => self.failf(format!("a template cannot show {}", v.type_name())),
        }
    }

    /// Go の `measureValue` を `fmt.Sprint` で書いた文字列です。
    fn measure_value(&mut self, v: &V) -> R<String> {
        Ok(match v {
            V::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            V::Seq(s) => s.to_string(),
            V::None => "none".to_owned(),
            V::Int(i) => i.to_string(),
            V::Bool(b) => b.to_string(),
            V::Dur(d) => gofmt::duration(*d),
            V::Addr(a) => a.to_string(),
            V::AddrPort(a) => a.to_string(),
            v => return self.failf(format!("measure cannot show {}", v.type_name())),
        })
    }

    // 評価。

    fn eval(&mut self, e: &Expr, local: Option<&HashMap<String, V>>) -> R<V> {
        match e {
            Expr::Int(i) => Ok(V::Int(*i)),
            Expr::Dur(d) => Ok(V::Dur(*d)),
            Expr::Str(s) => Ok(V::Bytes(s.clone())),
            Expr::Name(n) => {
                if let Some(v) = local.and_then(|l| l.get(n)) {
                    return Ok(v.clone());
                }
                if let Some(v) = self.constant(n)? {
                    return Ok(v);
                }
                match self.vars.get(n) {
                    Some(v) => Ok(v.clone()),
                    None => self.failf(format!("{n} is not bound")),
                }
            }
            Expr::Field { of, name } => {
                let x = self.eval(of, local)?;
                self.field(&x, name)
            }
            Expr::Index { of, index } => {
                let x = self.eval(of, local)?;
                let i = self.eval(index, local)?;
                let i = self.int(&i)?;
                match &x {
                    V::List(l) => match usize::try_from(i).ok().and_then(|i| l.get(i)) {
                        Some(v) => Ok(v.clone()),
                        None => self.failf(format!("index {i} out of range of {}", l.len())),
                    },
                    V::Bytes(b) => match usize::try_from(i).ok().and_then(|i| b.get(i)) {
                        Some(v) => Ok(V::Int(i64::from(*v))),
                        None => self.failf(format!("index {i} out of range of {}", b.len())),
                    },
                    x => self.failf(format!("cannot index {}", x.type_name())),
                }
            }
            Expr::Slice { of, lo, hi } => {
                let b = self.eval(of, local)?;
                let b = self.bytes(&b)?;
                let mut l = 0;
                let mut r = len64(b.len());
                if let Some(e) = lo {
                    let v = self.eval(e, local)?;
                    l = self.int(&v)?;
                }
                if let Some(e) = hi {
                    let v = self.eval(e, local)?;
                    r = self.int(&v)?;
                }
                if l < 0 || r < l || r > len64(b.len()) {
                    return self.failf(format!("slice [{l}:{r}] out of range of {}", b.len()));
                }
                Ok(V::Bytes(
                    b[usize::try_from(l).unwrap_or(0)..usize::try_from(r).unwrap_or(0)].to_vec(),
                ))
            }
            Expr::Un { op, x } => {
                let v = self.eval(x, local)?;
                if *op == "!" {
                    return Ok(V::Bool(!self.truth(&v)?));
                }
                match v {
                    V::Int(i) => Ok(V::Int(i.wrapping_neg())),
                    V::Dur(d) => Ok(V::Dur(d.wrapping_neg())),
                    v => self.failf(format!("cannot negate {}", v.type_name())),
                }
            }
            Expr::Bin { op, l, r } => self.binary(op, l, r, local),
            Expr::Call { name, args, named } => self.call(name, args, named, local),
        }
    }

    fn constant(&mut self, name: &str) -> R<Option<V>> {
        Ok(Some(match name {
            "SYN" => V::Int(i64::from(SYN)),
            "FIN" => V::Int(i64::from(FIN)),
            "RST" => V::Int(i64::from(RST)),
            "PSH" => V::Int(i64::from(PSH)),
            "ACK" => V::Int(i64::from(ACK)),
            "PEER_ADDR" => V::Addr(PEER_ADDR),
            "DUT_ADDR" => V::Addr(self.h.dut_addr),
            "MTU" => V::Int(len64(MTU)),
            "DUT_MTU" => V::Int(len64(self.h.mtu)),
            "now" => V::Time(self.h.now()?),
            "prompt" => V::Dur(0),
            "none" => V::None,
            "true" => V::Bool(true),
            "false" => V::Bool(false),
            _ => return Ok(None),
        }))
    }

    fn binary(&mut self, op: &str, l: &Expr, r: &Expr, local: Option<&HashMap<String, V>>) -> R<V> {
        match op {
            "&&" => {
                let a = self.eval(l, local)?;
                if !self.truth(&a)? {
                    return Ok(V::Bool(false));
                }
                let b = self.eval(r, local)?;
                return Ok(V::Bool(self.truth(&b)?));
            }
            "||" => {
                let a = self.eval(l, local)?;
                if self.truth(&a)? {
                    return Ok(V::Bool(true));
                }
                let b = self.eval(r, local)?;
                return Ok(V::Bool(self.truth(&b)?));
            }
            _ => {}
        }
        let a = self.eval(l, local)?;
        let b = self.eval(r, local)?;
        match op {
            "==" => return Ok(V::Bool(self.equal(&a, &b)?)),
            "!=" => return Ok(V::Bool(!self.equal(&a, &b)?)),
            "<" | "<=" | ">" | ">=" => {
                let c = self.compare(&a, &b)?;
                return Ok(V::Bool(match op {
                    "<" => c.is_lt(),
                    "<=" => c.is_le(),
                    ">" => c.is_gt(),
                    _ => c.is_ge(),
                }));
            }
            _ => {}
        }
        let v = match (&a, &b, op) {
            (V::Int(x), V::Int(y), "+") => Some(V::Int(x.wrapping_add(*y))),
            (V::Int(x), V::Int(y), "-") => Some(V::Int(x.wrapping_sub(*y))),
            (V::Int(x), V::Int(y), "*") => Some(V::Int(x.wrapping_mul(*y))),
            (V::Int(_), V::Int(0), "/" | "%") | (V::Dur(_), V::Int(0), "/") => {
                return self.failf("division by zero");
            }
            (V::Int(x), V::Int(y), "/") => Some(V::Int(x.wrapping_div(*y))),
            (V::Int(x), V::Int(y), "%") => Some(V::Int(x.wrapping_rem(*y))),
            (V::Int(x), V::Int(y), "|") => Some(V::Int(x | y)),
            (V::Int(x), V::Seq(s), "+") | (V::Seq(s), V::Int(x), "+") => {
                Some(V::Seq(s.wrapping_add(trunc32(*x))))
            }
            (V::Seq(s), V::Int(x), "-") => Some(V::Seq(s.wrapping_sub(trunc32(*x)))),
            (V::Seq(x), V::Seq(y), "-") => Some(V::Int(i64::from(seq_diff(*x, *y)))),
            (V::Int(x), V::Dur(d), "*") | (V::Dur(d), V::Int(x), "*") => {
                Some(V::Dur(x.wrapping_mul(*d)))
            }
            (V::Dur(x), V::Dur(y), "+") => Some(V::Dur(x.wrapping_add(*y))),
            (V::Dur(x), V::Dur(y), "-") => Some(V::Dur(x.wrapping_sub(*y))),
            (V::Dur(x), V::Int(y), "/") => Some(V::Dur(x.wrapping_div(*y))),
            (V::Time(x), V::Time(y), "-") => Some(V::Dur(x.saturating_sub(*y))),
            (V::Time(x), V::Dur(d), "+") => Some(V::Time(x.saturating_add(*d))),
            (V::Bytes(x), V::Bytes(y), "+") => {
                Some(V::Bytes([x.as_slice(), y.as_slice()].concat()))
            }
            _ => None,
        };
        match v {
            Some(v) => Ok(v),
            None => self.failf(format!(
                "{} {op} {} is not defined",
                a.type_name(),
                b.type_name()
            )),
        }
    }

    fn equal(&mut self, l: &V, r: &V) -> R<bool> {
        if matches!(l, V::None) || matches!(r, V::None) {
            return Ok(matches!(l, V::None) && matches!(r, V::None));
        }
        let same = l.type_name() == r.type_name();
        Ok(match (l, r) {
            (V::Bytes(a), V::Bytes(b)) => a == b,
            (V::Bytes(_), _) => {
                return self.failf(format!("bytes == {} is not defined", r.type_name()));
            }
            (
                V::Int(_)
                | V::Bool(_)
                | V::Seq(_)
                | V::Addr(_)
                | V::AddrPort(_)
                | V::Dur(_)
                | V::Block(_),
                _,
            ) if !same => {
                return self.failf(format!(
                    "{} == {} is not defined",
                    l.type_name(),
                    r.type_name()
                ));
            }
            (V::Int(a), V::Int(b)) | (V::Dur(a), V::Dur(b)) => a == b,
            (V::Bool(a), V::Bool(b)) => a == b,
            (V::Seq(a), V::Seq(b)) => a == b,
            (V::Addr(a), V::Addr(b)) => a == b,
            (V::AddrPort(a), V::AddrPort(b)) => a == b,
            (V::Block(a), V::Block(b)) => a == b,
            (V::Ts(a, b), V::Ts(c, d)) => a == c && b == d,
            (V::Ts(..) | V::Err(_), _) => false,
            _ => {
                return self.failf(format!(
                    "{} == {} is not defined",
                    l.type_name(),
                    r.type_name()
                ));
            }
        })
    }

    fn compare(&mut self, l: &V, r: &V) -> R<std::cmp::Ordering> {
        match (l, r) {
            (V::Int(a), V::Int(b)) | (V::Dur(a), V::Dur(b)) | (V::Time(a), V::Time(b)) => {
                Ok(a.cmp(b))
            }
            (V::Seq(a), V::Seq(b)) => Ok(seq_diff(*a, *b).cmp(&0)),
            _ => self.failf(format!(
                "{} and {} do not compare",
                l.type_name(),
                r.type_name()
            )),
        }
    }

    fn field(&mut self, x: &V, name: &str) -> R<V> {
        let v = match x {
            V::Seg(s) => self.seg_field(s, name)?,
            V::Peer(p) => self.peer_field(p, name)?,
            V::Record(r) => match r.fields.iter().find(|(k, _)| *k == name) {
                Some((_, v)) => Some(v.clone()),
                None => return self.failf(format!("the {} result has no field {name}", r.name)),
            },
            V::Ts(val, ecr) => match name {
                "val" => Some(V::Seq(*val)),
                "ecr" => Some(V::Seq(*ecr)),
                _ => None,
            },
            V::Opts(o) => match name {
                "mss" => Some(o.mss.map_or(V::None, |m| V::Int(i64::from(m)))),
                "ws" => Some(V::Int(o.ws)),
                "sack_permitted" => Some(V::Bool(o.sack_permitted)),
                "ts" => Some(o.ts.map_or(V::None, |t| V::Ts(t.val, t.ecr))),
                _ => None,
            },
            V::Block(b) => match name {
                "left" => Some(V::Seq(b.left)),
                "right" => Some(V::Seq(b.right)),
                _ => None,
            },
            V::None => return self.failf(format!("none has no field {name}")),
            _ => net_field(x, name),
        };
        match v {
            Some(v) => Ok(v),
            None => self.failf(format!("{} has no field {name}", x.type_name())),
        }
    }

    fn seg_field(&mut self, v: &SegV, name: &str) -> R<Option<V>> {
        let s = &v.seg;
        Ok(Some(match name {
            "ok" => V::Bool(v.ok),
            "at" => V::Time(v.at),
            "src" => V::AddrPort(s.src),
            "dst" => V::AddrPort(s.dst),
            "seq" => V::Seq(s.seq),
            "ack" => V::Seq(s.ack),
            "flags" => V::Int(i64::from(s.flags)),
            "window" => V::Int(i64::from(s.window)),
            "len" => V::Int(len64(s.payload.len())),
            "seq_len" => V::Int(i64::from(s.seq_len())),
            "payload" => V::Bytes(s.payload.clone()),
            "mss" => s.opts.mss.map_or(V::None, |m| V::Int(i64::from(m))),
            "ws" => V::Int(s.opts.ws),
            "sack_permitted" => V::Bool(s.opts.sack_permitted),
            "sack" => V::list(s.opts.sack.iter().map(|b| V::Block(*b)).collect()),
            "ts" => s.opts.ts.map_or(V::None, |t| V::Ts(t.val, t.ecr)),
            "df" => V::Bool(s.df),
            "ttl" => V::Int(i64::from(s.ttl)),
            "id" => V::Int(i64::from(s.id)),
            _ => return self.failf(format!("a segment has no field {name}")),
        }))
    }

    fn peer_field(&mut self, v: &PeerV, name: &str) -> R<Option<V>> {
        let p = v.p.borrow().clone();
        Ok(Some(match name {
            "local" => V::AddrPort(p.local),
            "remote" => V::AddrPort(p.remote),
            "iss" => V::Seq(p.iss),
            "snd_nxt" => V::Seq(p.snd_nxt),
            "dut_iss" => V::Seq(p.dut_iss),
            "rcv_nxt" => V::Seq(p.rcv_nxt),
            "ws" => V::Int(p.ws),
            "dut_ws" => V::Int(p.dut_ws),
            "window" => V::Int(i64::from(p.window)),
            "sack" => V::Bool(p.sack),
            "ts" => V::Bool(p.ts),
            "ts_recent" => V::Seq(p.ts_recent),
            "syn_ts_val" => V::Seq(p.syn_ts_val),
            "dut_ack" => V::Seq(p.dut_ack),
            "dut_window" => V::Int(p.dut_window),
            "synack" => match &v.synack {
                Some(s) => V::Seg(s.clone()),
                None => {
                    return self.failf("the peer has no SYN-ACK; connect and handshake record it");
                }
            },
            "conn" => match v.conn {
                Some(c) => V::Conn(c),
                None => return self.failf("the peer has no connection; connect records it"),
            },
            _ => return self.failf(format!("a peer has no field {name}")),
        }))
    }

    // 変換。

    fn truth(&mut self, v: &V) -> R<bool> {
        match v {
            V::Bool(b) => Ok(*b),
            v => self.failf(format!("a condition is bool, not {}", v.type_name())),
        }
    }

    fn int(&mut self, v: &V) -> R<i64> {
        match v {
            V::Int(i) => Ok(*i),
            v => self.failf(format!("an int is expected, not {}", v.type_name())),
        }
    }

    fn count(&mut self, v: &V) -> R<i64> {
        let n = self.int(v)?;
        if n < 0 {
            return self.failf(format!("a count is at least 0; got {n}"));
        }
        Ok(n)
    }

    fn seq(&mut self, v: &V) -> R<u32> {
        match v {
            V::Seq(s) => Ok(*s),
            v => self.failf(format!(
                "a sequence number is expected, not {}",
                v.type_name()
            )),
        }
    }

    fn dur(&mut self, v: &V) -> R<i64> {
        match v {
            V::Dur(d) => Ok(*d),
            v => self.failf(format!("a duration is expected, not {}", v.type_name())),
        }
    }

    fn bytes(&mut self, v: &V) -> R<Vec<u8>> {
        match v {
            V::Bytes(b) => Ok(b.clone()),
            v => self.failf(format!("bytes are expected, not {}", v.type_name())),
        }
    }

    fn port(&mut self, v: &V) -> R<u16> {
        let i = self.int(v)?;
        match u16::try_from(i) {
            Ok(p) if p >= 1 => Ok(p),
            _ => self.failf(format!("port {i} out of range")),
        }
    }

    fn peer(&mut self, v: &V) -> R<Rc<PeerV>> {
        match v {
            V::Peer(p) => Ok(p.clone()),
            v => self.failf(format!("a peer is expected, not {}", v.type_name())),
        }
    }

    fn listener(&mut self, v: &V) -> R<Rc<RefCell<ListenerV>>> {
        match v {
            V::Listener(l) => Ok(l.clone()),
            v => self.failf(format!("a listener is expected, not {}", v.type_name())),
        }
    }

    fn conn(&mut self, v: &V) -> R<Handle> {
        match v {
            V::Conn(c) => Ok(*c),
            v => self.failf(format!("a connection is expected, not {}", v.type_name())),
        }
    }

    fn seg(&mut self, v: &V) -> R<Rc<SegV>> {
        match v {
            V::Seg(s) => Ok(s.clone()),
            v => self.failf(format!("a segment is expected, not {}", v.type_name())),
        }
    }

    fn opts(&mut self, v: &V) -> R<Options> {
        match v {
            V::Opts(o) => Ok((**o).clone()),
            v => self.failf(format!("options are expected, not {}", v.type_name())),
        }
    }

    fn list(&mut self, v: &V) -> R<Rc<Vec<V>>> {
        match v {
            V::List(l) => Ok(l.clone()),
            V::None => Ok(Rc::new(Vec::new())),
            v => self.failf(format!("a list is expected, not {}", v.type_name())),
        }
    }

    fn ip(&mut self, v: &V) -> R<Rc<IpV>> {
        match v {
            V::Ip(p) => Ok(p.clone()),
            v => self.failf(format!("an IPv4 packet is expected, not {}", v.type_name())),
        }
    }

    fn addr(&mut self, v: &V) -> R<Ipv4Addr> {
        match v {
            V::Addr(a) => Ok(*a),
            v => self.failf(format!("an address is expected, not {}", v.type_name())),
        }
    }

    fn addr_port(&mut self, v: &V) -> R<SocketAddrV4> {
        match v {
            V::AddrPort(a) => Ok(*a),
            v => self.failf(format!(
                "an address and port are expected, not {}",
                v.type_name()
            )),
        }
    }

    fn udp_conn(&mut self, v: &V) -> R<Rc<RefCell<UdpConnV>>> {
        match v {
            V::UdpConn(u) => Ok(u.clone()),
            v => self.failf(format!("a UDP socket is expected, not {}", v.type_name())),
        }
    }

    // 関数。

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per function, as the Go runner's switch"
    )]
    fn call(
        &mut self,
        name: &str,
        args: &[Expr],
        named: &BTreeMap<String, Expr>,
        local: Option<&HashMap<String, V>>,
    ) -> R<V> {
        let n = args.len();
        macro_rules! arg {
            ($i:expr) => {
                match args.get($i) {
                    Some(e) => self.eval(e, local)?,
                    None => {
                        return self.failf(format!("{name} needs at least {} arguments", $i + 1))
                    }
                }
            };
        }
        // 捕捉の ok を上書きする省略できる引数です
        macro_rules! ok_arg {
            ($i:expr, $s:expr) => {
                if n > $i {
                    let v = arg!($i);
                    self.truth(&v)?
                } else {
                    $s.ok
                }
            };
        }
        Ok(match name {
            "yes_no" => {
                let c = arg!(0);
                if self.truth(&c)? { arg!(1) } else { arg!(2) }
            }
            "clocked" => arg!(0),
            "is_data" | "is_pure_ack" | "is_fin" | "is_rst" | "is_synack" => {
                let v = arg!(0);
                let s = self.seg(&v)?;
                let s = &s.seg;
                V::Bool(match name {
                    "is_data" => is_data(s),
                    "is_pure_ack" => is_pure_ack(s),
                    "is_fin" => s.has(FIN),
                    "is_rst" => s.has(RST),
                    _ => s.has(SYN | ACK),
                })
            }
            "has" => {
                let v = arg!(0);
                let s = self.seg(&v)?;
                let f = arg!(1);
                let f = trunc8(self.int(&f)?);
                V::Bool(s.seg.has(f))
            }
            "acks" => {
                let q = arg!(1);
                let q = self.seq(&q)?;
                let v = arg!(0);
                let s = self.seg(&v)?;
                V::Bool(s.seg.has(ACK) && !s.seg.has(RST) && s.seg.ack == q)
            }
            "len" => match arg!(0) {
                V::Bytes(b) => V::Int(len64(b.len())),
                V::List(l) => V::Int(len64(l.len())),
                _ => return self.failf("len takes bytes or a list"),
            },
            "count" => {
                let v = arg!(0);
                V::Int(len64(self.list(&v)?.len()))
            }
            "first" | "filter" | "any" => {
                let v = arg!(0);
                let l = self.list(&v)?;
                let mut out = Vec::new();
                for x in l.iter() {
                    let mut loc = local.cloned().unwrap_or_default();
                    loc.insert("s".to_owned(), x.clone());
                    let Some(e) = args.get(1) else {
                        return self.failf(format!("{name} needs at least 2 arguments"));
                    };
                    let t = self.eval(e, Some(&loc))?;
                    if self.truth(&t)? {
                        match name {
                            "first" => return Ok(x.clone()),
                            "any" => return Ok(V::Bool(true)),
                            _ => out.push(x.clone()),
                        }
                    }
                }
                match name {
                    "first" => V::seg(Segment::default(), false, ZERO_TIME),
                    "any" => V::Bool(false),
                    _ => V::list(out),
                }
            }
            "max_of" | "sum_of" => {
                let v = arg!(0);
                let l = self.list(&v)?;
                let mut acc = 0i64;
                for (i, x) in l.iter().enumerate() {
                    let mut loc = local.cloned().unwrap_or_default();
                    loc.insert("s".to_owned(), x.clone());
                    let Some(e) = args.get(1) else {
                        return self.failf(format!("{name} needs at least 2 arguments"));
                    };
                    let t = self.eval(e, Some(&loc))?;
                    let v = self.int(&t)?;
                    if name == "sum_of" {
                        acc = acc.wrapping_add(v);
                    } else if i == 0 || v > acc {
                        acc = v;
                    }
                }
                V::Int(acc)
            }
            "pattern" => {
                let c = arg!(0);
                let c = self.count(&c)?;
                let s = arg!(1);
                let s = trunc8(self.int(&s)?);
                V::Bytes(pattern(usize::try_from(c).unwrap_or(0), s))
            }
            "seq" => {
                let v = arg!(0);
                V::Seq(trunc32(self.int(&v)?))
            }
            "int" => {
                let v = arg!(0);
                V::Int(i64::from(self.seq(&v)?))
            }
            "text" => {
                let v = arg!(0);
                V::Bytes(self.text(&v)?.into_bytes())
            }
            "ms" => {
                let v = arg!(0);
                V::Int(self.dur(&v)? / MS)
            }
            "block" => {
                let a = arg!(0);
                let a = self.seq(&a)?;
                let b = arg!(1);
                let b = self.seq(&b)?;
                V::Block(SackBlock { left: a, right: b })
            }
            "ts" => {
                let a = arg!(0);
                let a = self.seq(&a)?;
                let b = arg!(1);
                let b = self.seq(&b)?;
                V::Ts(a, b)
            }
            "ts_val" => {
                let v = arg!(0);
                let p = self.peer(&v)?;
                let p = p.p.borrow().clone();
                V::Seq(self.h.ts_val(&p)?)
            }
            "opts_standard" => V::Opts(Rc::new(standard_syn())),
            "opts_nosack" => {
                let mut o = standard_syn();
                o.sack_permitted = false;
                V::Opts(Rc::new(o))
            }
            "opts_none" => V::Opts(Rc::new(Options::none())),
            "segment" => {
                let v = arg!(0);
                let p = self.peer(&v)?;
                let b = if n == 4 {
                    let v = arg!(3);
                    self.bytes(&v)?
                } else {
                    Vec::new()
                };
                let f = arg!(1);
                let f = trunc8(self.int(&f)?);
                let q = arg!(2);
                let q = self.seq(&q)?;
                let p = p.p.borrow().clone();
                let s = self.h.segment(&p, f, q, b)?;
                V::seg(s, true, ZERO_TIME)
            }
            "raw" => {
                let v = arg!(0);
                let p = self.peer(&v)?;
                let f = arg!(1);
                let f = trunc8(self.int(&f)?);
                let q = arg!(2);
                let q = self.seq(&q)?;
                let p = p.p.borrow();
                V::seg(
                    Segment {
                        src: p.local,
                        dst: p.remote,
                        seq: q,
                        flags: f,
                        opts: zero_options(),
                        ..Segment::default()
                    },
                    true,
                    ZERO_TIME,
                )
            }
            "syn" => {
                let v = arg!(0);
                let p = self.peer(&v)?;
                let o = arg!(1);
                let o = self.opts(&o)?;
                let p = p.p.borrow();
                V::seg(
                    Segment {
                        src: p.local,
                        dst: p.remote,
                        seq: p.iss,
                        flags: SYN,
                        window: 65535,
                        opts: o,
                        ..Segment::default()
                    },
                    true,
                    ZERO_TIME,
                )
            }
            "with" => {
                let x = arg!(0);
                self.with(&x, named, local)?
            }
            "seg_desc" => {
                let v = arg!(0);
                let s = self.seg(&v)?;
                let ok = ok_arg!(1, s);
                V::Bytes(seg_desc(&s.seg, ok).into_bytes())
            }
            "ack_desc" | "sack_desc" => {
                let v = arg!(0);
                let s = self.seg(&v)?;
                let b = arg!(1);
                let base = self.seq(&b)?;
                let ok = ok_arg!(2, s);
                let d = if name == "ack_desc" {
                    ack_desc(&s.seg, ok, base)
                } else {
                    sack_desc(&s.seg, ok, base)
                };
                V::Bytes(d.into_bytes())
            }
            "synack_desc" => {
                let v = arg!(1);
                let s = self.seg(&v)?;
                let p = arg!(0);
                let p = self.peer(&p)?;
                let ok = ok_arg!(2, s);
                let d = synack_string(&p.p.borrow(), &s.seg, ok);
                V::Bytes(d.into_bytes())
            }
            "err_kind" | "err_string" => {
                let e = match arg!(0) {
                    V::None => None,
                    V::Err(e) => Some(e),
                    _ => return self.failf(format!("{name} takes an error or none")),
                };
                let s = if name == "err_kind" {
                    err_kind(e.as_deref()).to_owned()
                } else {
                    err_string(e.as_deref())
                };
                V::Bytes(s.into_bytes())
            }
            "quote" => {
                let v = arg!(0);
                let b = self.bytes(&v)?;
                V::Bytes(gofmt::quote(&b).into_bytes())
            }
            _ => return self.net_call(name, args, local),
        })
    }

    /// 名前つきの欄を置き換えた segment か option の写しです。
    fn with(
        &mut self,
        x: &V,
        named: &BTreeMap<String, Expr>,
        local: Option<&HashMap<String, V>>,
    ) -> R<V> {
        match x {
            V::Seg(v) => {
                let mut cp = (**v).clone();
                for (k, e) in named {
                    let val = self.eval(e, local)?;
                    match k.as_str() {
                        "seq" => cp.seg.seq = self.seq(&val)?,
                        "ack" => cp.seg.ack = self.seq(&val)?,
                        "flags" => cp.seg.flags = trunc8(self.int(&val)?),
                        "window" => cp.seg.window = trunc16(self.int(&val)?),
                        "payload" => cp.seg.payload = self.bytes(&val)?,
                        "opts" => cp.seg.opts = self.opts(&val)?,
                        "mss" => {
                            cp.seg.opts.mss = match val {
                                V::None => None,
                                v => Some(trunc16(self.int(&v)?)),
                            };
                        }
                        "ts_val" => {
                            let q = self.seq(&val)?;
                            match cp.seg.opts.ts.as_mut() {
                                Some(t) => t.val = q,
                                None => {
                                    return self
                                        .failf("with ts_val= on a segment without timestamps");
                                }
                            }
                        }
                        "src" | "dst" => {
                            let V::AddrPort(ap) = val else {
                                return self.failf(format!("{k}= takes an address and port"));
                            };
                            if k == "src" {
                                cp.seg.src = ap;
                            } else {
                                cp.seg.dst = ap;
                            }
                        }
                        _ => return self.failf(format!("with does not set a segment's {k}")),
                    }
                }
                Ok(V::Seg(Rc::new(cp)))
            }
            V::Opts(o) => {
                let mut o = (**o).clone();
                for (k, e) in named {
                    let val = self.eval(e, local)?;
                    match k.as_str() {
                        "mss" => {
                            o.mss = match val {
                                V::None => None,
                                v => Some(trunc16(self.int(&v)?)),
                            };
                        }
                        "ws" => o.ws = self.int(&val)?,
                        "sack_permitted" => o.sack_permitted = self.truth(&val)?,
                        "ts" => {
                            o.ts = match val {
                                V::None => None,
                                V::Ts(a, b) => Some(Timestamps { val: a, ecr: b }),
                                _ => return self.failf("ts= takes ts(val, ecr) or none"),
                            };
                        }
                        _ => return self.failf(format!("with does not set an option {k}")),
                    }
                }
                Ok(V::Opts(Rc::new(o)))
            }
            x => self.failf(format!(
                "with takes a segment or options, not {}",
                x.type_name()
            )),
        }
    }
}

/// `connect` と `handshake` の試験台の側です。Go の `Dial` です。
struct Dial {
    syn: Options,
    window: u16,
    syn_window: u16,
    ack_delay: i64,
}

/// `script_net.go` の値の欄です。
fn net_field(x: &V, name: &str) -> Option<V> {
    match x {
        V::Ip(v) => {
            let p = &v.p;
            Some(match name {
                "ok" => V::Bool(v.ok),
                "at" => V::Time(v.at),
                "src" => V::Addr(p.src),
                "dst" => V::Addr(p.dst),
                "proto" => V::Int(i64::from(p.proto)),
                "id" => V::Int(i64::from(p.id)),
                "df" => V::Bool(p.df),
                "mf" => V::Bool(p.mf),
                "offset" => V::Int(len64(p.offset)),
                "ttl" => V::Int(i64::from(p.ttl)),
                "payload" => V::Bytes(p.payload.clone()),
                _ => return None,
            })
        }
        V::Udp(v) => {
            let (u, err) = &**v;
            Some(match name {
                "err" => V::err(err.clone().map(GoErr::Other)),
                "src" => V::AddrPort(u.src),
                "dst" => V::AddrPort(u.dst),
                "payload" => V::Bytes(u.payload.clone()),
                "checksum" => V::Int(i64::from(u.checksum)),
                _ => return None,
            })
        }
        V::Icmp(v) => {
            let (m, ok) = &**v;
            Some(match name {
                "ok" => V::Bool(*ok),
                "type" => V::Int(i64::from(m.typ)),
                "code" => V::Int(i64::from(m.code)),
                "rest" => V::Int(i64::from(m.rest)),
                "body" => V::Bytes(m.body.clone()),
                _ => return None,
            })
        }
        V::Quote(v) => {
            let (q, ok) = &**v;
            Some(match name {
                "ok" => V::Bool(*ok),
                "id" => V::Int(i64::from(q.ip.id)),
                "src" => V::Addr(q.ip.src),
                "dst" => V::Addr(q.ip.dst),
                "proto" => V::Int(i64::from(q.ip.proto)),
                "offset" => V::Int(len64(q.ip.offset)),
                "payload" => V::Bytes(q.ip.payload.clone()),
                "bytes" => V::Int(len64(q.bytes)),
                _ => return None,
            })
        }
        V::AddrPort(a) => Some(match name {
            "addr" => V::Addr(*a.ip()),
            "port" => V::Int(i64::from(a.port())),
            _ => return None,
        }),
        _ => None,
    }
}

// script_net.go の文と関数。
impl Interp<'_, '_> {
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per statement, as the Go runner's switch"
    )]
    fn net_stmt(&mut self, st: &Stmt) -> R<bool> {
        match st.verb.as_str() {
            "collect_flow" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let d = self.arg(st, 1)?;
                let d = self.dur(&d)?;
                let until = st.named.get("until").map(|e| self.predicate(e));
                let mut out = Vec::new();
                let deadline = self.h.now()?.saturating_add(d);
                loop {
                    let wait = deadline.saturating_sub(self.h.now()?).max(0);
                    let Some(s) = self.h.peer_next_logged(&mut pv.p.borrow_mut(), wait)? else {
                        break;
                    };
                    let at = self.h.now()?;
                    let sv = V::seg(s, true, at);
                    out.push(sv.clone());
                    if let Some(u) = &until
                        && self.pred_true(u, sv)?
                    {
                        break;
                    }
                }
                self.bind(st, V::list(out));
            }
            "flight" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let c = self.arg(st, 1)?;
                let c = self.conn(&c)?;
                let n = self.arg(st, 2)?;
                let n = self.int(&n)?;
                let salt = self.arg(st, 3)?;
                let salt = trunc8(self.int(&salt)?);
                let size = n.wrapping_mul(seg_size(&pv.p.borrow()));
                let data = pattern(usize::try_from(size).unwrap_or(0), salt);
                let (_, err) = self.conn_write(c, &data)?;
                if let Some(e) = err {
                    return Err(self.h.fatalf(format!("write: {}", e.err_string())));
                }
                let (segs, sent) = self.burst_until(&pv, data.len())?;
                self.h.require(
                    "flight",
                    sent == data.len() && len64(segs.len()) >= n,
                    &format!(
                        "the {} bytes leave in one initial burst of at least {n} segments",
                        data.len()
                    ),
                    &format!("{sent} bytes in {} segments", segs.len()),
                )?;
                let segs = segs
                    .into_iter()
                    .map(|s| V::seg(s, true, ZERO_TIME))
                    .collect();
                self.bind(
                    st,
                    V::record(
                        "flight",
                        vec![("segs", V::list(segs)), ("data", V::Bytes(data))],
                    ),
                );
            }
            "burst" => {
                let pv = self.arg(st, 0)?;
                let pv = self.peer(&pv)?;
                let (segs, n) = self.burst_until(&pv, 0)?;
                let segs = segs
                    .into_iter()
                    .map(|s| V::seg(s, true, ZERO_TIME))
                    .collect();
                self.bind(
                    st,
                    V::record(
                        "burst",
                        vec![("segs", V::list(segs)), ("bytes", V::Int(len64(n)))],
                    ),
                );
            }
            "at_once" => {
                let v = self.arg(st, 0)?;
                let l = self.list(&v)?;
                let mut segs = Vec::new();
                for x in l.iter() {
                    segs.push(self.seg(x)?.seg.clone());
                }
                // 手で進める時計では、同じ ms の timestamp を持つ segment が一緒に送ったものです (Go の atOnce)
                let out: Vec<Segment> = match segs.first().and_then(|s| s.opts.ts) {
                    None => segs,
                    Some(t0) => segs
                        .into_iter()
                        .filter(|s| s.opts.ts.is_none_or(|t| seq_diff(t.val, t0.val) <= 0))
                        .collect(),
                };
                self.bind(
                    st,
                    V::list(
                        out.into_iter()
                            .map(|s| V::seg(s, true, ZERO_TIME))
                            .collect(),
                    ),
                );
            }
            "listen_udp" => {
                let pa = self.arg(st, 1)?;
                let port = self.port(&pa)?;
                match self.h.dut().udp_listen(port) {
                    Ok(h) => {
                        let c = Rc::new(RefCell::new(UdpConnV {
                            h,
                            port,
                            closed: false,
                        }));
                        self.h.cleanups.push(Cleanup::CloseUdp(c.clone()));
                        self.set_var(&Self::first_name(st), V::UdpConn(c));
                    }
                    Err(DutError::Engine(e)) => {
                        let e = GoErr::from_engine(e);
                        return Err(self
                            .h
                            .fatalf(format!("listen on UDP {port}: {}", e.err_string())));
                    }
                    Err(e) => return Err(self.h.broken(&e)),
                }
            }
            "udp_read" => {
                let u = self.arg(st, 0)?;
                let u = self.udp_conn(&u)?;
                let d = self.arg(st, 1)?;
                let d = self.dur(&d)?;
                let (data, from, err) = self.read_datagram(&u, d)?;
                self.bind(
                    st,
                    V::record(
                        "udp_read",
                        vec![
                            ("data", V::Bytes(data)),
                            ("from", V::AddrPort(from)),
                            ("err", V::err(err)),
                        ],
                    ),
                );
            }
            "udp_write" => {
                let Some(e) = st.named.get("to") else {
                    return self.failf("udp_write needs to=");
                };
                let to = self.eval(e, None)?;
                let V::AddrPort(to) = to else {
                    return self.failf("to= takes an address and port");
                };
                let u = self.arg(st, 0)?;
                let u = self.udp_conn(&u)?;
                let b = self.arg(st, 1)?;
                let b = self.bytes(&b)?;
                let err = self.write_to(&u, &b, to)?;
                if st.bind.is_none()
                    && let Some(e) = &err
                {
                    return Err(self.h.fatalf(format!("WriteTo: {}", e.err_string())));
                }
                self.bind(st, V::record("udp_write", vec![("err", V::err(err))]));
            }
            "inject_ip" => match self.arg(st, 0)? {
                V::Ip(p) => self.inject_ip(&p.p)?,
                V::List(l) => {
                    for x in l.iter() {
                        let p = self.ip(x)?;
                        self.inject_ip(&p.p)?;
                    }
                }
                v => {
                    return self.failf(format!(
                        "inject_ip takes a packet or a list of them, not {}",
                        v.type_name()
                    ));
                }
            },
            "inject_icmp_error" => {
                let b = self.arg(st, 0)?;
                let b = self.bytes(&b)?;
                self.h.logf(format!(
                    "-> ICMP error {}",
                    gofmt::hex_spaced(&b[..b.len().min(28)])
                ));
                if let Err(e) = self.h.inject(&b) {
                    return Err(self.h.fatalf(format!("inject: {e}")));
                }
            }
            "await_ip" => {
                let Some(e) = st.named.get("match") else {
                    return self.failf(format!("{} needs match=", st.verb));
                };
                let pred = self.predicate(e);
                let d = self.arg(st, 0)?;
                let d = self.dur(&d)?;
                let got = self.packet(d, &mut |me, p| me.pred_ip(&pred, p))?;
                let at = self.h.now()?;
                let ok = got.is_some();
                self.bind(
                    st,
                    V::Ip(Rc::new(IpV {
                        p: got.unwrap_or_default(),
                        ok,
                        at,
                    })),
                );
            }
            "await_datagram" => {
                let Some(e) = st.named.get("match") else {
                    return self.failf(format!("{} needs match=", st.verb));
                };
                let pred = self.predicate(e);
                let mut r = Reassembler::default();
                let (mut frags, mut df, mut zero_id) = (0i64, false, false);
                let mut back = Ipv4::default();
                let mut done = false;
                let start = self.h.now()?;
                let d = self.arg(st, 0)?;
                let deadline = start.saturating_add(self.dur(&d)?);
                while !done {
                    let wait = deadline.saturating_sub(self.h.now()?).max(0);
                    let Some(p) = self.packet(wait, &mut |me, p| me.pred_ip(&pred, p))? else {
                        break;
                    };
                    frags += 1;
                    df = df || p.df;
                    zero_id = zero_id || p.id == 0;
                    if let Some(w) = r.add(p) {
                        back = w;
                        done = true;
                    }
                }
                let at = self.h.now()?;
                self.bind(
                    st,
                    V::record(
                        "await_datagram",
                        vec![
                            ("done", V::Bool(done)),
                            (
                                "packet",
                                V::Ip(Rc::new(IpV {
                                    p: back,
                                    ok: done,
                                    at,
                                })),
                            ),
                            ("frags", V::Int(frags)),
                            ("df", V::Bool(df)),
                            ("zero_id", V::Bool(zero_id)),
                        ],
                    ),
                );
            }
            "echo" => {
                let a = self.arg(st, 0)?;
                let ipid = trunc16(self.int(&a)?);
                let a = self.arg(st, 1)?;
                let ident = trunc16(self.int(&a)?);
                let a = self.arg(st, 2)?;
                let seq = trunc16(self.int(&a)?);
                let a = self.arg(st, 3)?;
                let payload = self.bytes(&a)?;
                let mut cuts = Vec::new();
                if let Some(e) = st.named.get("cuts") {
                    let v = self.eval(e, None)?;
                    for x in self.list(&v)?.iter() {
                        cuts.push(usize::try_from(self.int(x)?).unwrap_or(0));
                    }
                }
                let (m, frags, df, ok) = self.echo(ipid, ident, seq, &payload, &cuts)?;
                let rest = u32::from(ident) << 16 | u32::from(seq);
                let good = ok
                    && m.typ == ip::ICMP_ECHO_REPLY
                    && m.code == 0
                    && m.rest == rest
                    && m.body == payload;
                let desc = if ok {
                    format!(
                        "type {} code {}, same identifier and sequence {}, {} of {} bytes equal {}",
                        m.typ,
                        m.code,
                        m.rest == rest,
                        m.body.len(),
                        payload.len(),
                        m.body == payload
                    )
                } else {
                    "no reply".to_owned()
                };
                self.bind(
                    st,
                    V::record(
                        "echo",
                        vec![
                            ("ok", V::Bool(ok)),
                            ("frags", V::Int(frags)),
                            ("df", V::Bool(df)),
                            ("good", V::Bool(good)),
                            ("desc", V::Bytes(desc.into_bytes())),
                        ],
                    ),
                );
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn pred_ip(&mut self, pred: &Pred, p: &Ipv4) -> R<bool> {
        let v = V::Ip(Rc::new(IpV {
            p: p.clone(),
            ok: true,
            at: ZERO_TIME,
        }));
        self.pred_true(pred, v)
    }

    /// Go の `H.InjectIP` です。
    fn inject_ip(&mut self, p: &Ipv4) -> R<()> {
        self.h.logf(format!("-> {p}"));
        if let Err(e) = self.h.inject(&p.marshal()) {
            return Err(self.h.fatalf(format!("inject {p}: {e}")));
        }
        Ok(())
    }

    /// DUT が `d` の内に送る、`m` が受け入れる最初の IPv4 の packet です。Go の `H.Packet` です。
    fn packet(
        &mut self,
        d: i64,
        m: &mut dyn FnMut(&mut Self, &Ipv4) -> R<bool>,
    ) -> R<Option<Ipv4>> {
        let deadline = self.h.now()?.saturating_add(d);
        loop {
            let wait = deadline.saturating_sub(self.h.now()?).max(0);
            let Some(pkt) = self.h.next(wait)? else {
                return Ok(None);
            };
            if pkt.len() > self.h.mtu {
                let msg = format!(
                    "FAIL  emitted packet on {}: at most the MTU of {} bytes; got: {} bytes",
                    self.h.engine,
                    self.h.mtu,
                    pkt.len()
                );
                self.h.errorf(msg);
            }
            let p = match ip::parse_ipv4(&pkt) {
                Ok(p) => p,
                Err(e) => {
                    self.h.logf(format!(
                        "emitted packet ignored: {e}: {}",
                        gofmt::hex_spaced(&pkt[..pkt.len().min(40)])
                    ));
                    continue;
                }
            };
            if m(self, &p)? {
                self.h.logf(format!("<- {p}"));
                return Ok(Some(p));
            }
            self.h.logf(format!("packet ignored: {p}"));
        }
    }

    /// Go の `echo` です。
    fn echo(
        &mut self,
        ipid: u16,
        ident: u16,
        seq: u16,
        payload: &[u8],
        cuts: &[usize],
    ) -> R<(Icmp, i64, bool, bool)> {
        let req = ip::icmp_packet(
            PEER_ADDR,
            super::DUT_ADDR,
            ipid,
            &Icmp {
                typ: ip::ICMP_ECHO_REQUEST,
                code: 0,
                rest: u32::from(ident) << 16 | u32::from(seq),
                body: payload.to_vec(),
            },
        );
        for f in ip::fragments(&req, cuts) {
            self.inject_ip(&f)?;
        }
        let mut r = Reassembler::default();
        let (mut frags, mut df) = (0, false);
        let deadline = self.h.now()?.saturating_add(SECOND);
        loop {
            let wait = deadline.saturating_sub(self.h.now()?).max(0);
            let Some(p) =
                self.packet(
                    wait,
                    &mut |_, p| Ok(to_peer(p) && p.proto == ip::PROTO_ICMP),
                )?
            else {
                return Ok((Icmp::default(), frags, df, false));
            };
            frags += 1;
            df = df || p.df;
            if let Some(whole) = r.add(p) {
                match ip::parse_icmp(&whole) {
                    Ok(m) => return Ok((m, frags, df, true)),
                    Err(e) => self.h.logf(format!("reply ignored: {e}")),
                }
            }
        }
    }

    /// 1 つの datagram を `d` の内に読みます。Go の `readDatagram` と rustdut の `ReadFrom` です。
    fn read_datagram(
        &mut self,
        u: &Rc<RefCell<UdpConnV>>,
        d: i64,
    ) -> R<(Vec<u8>, SocketAddrV4, Option<GoErr>)> {
        let zero = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        let (h, closed) = {
            let u = u.borrow();
            (u.h, u.closed)
        };
        let expired_err = if closed {
            GoErr::Closed
        } else {
            GoErr::Timeout
        };
        if d <= 0 {
            return Ok((Vec::new(), zero, Some(expired_err)));
        }
        match self.h.dut().udp_recv(h, 70000) {
            Op::Ready(g) => Ok((g.data, g.from, None)),
            Op::WouldBlock => Ok((Vec::new(), zero, Some(expired_err))),
            Op::Failed(DutError::Engine(e)) => Ok((Vec::new(), zero, Some(GoErr::from_engine(e)))),
            Op::Failed(e) => Err(self.h.broken(&e)),
        }
    }

    /// 1 つの datagram を送ります。rustdut の `WriteTo` です。
    fn write_to(
        &mut self,
        u: &Rc<RefCell<UdpConnV>>,
        b: &[u8],
        to: SocketAddrV4,
    ) -> R<Option<GoErr>> {
        let (h, port) = {
            let u = u.borrow();
            (u.h, u.port)
        };
        let src = SocketAddrV4::new(self.h.dut_addr, port);
        if to.port() == 0 {
            return Ok(Some(GoErr::Other(op_error(
                "write",
                "udp",
                src,
                &to.to_string(),
                "invalid UDP address",
            ))));
        }
        if b.len() > 65535 - 20 - 8 {
            return Ok(Some(GoErr::Other(op_error(
                "write",
                "udp",
                src,
                &to.to_string(),
                "message too long",
            ))));
        }
        match self.h.dut().udp_send(h, to, b) {
            Op::Ready(()) => Ok(None),
            Op::WouldBlock => Err(self.h.fatalf(
                "rustdut: a UDP write without a deadline would wait for ever: the DUT's send budget is used up".to_owned(),
            )),
            Op::Failed(DutError::Engine(e)) => Ok(Some(GoErr::from_engine(e))),
            Op::Failed(e) => Err(self.h.broken(&e)),
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per function, as the Go runner's switch"
    )]
    fn net_call(&mut self, name: &str, args: &[Expr], local: Option<&HashMap<String, V>>) -> R<V> {
        let n = args.len();
        macro_rules! arg {
            ($i:expr) => {
                match args.get($i) {
                    Some(e) => self.eval(e, local)?,
                    None => {
                        return self.failf(format!("{name} needs at least {} arguments", $i + 1))
                    }
                }
            };
        }
        Ok(match name {
            "list" => {
                let mut out = Vec::with_capacity(n);
                for i in 0..n {
                    out.push(arg!(i));
                }
                V::list(out)
            }
            "max" => {
                let a = arg!(0);
                let a = self.int(&a)?;
                let b = arg!(1);
                V::Int(a.max(self.int(&b)?))
            }
            "zeros" => {
                let c = arg!(0);
                V::Bytes(vec![0; usize::try_from(self.count(&c)?).unwrap_or(0)])
            }
            "addr" => {
                let v = arg!(0);
                let b = self.bytes(&v)?;
                match String::from_utf8_lossy(&b).parse::<Ipv4Addr>() {
                    Ok(a) => V::Addr(a),
                    Err(e) => return self.failf(format!("addr: {e}")),
                }
            }
            "addrport" => {
                let V::Addr(a) = arg!(0) else {
                    return self.failf("addrport takes an address and a port");
                };
                let p = arg!(1);
                V::AddrPort(SocketAddrV4::new(a, self.port(&p)?))
            }
            "with_port" => {
                let V::AddrPort(ap) = arg!(0) else {
                    return self.failf("with_port takes an address and port");
                };
                let p = arg!(1);
                V::AddrPort(SocketAddrV4::new(*ap.ip(), self.port(&p)?))
            }
            "seg_size" => {
                let v = arg!(0);
                let p = self.peer(&v)?;
                V::Int(seg_size(&p.p.borrow()))
            }
            "wire" | "wire_len" => {
                let b = match arg!(0) {
                    V::Seg(s) => s.seg.marshal(),
                    V::Ip(p) => p.p.marshal(),
                    _ => return self.failf(format!("{name} takes a segment or a packet")),
                };
                if name == "wire" {
                    V::Bytes(b)
                } else {
                    V::Int(len64(b.len()))
                }
            }
            "udp" => {
                let a = arg!(0);
                let src = self.addr_port(&a)?;
                let a = arg!(1);
                let dst = self.addr_port(&a)?;
                let a = arg!(2);
                let id = trunc16(self.int(&a)?);
                let a = arg!(3);
                let b = self.bytes(&a)?;
                V::Ip(Rc::new(IpV {
                    p: ip::udp_packet(src, dst, id, &b),
                    ok: true,
                    at: ZERO_TIME,
                }))
            }
            "icmp" => {
                let mut ints = [0i64; 4];
                let a = arg!(3);
                ints[0] = self.int(&a)?;
                let a = arg!(4);
                ints[1] = self.int(&a)?;
                let a = arg!(5);
                ints[2] = self.int(&a)?;
                let a = arg!(6);
                let body = self.bytes(&a)?;
                let m = Icmp {
                    typ: trunc8(ints[0]),
                    code: trunc8(ints[1]),
                    rest: trunc32(ints[2]),
                    body,
                };
                let a = arg!(0);
                let src = self.addr(&a)?;
                let a = arg!(1);
                let dst = self.addr(&a)?;
                let a = arg!(2);
                let id = trunc16(self.int(&a)?);
                V::Ip(Rc::new(IpV {
                    p: ip::icmp_packet(src, dst, id, &m),
                    ok: true,
                    at: ZERO_TIME,
                }))
            }
            "fragments" => {
                if n < 1 {
                    return self.failf("fragments takes a packet and cuts");
                }
                let a = arg!(0);
                let p = self.ip(&a)?;
                let mut cuts = Vec::new();
                let mut prev = 0i64;
                for i in 1..n {
                    let c = arg!(i);
                    let c = self.int(&c)?;
                    if c % 8 != 0 || c <= prev || c >= len64(p.p.payload.len()) {
                        return self.failf(format!(
                            "fragments: cut {c} is not a multiple of 8 between {prev} and {}",
                            p.p.payload.len()
                        ));
                    }
                    cuts.push(usize::try_from(c).unwrap_or(0));
                    prev = c;
                }
                ip_list(ip::fragments(&p.p, &cuts))
            }
            "fragments_every" => {
                let a = arg!(0);
                let p = self.ip(&a)?;
                let s = arg!(1);
                let step = self.int(&s)?;
                if step <= 0 || step % 8 != 0 {
                    return self.failf("fragments_every takes a positive multiple of 8");
                }
                let step = usize::try_from(step).unwrap_or(8);
                let cuts: Vec<usize> = (step..p.p.payload.len()).step_by(step).collect();
                ip_list(ip::fragments(&p.p, &cuts))
            }
            "frag" => {
                let a = arg!(0);
                let p = self.ip(&a)?;
                let f = arg!(1);
                let from = self.int(&f)?;
                let t = arg!(2);
                let to = self.int(&t)?;
                if from < 0 || to < from || to > len64(p.p.payload.len()) || from % 8 != 0 {
                    return self.failf(format!(
                        "frag [{from}:{to}] out of range of {}, or not at a multiple of 8",
                        p.p.payload.len()
                    ));
                }
                let fr = ip::frag(
                    &p.p,
                    usize::try_from(from).unwrap_or(0),
                    usize::try_from(to).unwrap_or(0),
                );
                V::Ip(Rc::new(IpV {
                    p: fr,
                    ok: true,
                    at: ZERO_TIME,
                }))
            }
            "frag_needed" => {
                let a = arg!(0);
                let from = self.addr(&a)?;
                let b = arg!(1);
                let orig = self.bytes(&b)?;
                let m = arg!(2);
                let mtu = trunc16(self.int(&m)?);
                if orig.len() < 20 {
                    return self.failf(format!("frag_needed: a packet of {} bytes", orig.len()));
                }
                V::Bytes(packet::frag_needed(from, &orig, mtu))
            }
            "corrupt" | "set_bytes" => {
                let a = arg!(0);
                let mut p = self.ip(&a)?.p.clone();
                let o = arg!(1);
                let off = self.int(&o)?;
                if name == "corrupt" {
                    let Some(i) = usize::try_from(off).ok().filter(|i| *i < p.payload.len()) else {
                        return self.failf(format!(
                            "corrupt at {off} out of range of {}",
                            p.payload.len()
                        ));
                    };
                    let x = arg!(2);
                    p.payload[i] ^= trunc8(self.int(&x)?);
                } else {
                    let x = arg!(2);
                    let b = self.bytes(&x)?;
                    let Some(i) = usize::try_from(off)
                        .ok()
                        .filter(|i| i + b.len() <= p.payload.len())
                    else {
                        return self.failf(format!(
                            "set_bytes at {off} out of range of {}",
                            p.payload.len()
                        ));
                    };
                    p.payload[i..i + b.len()].copy_from_slice(&b);
                }
                V::Ip(Rc::new(IpV {
                    p,
                    ok: true,
                    at: ZERO_TIME,
                }))
            }
            "to_peer" => {
                let a = arg!(0);
                V::Bool(to_peer(&self.ip(&a)?.p))
            }
            "icmp_type" => {
                let a = arg!(0);
                V::Int(ip::parse_icmp(&self.ip(&a)?.p).map_or(-1, |m| i64::from(m.typ)))
            }
            "parse_udp" => {
                let a = arg!(0);
                let r = ip::parse_udp(&self.ip(&a)?.p);
                V::Udp(Rc::new(match r {
                    Ok(u) => (u, None),
                    Err(e) => (ip::Udp::default(), Some(e)),
                }))
            }
            "parse_icmp" => {
                let a = arg!(0);
                let r = ip::parse_icmp(&self.ip(&a)?.p);
                V::Icmp(Rc::new(match r {
                    Ok(m) => (m, true),
                    Err(_) => (Icmp::default(), false),
                }))
            }
            "parse_quote" => {
                let a = arg!(0);
                let b = self.bytes(&a)?;
                V::Quote(Rc::new(match ip::parse_quote(&b) {
                    Some(q) => (q, true),
                    None => (ip::Quote::default(), false),
                }))
            }
            "reply_desc" => {
                let V::Udp(u) = arg!(1) else {
                    return self.failf("reply_desc takes the result of parse_udp");
                };
                let a = arg!(0);
                let ok = self.truth(&a)?;
                let w = arg!(2);
                let want = self.bytes(&w)?;
                let (u, err) = &*u;
                let d = if !ok {
                    "no reply".to_owned()
                } else if let Some(e) = err {
                    e.clone()
                } else if u.checksum == 0 {
                    "no checksum".to_owned()
                } else if u.payload != want {
                    format!("{} bytes, different", u.payload.len())
                } else {
                    "valid reply".to_owned()
                };
                V::Bytes(d.into_bytes())
            }
            "pmtu_desc" => {
                let a = arg!(0);
                let largest = self.int(&a)?;
                let d = if largest <= 1000 {
                    format!("applied: largest packet {largest} bytes")
                } else {
                    format!("ignored: largest packet {largest} bytes")
                };
                V::Bytes(d.into_bytes())
            }
            "seg_descs" => {
                let a = arg!(0);
                let l = self.list(&a)?;
                let mut descs = Vec::new();
                for x in l.iter() {
                    let s = self.seg(x)?;
                    descs.push(seg_desc(&s.seg, s.ok));
                }
                V::Bytes(format!("[{}]", descs.join(" ")).into_bytes())
            }
            "seconds_text" => {
                let a = arg!(0);
                let d = self.dur(&a)?;
                let p = arg!(1);
                let prec = self.int(&p)?;
                #[expect(clippy::cast_precision_loss, reason = "Go's Duration.Seconds")]
                let secs = (d / SECOND) as f64 + (d % SECOND) as f64 / 1e9;
                V::Bytes(gofmt::float_f(secs, prec).into_bytes())
            }
            _ => return self.failf(format!("unknown function {name}")),
        })
    }
}

fn ip_list(ps: Vec<Ipv4>) -> V {
    V::list(
        ps.into_iter()
            .map(|p| {
                V::Ip(Rc::new(IpV {
                    p,
                    ok: true,
                    at: ZERO_TIME,
                }))
            })
            .collect(),
    )
}
