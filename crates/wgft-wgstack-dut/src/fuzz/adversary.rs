//! `adversarial_sender` の target:Go の `FuzzAdversarialSender` (`runAudit`) の写しです。
//!
//! 嘘の ACK、SACK、D-SACK、timestamp、窓、ICMP、SACK の取り消しを混ぜた相手に stream を送らせ、出力が回り
//! 続けず、送った byte が書いた stream と同じで、相手が stream と FIN を受け取り、各段で不変条件と保持の上界が
//! 守られることを確かめます。決まった数の段の後、相手は正直になります。
//!
//! Go と違う点:
//!
//! - Go は各段で接続の送り手の内部の欄を確かめます。SND.UNA ≤ SND.NXT ≤ SND.MAX、cwnd が 0 でないこと、
//!   pipe ≤ 2 × flight + 1、scoreboard の数え直し (再送した byte、SACK 済み、その先の欄)、損失の列と再送の
//!   位置の範囲、list のつながり、損失の列と再送の途中の位置 (`qMid` と `qOff`、`rxtMid` と `rxtOff`) です。
//!   核の `check_invariants` は使っている接続ごとに送り手の確かめ (`check_sender`) を行い、この送り手の欄の
//!   確かめと Go の `checkScoreboard` を写します。この target は各段の後に `check_invariants` を呼ぶので、Go と同じ確かめを
//!   各段で受けます。加えて外から見える出力を確かめます。DUT の data は書いた byte の範囲の中にあり、中身は
//!   stream と同じで、FIN は stream の終わりにあることです
//! - 嘘の SACK の block の範囲と ICMP の引く番号は、Go は DUT の SND.UNA と SND.MAX から取ります。ここでは
//!   相手が知る値 (累積の確認と、見た DUT の segment の最も先の番号) から取ります
//! - Go の boost の切り替え (`tryBoost` と `demote` を試験が直接呼ぶ) は frame に無い内部の操作です。ここでは
//!   hook が floor に戻ることを許すかを切り替えます。核が boost を持たない段では効きません
//! - Go は書ける量があるときだけ書く量を乱数で決めます。ここでは毎回決めて書き、`WouldBlock` を受け入れます。
//!   乱数を引く回数が Go と違うので、同じ番号の種でも Go と同じ相手の列にはなりません
//! - ICMP の frag-needed の MTU は、相手が覚えた値から送るたびに 1 から 100 下げます。DUT が受け入れたかを
//!   見ないので、値は下がり続け、600 以下で送るのを止めます
//! - 核がまだ持たない輻輳の制御と boost の方針 (設定の誤りになる選択) は、持つ方に替えます
//! - 表の大きさは Go と同じ `small_limits` ですが、相手が触れない UDP の datagram の表だけを `fuzz_limits` と
//!   同じ小ささにします。各段の不変条件の検査が datagram の表をすべてたどるためです
//! - stream の長さは `2000 + (seed × 7919 mod 2^64) mod 200000` です。Go の元の式は積を符号つきの int に
//!   してから剰余を取ったので、積が 2^63 以上の種では長さが負になり、`make` が panic しました。Go の
//!   `adversaryCfg` も同じ符号なしの剰余に直したので、2 つは同じ長さを返します。積が 2^63 より小さい種
//!   (Go の試験と記録が使う範囲) では、元の式と同じ値です

use std::cell::Cell;
use std::net::SocketAddrV4;
use std::rc::Rc;
use std::time::Duration;

use wgft_tcpharness::packet::{self, ACK, FIN, RST, SYN, SackBlock, Segment};
use wgft_tcpharness::rng::Pcg;
use wgft_wgstack::{BoostPolicy, Config, Congestion, ConnId, Error, Event, Hook, Limits};

use super::net::{DUT, MTU, Net, PEER, fuzz_limits, small_limits};
use super::peer::{PeerConn, SackPeer, seq_gt};

/// 相手のポートです。
const PEER_PORT: u16 = 40000;
/// 正直になった後に進める段の数です。Go と同じです。
const HONEST_STEPS: usize = 40_000;

/// 種から決める相手の振る舞いの組み合わせです。Go の `auditCfg` と `adversaryCfg` です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per adversarial behaviour, as in the Go auditCfg"
)]
pub struct AdversaryCfg {
    pub seed: u64,
    pub ts: bool,
    pub sack: bool,
    pub ws: bool,
    pub close_write: bool,
    pub length: usize,
    pub adv_steps: usize,
    pub lie_ts: bool,
    pub lie_dsack: bool,
    pub icmp: bool,
    pub zero_wnd: bool,
    pub peer_data: bool,
    pub boost_flip: bool,
    pub newreno: bool,
}

impl AdversaryCfg {
    /// Go の `adversaryCfg` です。
    pub fn from_seed(seed: u64) -> Self {
        let len = 2000 + seed.wrapping_mul(7919) % 200_000;
        Self {
            seed,
            ts: seed.is_multiple_of(2),
            sack: !seed.is_multiple_of(3),
            ws: !seed.is_multiple_of(5),
            close_write: seed % 2 == 1 || seed % 3 == 2 || seed % 5 == 1,
            length: usize::try_from(len).expect("below 202000"),
            adv_steps: 2000 + usize::try_from(seed % 5).expect("small") * 1000,
            lie_ts: seed.is_multiple_of(4),
            lie_dsack: seed % 3 == 1,
            icmp: seed.is_multiple_of(2),
            zero_wnd: seed.is_multiple_of(7),
            peer_data: seed % 3 == 2 || seed % 5 == 1,
            boost_flip: seed % 4 == 1,
            newreno: seed % 6 == 5,
        }
    }
}

/// floor に戻ることを許すかを試験が切り替える hook です。
#[derive(Debug, Clone)]
struct FlipHook(Rc<Cell<bool>>);

impl Hook for FlipHook {
    fn may_return(&mut self, _conn: ConnId) -> bool {
        self.0.get()
    }
}

/// 核がこの選択を持つかです。持たない段の核は設定の誤りにします。誤りの種類の名前は段で変わるので見ません。
fn supported(c: Config) -> bool {
    c.validate().is_ok()
}

/// `adversarial_sender` の target の 1 回分です。入力の先頭の 8 byte を little endian の種として読みます
/// (短ければ 0 で埋めます)。Go の corpus の `uint64` の値は同じ 8 byte になります。
pub fn adversarial_sender(data: &[u8]) {
    let mut b = [0u8; 8];
    let k = data.len().min(8);
    b[..k].copy_from_slice(&data[..k]);
    adversarial_sender_seed(u64::from_le_bytes(b));
}

/// 種 `seed` の相手で 1 回流します。
pub fn adversarial_sender_seed(seed: u64) {
    run(&AdversaryCfg::from_seed(seed));
}

fn int_n(rng: &mut Pcg, n: usize) -> usize {
    usize::try_from(rng.int_n(n as u64)).expect("below n")
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).expect("below 4 GiB")
}

#[expect(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "one loop that mirrors the Go runAudit switch case by case, with its names"
)]
fn run(cfg: &AdversaryCfg) {
    let seed = cfg.seed;
    let mut rng = Pcg::new(seed, seed.wrapping_mul(7).wrapping_add(1));
    // UDP の datagram の表だけを小さくします (module の説明)。TCP の出力は UDP の表の大きさに依りません。
    let base_cfg = Net::<FlipHook>::config(Limits {
        udp_rx_datagrams: fuzz_limits().udp_rx_datagrams,
        udp_tx_datagrams: fuzz_limits().udp_tx_datagrams,
        ..small_limits()
    });
    let cubic = supported(Config {
        congestion: Congestion::Cubic,
        ..base_cfg
    });
    let on_demand = supported(Config {
        boost: BoostPolicy::OnDemand,
        ..base_cfg
    });
    let config = Config {
        congestion: if cfg.newreno || !cubic {
            Congestion::NewReno
        } else {
            Congestion::Cubic
        },
        boost: if on_demand {
            BoostPolicy::OnDemand
        } else {
            BoostPolicy::Never
        },
        ..base_cfg
    };
    let may_return = Rc::new(Cell::new(true));
    let mut n = Net::new(config, FlipHook(may_return.clone()));
    let now = n.now();
    let l = n
        .stack()
        .listen_tcp(now, SocketAddrV4::new(DUT, 80))
        .expect("listen on port 80");

    // 握手。Go の testNet.handshake と同じく、相手の ISN は 1000、timestamp は 5000 から
    let (p, sa) = PeerConn::connect(
        &mut n,
        PEER_PORT,
        80,
        if cfg.ws { 7 } else { -1 },
        cfg.sack,
        cfg.ts,
    );
    let sack_ok = sa.opts.sack_permitted;
    let now = n.now();
    let (c, _) = n.stack().accept(now, l).expect("accept the handshake");
    let base = p.rcv;
    let mut q = SackPeer::new(p);

    let stream: Vec<u8> = (0..cfg.length)
        .map(|_| rng.uint32().to_le_bytes()[0])
        .collect();
    let mut written = 0usize;
    let mut closed = false;
    let mut netq: Vec<Segment> = Vec::new();
    // 相手が見た DUT の segment の最も先の番号と、最後に見た data の segment (ICMP が引く)
    let mut hi = base;
    let mut last_data: Option<Segment> = None;
    let mut pmtu = MTU;
    let mut honest = false;
    let mut peer_fin = false;
    let mut ooo_end = 0u32;
    let mut have_ooo = false;
    let mut rbuf = vec![0u8; 8192];
    let steps = cfg.adv_steps + HONEST_STEPS;
    let mut last_step = 0;
    // 接続のプロトコルが終わった (Event::Closed) か。終わった後も handle は枠を持ちうる
    let mut ended = false;
    for step in 0..steps {
        last_step = step;
        if step == cfg.adv_steps {
            honest = true;
            q.p.wnd = 65535;
        }
        ended |= closed_event(&mut n, c);
        let held = n.stack().local_addr(c).is_some();
        let alive = held && !ended;
        let got = q.p.rcv.wrapping_sub(base);
        if closed && got == len32(stream.len()) + 1 && (honest || !alive) {
            break;
        }
        if !held {
            // 枠を離れた。stream を届け終えた時だけ通る (最後の確かめ)
            break;
        }
        let r = int_n(&mut rng, 100);
        let now = n.now();
        if r < 15 {
            if written < stream.len() {
                let mut k = (1 + int_n(&mut rng, 30000)).min(stream.len() - written);
                if int_n(&mut rng, 4) == 0 {
                    k = k.min(1 + int_n(&mut rng, 40));
                }
                match n.stack().write(now, c, &stream[written..written + k]) {
                    Ok(m) => written += m,
                    Err(Error::WouldBlock) => {}
                    Err(e) => panic!("seed {seed} step {step}: write: {e}"),
                }
            } else if !closed && (honest || int_n(&mut rng, 20) == 0) {
                closed = true;
                if cfg.close_write {
                    n.stack()
                        .close_write(now, c)
                        .unwrap_or_else(|e| panic!("seed {seed}: close_write: {e}"));
                } else {
                    n.stack().close_conn(now, c);
                }
            }
        } else if r < 35 {
            for o in n.drain() {
                if o.dst.port() != PEER_PORT {
                    continue;
                }
                assert!(
                    !(o.has(RST) && alive),
                    "seed {seed} step {step}: DUT sent RST {o} peer_fin {peer_fin} closed {closed} stats {:?}",
                    n.stack().stats()
                );
                check_bytes(seed, step, &o, base, &stream[..written], closed);
                let end = o.seq.wrapping_add(o.seq_len() - u32::from(o.has(SYN)));
                if seq_gt(end, hi) {
                    hi = end;
                }
                if !o.payload.is_empty() {
                    last_data = Some(o.clone());
                }
                if !honest && int_n(&mut rng, 100) < 10 {
                    continue;
                }
                if !honest && int_n(&mut rng, 30) == 0 {
                    netq.push(o.clone());
                }
                netq.push(o);
            }
        } else if r < 60 {
            if netq.is_empty() {
                // Go と同じく、届けるものが無ければ何もしない
            } else {
                let i = if int_n(&mut rng, 4) == 0 {
                    int_n(&mut rng, netq.len())
                } else {
                    0
                };
                let o = netq.remove(i);
                q.recv(&o);
                if honest || int_n(&mut rng, 10) != 0 {
                    let s = q.ack();
                    n.inject(&s);
                }
            }
        } else if r < 70 && !honest {
            // 嘘の ACK。相手が持つ所より先は確認しない
            let mut s = q.p.seg(ACK, Vec::new());
            s.ack = q.p.rcv.wrapping_sub(len32(int_n(&mut rng, 3000)));
            s.window = if cfg.zero_wnd && int_n(&mut rng, 3) == 0 {
                0
            } else {
                u16::try_from(int_n(&mut rng, 65536)).expect("below 65536")
            };
            if cfg.lie_ts && int_n(&mut rng, 2) == 0 {
                let dut_ts = q.p.dut_ts;
                let lie = len32(int_n(&mut rng, 1 << 20));
                if let Some(ts) = s.opts.ts.as_mut() {
                    ts.ecr = dut_ts.wrapping_sub(lie);
                }
            }
            let una = q.p.rcv;
            let span =
                usize::try_from(hi.wrapping_sub(una).cast_signed().max(0)).expect("positive");
            while s.opts.sack.len() < 3 && int_n(&mut rng, 2) == 0 {
                let mut a = una.wrapping_add(len32(int_n(&mut rng, span + 1)));
                let rest =
                    usize::try_from(hi.wrapping_sub(a).cast_signed().max(0)).expect("positive");
                let mut b = a.wrapping_add(len32(int_n(&mut rng, rest + 1)));
                if cfg.lie_dsack && int_n(&mut rng, 3) == 0 {
                    a = una.wrapping_sub(len32(int_n(&mut rng, 5000)));
                    b = a.wrapping_add(1 + len32(int_n(&mut rng, 3000)));
                }
                s.opts.sack.push(SackBlock { left: a, right: b });
            }
            n.inject(&s);
        } else if r < 74 && !honest && cfg.icmp {
            // DUT の segment を引く ICMP の frag-needed
            let una = q.p.rcv;
            if let Some(d) = last_data.as_ref()
                && seq_gt(hi, una)
                && pmtu > 600
            {
                let span = usize::try_from(hi.wrapping_sub(una)).expect("positive");
                let mut quoted = d.clone();
                quoted.seq = una.wrapping_add(len32(int_n(&mut rng, span)));
                pmtu = pmtu - 1 - int_n(&mut rng, 100);
                let mtu = u16::try_from(pmtu).expect("below the MTU");
                n.write(&packet::frag_needed(PEER, &quoted.marshal(), mtu));
            }
        } else if r < 76 && cfg.close_write && !peer_fin && int_n(&mut rng, 8) == 0 {
            peer_fin = true;
            if have_ooo && seq_gt(ooo_end, q.p.snd) {
                let fill = ooo_end.wrapping_sub(q.p.snd);
                let s = q.p.ack(vec![0; fill as usize]);
                n.inject(&s);
            }
            let s = q.p.fin();
            n.inject(&s);
        } else if r < 78 && cfg.peer_data {
            if !peer_fin && (!closed || cfg.close_write) {
                let s = q.p.ack(vec![0; 1 + int_n(&mut rng, 1300)]);
                n.inject(&s);
            }
        } else if r < 79 && cfg.peer_data && !peer_fin {
            // 順序外の相手の data。DUT の segment に SACK の block を持たせる
            let mut sg = q.p.seg(ACK, vec![0; 1 + int_n(&mut rng, 200)]);
            sg.seq = sg.seq.wrapping_add(1 + len32(int_n(&mut rng, 3000)));
            n.inject(&sg);
            let e = sg.seq.wrapping_add(len32(sg.payload.len()));
            if !have_ooo || seq_gt(e, ooo_end) {
                ooo_end = e;
                have_ooo = true;
            }
        } else if r < 80 && cfg.peer_data {
            match n.stack().read(now, c, &mut rbuf) {
                Ok(_) | Err(Error::WouldBlock) => {}
                Err(e) => panic!("seed {seed} step {step}: read: {e}"),
            }
        } else if r < 82 && cfg.boost_flip {
            may_return.set(!may_return.get());
        } else if r < 84 && !honest && sack_ok {
            // SACK の取り消し
            q.renege();
            let s = q.ack();
            n.inject(&s);
        } else {
            let ms = if int_n(&mut rng, 20) == 0 {
                int_n(&mut rng, 3000)
            } else {
                1 + int_n(&mut rng, 60)
            };
            n.advance(Duration::from_millis(ms as u64));
        }
        n.check();
    }
    n.check();
    let faults = n.stack().stats().accounting_faults;
    assert_eq!(faults, 0, "seed {seed}: accounting faults");
    let got = q.p.rcv.wrapping_sub(base);
    assert_eq!(
        got,
        len32(stream.len()) + 1,
        "seed {seed}: peer got {got} of {} (+FIN); written {written} closed {closed} step {last_step} stats {:?} held {:?}",
        stream.len(),
        n.stack().stats(),
        n.held()
    );
    n.finish();
}

/// 接続 `c` の `Event::Closed` が来たかを、たまった知らせを読み捨てながら返します。
fn closed_event<H: Hook>(n: &mut Net<H>, c: ConnId) -> bool {
    let mut seen = false;
    while let Some(e) = n.stack().poll_event() {
        seen |= e == Event::Closed(c);
    }
    seen
}

/// DUT の segment の data が書いた stream の範囲にあって中身が同じで、FIN が stream の終わりにあることを
/// 確かめます。
fn check_bytes(seed: u64, step: usize, o: &Segment, base: u32, written: &[u8], closed: bool) {
    if o.has(SYN) {
        return;
    }
    let off = o.seq.wrapping_sub(base).cast_signed();
    if !o.payload.is_empty() && off >= 0 {
        let off = usize::try_from(off).expect("positive");
        assert!(
            off + o.payload.len() <= written.len()
                && o.payload == written[off..off + o.payload.len()],
            "seed {seed} step {step}: wrong bytes at {off} len {} with {} written",
            o.payload.len(),
            written.len()
        );
    }
    if o.has(FIN) {
        let end = o.seq.wrapping_add(len32(o.payload.len()));
        assert!(
            closed && end == base.wrapping_add(len32(written.len())),
            "seed {seed} step {step}: FIN at {} with {} written, closed {closed}",
            end.wrapping_sub(base),
            written.len()
        );
    }
}
