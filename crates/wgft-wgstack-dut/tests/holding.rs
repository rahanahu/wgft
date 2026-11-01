//! 敵対的な保持の試験です (`docs/design/userspace/wgstack-verification.md` の「敵対的な保持の試験」の表、
//! `docs/design/v2/wgstack-rs.md` の「上界と敵対的な保持の試験」)。
//!
//! 入力ごとに 1 つの試験で、核の公開の API だけを使います。保持は設定の上限でなく、実際に持つ量で確かめます。
//!
//! - 確保の数え (`wgft-alloc-count`):核を作った後に増えた生きている byte が、`Held` の文書の式の値に
//!   ちょうど一致すること。式は会計の chunk、送信の記録、区間の表、再組み立ての写し、UDP の chunk、置き場の
//!   chunk の和から、借りている boost の配列 (`Budget` が先に確保したもの) を引いた値です。核を閉じた後に、
//!   核を作る前の値へ戻ること。生きている byte と最大値が上界 (`Bound`) の内にあること
//! - 会計:表の行の数が表の大きさの内にあり、入力ごとの項 (接続の枠の floor の項など) を超えないこと
//! - 入力ごとの確かめ:洪水の間に保持が増えないこと、上限で捨てた数が数えられること、入力が止まった後に
//!   表が空に戻ること
//!
//! 確保の数えはプロセスで 1 つなので、試験は 1 つずつ順に流します (`--test-threads` は 1 に固定します)。
//! 試験の側の確保が数えに混ざらないように、試験の集まりは測る前に容量を取り、確かめは出力の列を捨てた後に
//! します。
//!
//! 試す入力は、TCP の受動の open とデータの経路、SACK と boost、断片と UDP です。

#![expect(
    clippy::many_single_char_names,
    reason = "h, l, c, p and s name the stack, listener, connection, peer and segment in every input"
)]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use libtest_mimic::{Arguments, Failed, Trial};
use wgft_alloc_count::{CountingAlloc, live_bytes, peak_bytes, reset_peak};
use wgft_tcpharness::ip;
use wgft_tcpharness::packet::{ACK, FIN, Options, RST, SYN, SackBlock, Segment};
use wgft_wgstack::{BoostPolicy, Config, ConnId, Error, Held, Limits, ListenerId, NoHook, UdpId};
use wgft_wgstack_dut::fuzz::{DUT, Net, PEER, PeerConn, small_limits};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// 試験の側の一時の確保 (出力の列、組み立てた packet) の上限です。最大値の確かめだけに足します。
const TEST_SLACK: usize = 1 << 20;

/// 核と、確保の数えの起点です。
struct Hold {
    n: Net<NoHook>,
    limits: Limits,
    /// 核を作る前の生きている byte
    base: usize,
    /// 核を作った直後の生きている byte
    created: usize,
}

impl Hold {
    fn new(limits: Limits) -> Self {
        Self::with(Net::<NoHook>::config(limits))
    }

    fn with(config: Config) -> Self {
        let limits = config.limits;
        // Budget はスレッドごとに 1 つ作って使い回すので、測る前にこのスレッドで作っておく
        Net::new(config, NoHook).finish();
        let base = live_bytes();
        reset_peak();
        let n = Net::new(config, NoHook);
        let created = live_bytes();
        Self {
            n,
            limits,
            base,
            created,
        }
    }

    /// 核を作った後に増えた生きている byte です。
    fn growth(&self) -> usize {
        live_bytes()
            .checked_sub(self.created)
            .expect("the live bytes fell below their value right after the stack was made")
    }

    /// 接続の枠 1 つの floor の項 (f_s + f_r + r_f + h_f) です。
    fn per_conn(&self) -> u64 {
        self.n.bound().floor_conn / self.limits.conns() as u64
    }

    fn held(&self) -> Held {
        self.n.held()
    }

    /// 不変条件と表の大きさ (`Net::check`) に加えて、確保の数えが会計と一致し、上界の内にあることを確かめます。
    fn check(&mut self, what: &str) {
        self.n.check();
        let h = self.held();
        let g = self.growth();
        // `Held` の文書の式:借りている boost の配列は Budget が先に確保したものなので引く
        let counted = (h.chunk_bytes
            + h.record_bytes
            + h.interval_bytes
            + h.frag_bytes
            + h.udp_rx_bytes
            + h.udp_tx_bytes
            + h.pool_bytes)
            .checked_sub(h.lent_array_bytes)
            .unwrap_or_else(|| panic!("{what}: the lent arrays exceed the accounted bytes: {h:?}"));
        assert_eq!(
            g, counted,
            "{what}: the stack grew {g} bytes but accounts for {counted}: {h:?}"
        );
        let total = self.n.bound().total;
        let live = (live_bytes() - self.base) as u64;
        assert!(
            live <= total,
            "{what}: {live} live bytes over the bound {total}"
        );
    }

    /// 核を閉じ、生きている byte が核を作る前の値へ戻ることと、最大値が上界の内にあったことを確かめます。
    fn finish(self) {
        let bound = self.n.bound();
        let base = self.base;
        self.n.finish();
        assert_eq!(live_bytes(), base, "closing returns every allocation");
        let peak = (peak_bytes() - base) as u64;
        assert!(
            peak <= bound.total + bound.transient + TEST_SLACK as u64,
            "the peak {peak} exceeds the bound {} with the transient {}",
            bound.total,
            bound.transient
        );
    }

    fn now(&self) -> wgft_wgstack::Time {
        self.n.now()
    }

    fn listen(&mut self, port: u16) -> ListenerId {
        let now = self.now();
        self.n
            .stack()
            .listen_tcp(now, SocketAddrV4::new(DUT, port))
            .expect("listen")
    }

    /// 相手のポート `sport` から接続を開き、受け取ります。窓の scale は 7 で、SACK と timestamp は求めません。
    fn establish(&mut self, l: ListenerId, sport: u16) -> (ConnId, PeerConn) {
        let (p, _) = PeerConn::connect(&mut self.n, sport, l.port(), 7, false, false);
        let now = self.now();
        let (c, _) = self.n.stack().accept(now, l).expect("accept");
        (c, p)
    }

    /// 書けなくなるまで書き、書いた byte 数を返します。
    fn fill(&mut self, c: ConnId) -> usize {
        let data = [0x5au8; 4096];
        let mut total = 0;
        loop {
            let now = self.now();
            match self.n.stack().write(now, c, &data) {
                Ok(k) => total += k,
                Err(Error::WouldBlock) => return total,
                Err(e) => panic!("write: {e}"),
            }
        }
    }

    fn drop_output(&mut self) {
        drop(self.n.drain());
    }

    fn advance(&mut self, d: Duration) {
        self.n.advance(d);
    }
}

/// どの接続にも当たらない、偽の送信元の segment です。
fn spoofed(i: u32, flags: u8) -> Segment {
    let [a, b, c, d] = i.to_be_bytes();
    Segment {
        src: SocketAddrV4::new(
            Ipv4Addr::new(172, 16 + (a & 0x0f) + (b >> 4), c, d.max(1)),
            1024 + (i % 60000) as u16,
        ),
        dst: SocketAddrV4::new(DUT, 80),
        seq: i.wrapping_mul(2_654_435_761),
        ack: i,
        flags,
        window: 65535,
        opts: Options {
            mss: (flags & SYN != 0).then_some(1380),
            ..Options::none()
        },
        ..Segment::default()
    }
}

/// 偽の送信元からの SYN の洪水:握手の途中の表が止まり、接続の枠とバッファを使いません。待ち受け 1 つの行は
/// 表の全体の半分までです (`Limits` の約束)。表が満ちた後の SYN には、行を作らずに SYN cookie で応えます。
fn syn_flood() {
    let mut h = Hold::new(small_limits());
    let _l = h.listen(80);
    for i in 0..20_000u32 {
        h.n.inject(&spoofed(i, SYN));
        if i % 500 == 0 {
            h.drop_output();
            h.check("syn flood");
            let held = h.held();
            assert!(
                held.conns == 0 && held.chunk_bytes == 0,
                "SYNs took a slot: {held:?}"
            );
            assert_eq!(h.growth(), 0, "SYNs allocated");
        }
    }
    assert_eq!(
        h.held().syn_rows,
        h.limits.syn_rows / 2,
        "the listener's share of the table is full"
    );
    assert!(
        h.n.stack().stats().syn_cookies_sent > 0,
        "the SYNs past the table are answered with cookies and counted"
    );
    for _ in 0..300 {
        h.advance(Duration::from_secs(1));
        h.drop_output();
    }
    h.check("after the flood");
    assert_eq!(h.held().syn_rows, 0, "the rows expire after the flood");
    h.finish();
}

/// 握手を終えたまま `accept` されない接続:accept の待ち行列が待ち受けごとの上限 (Q の半分) で止まり、超えた
/// 最後の ACK を捨てます。
fn accept_backlog() {
    let mut taken = Vec::with_capacity(small_limits().conns());
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let mut done = 0;
    for i in 0..200u16 {
        if PeerConn::try_connect(&mut h.n, 2000 + i, 80, 7, false, false).is_some() {
            done += 1;
        }
        h.check("handshakes");
        let held = h.held();
        assert!(held.accept_queued <= h.limits.accept_queue / 2, "{held:?}");
        let floor = (held.record_bytes + held.interval_bytes) as u64;
        assert!(
            floor <= held.conns as u64 * h.per_conn(),
            "the queued connections hold {floor} bytes over {} slots of {}",
            held.conns,
            h.per_conn()
        );
    }
    assert!(done > 0, "no handshake completed");
    let st = h.n.stack().stats();
    assert!(
        st.accept_overflow + st.syn_table_full > 0,
        "the overflow is counted: {st:?}"
    );
    loop {
        let now = h.now();
        match h.n.stack().accept(now, l) {
            Ok((c, _)) => taken.push(c),
            Err(Error::WouldBlock) => break,
            Err(e) => panic!("accept: {e}"),
        }
    }
    assert!(
        taken.len() <= h.limits.accept_queue / 2,
        "accepted {} from a listener's queue of {}",
        taken.len(),
        h.limits.accept_queue / 2
    );
    for c in taken.drain(..) {
        let now = h.now();
        h.n.stack().abort(now, c);
    }
    let now = h.now();
    h.n.stack().close_listener(now, l);
    for _ in 0..120 {
        h.advance(Duration::from_secs(1));
        h.drop_output();
    }
    h.check("after the backlog");
    let held = h.held();
    assert!(
        held.conns == 0 && held.accept_queued == 0 && held.syn_rows == 0,
        "{held:?}"
    );
    h.finish();
    drop(taken);
}

/// 短い接続の入れ替わり:TIME_WAIT の表が M で止まり、追い出した数が数えられます。
fn time_wait_churn() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    for i in 0..2000u16 {
        let (c, mut p) = h.establish(l, 5000 + i);
        // DUT が先に閉じ、相手が FIN の確認と自分の FIN を返すと、DUT の接続は TIME_WAIT に移ります
        let now = h.now();
        h.n.stack().close_conn(now, c);
        for o in h.n.drain() {
            p.absorb(&o);
        }
        let s = p.seg(ACK | FIN, Vec::new());
        h.n.inject(&s);
        h.drop_output();
        if i % 100 == 0 {
            h.check("churn");
        }
        assert!(h.held().tw_rows <= h.limits.tw_rows, "{:?}", h.held());
    }
    h.check("after the churn");
    assert_eq!(h.held().tw_rows, h.limits.tw_rows, "the table is full");
    assert!(
        h.n.stack().stats().tw_evicted > 0,
        "the evicted rows are counted"
    );
    for _ in 0..120 {
        h.advance(Duration::from_secs(1));
        h.drop_output();
    }
    h.check("after TIME_WAIT");
    let held = h.held();
    assert!(held.tw_rows == 0 && held.conns == 0, "{held:?}");
    h.finish();
}

/// 中身の無い segment の洪水:重複した ACK と、累積の確認を 1 byte ずつ進める ACK です。処理待ちが生まれず、
/// 送り残しの多い接続でも保持が増えません。
fn empty_ack_flood() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let (c, mut p) = h.establish(l, 40000);
    h.fill(c);
    h.drop_output();
    h.check("filled");
    let before = h.growth();
    let una = p.rcv;
    for i in 0..20_000u32 {
        // 前半は重複した ACK、後半は 1 byte ずつ進む ACK
        let mut s = p.seg(ACK, Vec::new());
        s.ack = if i < 10_000 {
            una
        } else {
            una.wrapping_add(i - 9_999)
        };
        h.n.inject(&s);
        if i % 100 == 0 {
            h.drop_output();
            h.check("ack flood");
            assert!(
                h.growth() <= before,
                "the flood grew the stack from {before} to {}",
                h.growth()
            );
        }
    }
    let now = h.now();
    h.n.stack().abort(now, c);
    h.drop_output();
    h.check("after the flood");
    h.finish();
}

/// 順序外の洪水:多数の穴を作る小さな segment です。順序外の保持が受信の予約の内に留まり、区間の数の上限で
/// 捨てた segment が数えられます。
fn ooo_flood() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let (c, mut p) = h.establish(l, 40000);
    h.check("established");
    let tables = h.held().interval_bytes;
    let start = p.snd;
    for i in 0..5000u32 {
        let mut s = p.seg(ACK, vec![0xa5]);
        s.seq = start.wrapping_add(2 + 2 * i);
        h.n.inject(&s);
        drop(s);
        if i % 100 == 0 {
            h.drop_output();
            h.check("ooo flood");
            let held = h.held();
            assert_eq!(held.interval_bytes, tables, "the interval table is fixed");
            assert!(held.chunk_bytes as u64 <= held.reserved, "{held:?}");
        }
    }
    assert!(
        h.n.stack().stats().ooo_dropped > 0,
        "the segments past the interval limit are counted"
    );
    let now = h.now();
    h.n.stack().abort(now, c);
    h.drop_output();
    h.check("after the flood");
    assert_eq!(
        h.held().chunk_bytes,
        0,
        "the aborted connection returns its chunks"
    );
    h.finish();
}

/// 読まない相手:送信の保持が送信の予約で止まり、窓の probe が続く間も増えません。
fn zero_window_peer() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let (c, mut p) = h.establish(l, 40000);
    p.wnd = 0;
    let s = p.ack(Vec::new());
    h.n.inject(&s);
    h.fill(c);
    h.drop_output();
    h.check("filled");
    let before = h.growth();
    let held = h.held();
    assert!(held.chunk_bytes as u64 <= held.reserved, "{held:?}");
    for _ in 0..600 {
        h.advance(Duration::from_secs(1));
        for o in h.n.drain() {
            p.absorb(&o);
        }
        // 窓の probe に 0 の窓で答える
        let s = p.ack(Vec::new());
        h.n.inject(&s);
        h.fill(c);
        h.check("probes");
        assert!(
            h.growth() <= before,
            "the probes grew the stack from {before} to {}",
            h.growth()
        );
    }
    let now = h.now();
    h.n.stack().abort(now, c);
    h.drop_output();
    h.check("after the probes");
    h.finish();
}

/// どの接続にも当たらない segment の洪水:制御の輪だけが埋まり、TCP の data は組の配分の分だけ進み続けます。
fn unmatched_flood() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let (c, mut p) = h.establish(l, 40000);
    let base = p.rcv;
    h.check("established");
    let before = h.growth();
    let mut i = 0u32;
    let mut last = 0;
    for round in 0..300 {
        h.fill(c);
        for _ in 0..100 {
            // ACK を持つ segment には RST が返る
            h.n.inject(&spoofed(i, ACK));
            i += 1;
        }
        let held = h.held();
        assert!(held.ctl_queued <= h.limits.ctl_slots, "{held:?}");
        for o in h.n.poll_some(8) {
            p.absorb(&o);
        }
        let s = p.ack(Vec::new());
        h.n.inject(&s);
        if round % 10 == 0 {
            h.check("unmatched flood");
            assert!(
                h.growth() <= before + h.held().chunk_bytes,
                "the flood grew the stack"
            );
        }
        // 洪水の間も、接続の data は 50 回の引き取りごとに進みます
        if round % 50 == 49 {
            let got = p.rcv.wrapping_sub(base);
            assert!(
                got > last,
                "round {round}: the data stopped at {got} bytes during the flood"
            );
            last = got;
        }
    }
    assert!(
        h.n.stack().stats().ctl_dropped > 0,
        "the control packets past the ring are counted"
    );
    let now = h.now();
    h.n.stack().abort(now, c);
    h.drop_output();
    h.check("after the flood");
    h.finish();
}

/// 遅い読み手への小さな書き込み:送信の記録の輪が容量で止まり、送信の輪の byte が予約を超えません。
fn small_writes_slow_reader() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let (c, mut p) = h.establish(l, 40000);
    h.check("established");
    let records = h.held().record_bytes;
    for round in 0..20_000 {
        let now = h.now();
        match h.n.stack().write(now, c, &[1]) {
            Ok(_) | Err(Error::WouldBlock) => {}
            Err(e) => panic!("write: {e}"),
        }
        if round % 10 == 0 {
            for o in h.n.drain() {
                p.absorb(&o);
            }
        }
        // 相手は 500 回に 1 回だけ確認し、窓は小さい
        if round % 500 == 0 {
            p.wnd = 16;
            let s = p.ack(Vec::new());
            h.n.inject(&s);
            h.advance(Duration::from_millis(200));
        }
        if round % 1000 == 0 {
            h.check("small writes");
            let held = h.held();
            assert_eq!(held.record_bytes, records, "the record ring is fixed");
            assert!(held.chunk_bytes as u64 <= held.reserved, "{held:?}");
        }
    }
    let now = h.now();
    h.n.stack().abort(now, c);
    h.drop_output();
    h.check("after the writes");
    h.finish();
}

/// 出力の詰まり:呼び手が出力を引き取らない間、保持が増えず、詰まりが解けた後に送り直しで回復します。
fn output_stall() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let (c, mut p) = h.establish(l, 40000);
    let base = p.rcv;
    let mut written = h.fill(c);
    h.check("filled");
    let before = h.growth();
    for _ in 0..100 {
        h.advance(Duration::from_millis(100));
        written += h.fill(c);
        h.check("stalled");
        assert!(
            h.growth() <= before,
            "the stall grew the stack from {before} to {}",
            h.growth()
        );
    }
    let now = h.now();
    h.n.stack().close_write(now, c).expect("close_write");
    for _ in 0..100_000 {
        for o in h.n.drain() {
            assert!(!o.has(RST), "the stall reset the connection");
            p.absorb(&o);
        }
        let s = p.ack(Vec::new());
        h.n.inject(&s);
        if p.rcv.wrapping_sub(base) as usize == written + 1 {
            break;
        }
        h.advance(Duration::from_millis(10));
    }
    assert_eq!(
        p.rcv.wrapping_sub(base) as usize,
        written + 1,
        "the stream and FIN arrive after the stall"
    );
    let now = h.now();
    h.n.stack().abort(now, c);
    h.drop_output();
    h.check("after the stall");
    h.finish();
}

/// SACK の block を持つ ACK の洪水:送り残しの多い接続に、飛んでいる範囲の中の嘘の SACK の block を持つ ACK
/// を送り続けても、保持が増えません。
fn sack_ack_flood() {
    let mut h = Hold::new(small_limits());
    let l = h.listen(80);
    let (p0, sa) = PeerConn::connect(&mut h.n, 40000, 80, 7, true, true);
    assert!(sa.opts.sack_permitted, "the stack agrees to SACK");
    let mut p = p0;
    let now = h.now();
    let (c, _) = h.n.stack().accept(now, l).expect("accept");
    // 先に data を確認して輻輳の窓を広げ、飛んでいる範囲を大きくする
    for _ in 0..20 {
        h.fill(c);
        for o in h.n.drain() {
            p.absorb(&o);
        }
        let s = p.ack(Vec::new());
        h.n.inject(&s);
        h.advance(Duration::from_millis(10));
    }
    h.fill(c);
    let mut hi = p.rcv;
    for o in h.n.drain() {
        hi = hi.max(
            o.seq
                .wrapping_add(u32::try_from(o.payload.len()).expect("below 4 GiB")),
        );
    }
    h.check("filled");
    let before = h.growth();
    let una = p.rcv;
    let span = hi.wrapping_sub(una).max(2);
    for i in 0..20_000u32 {
        let mut s = p.seg(ACK, Vec::new());
        s.ack = una;
        let a = una.wrapping_add(1 + (i.wrapping_mul(2_654_435_761) % (span - 1)));
        let b = a.wrapping_add(1 + i % 1400);
        s.opts.sack = vec![SackBlock { left: a, right: b }];
        h.n.inject(&s);
        drop(s);
        if i % 100 == 0 {
            h.drop_output();
            h.check("sack flood");
            assert!(
                h.growth() <= before,
                "the flood grew the stack from {before} to {}",
                h.growth()
            );
        }
    }
    let now = h.now();
    h.n.stack().abort(now, c);
    h.drop_output();
    h.check("after the flood");
    h.finish();
}

/// 需要の無いまま boost の枠を持つ接続:別の接続が枠を求めると、1 秒の間どちらの向きにも需要の無かった保有者は
/// 枠を返します (`docs/design/userspace/wgstack-buffers.md` の回収の条件)。確立の
/// 時刻も需要の時刻なので、確立から 1 秒の内の保有者は返しません。
fn idle_boost_holders() {
    let limits = Limits {
        max_flows: 64,
        accept_queue: 8,
        ..small_limits()
    };
    let config = Config {
        boost: BoostPolicy::AtAccept,
        ..Net::<NoHook>::config(limits)
    };
    let mut conns = Vec::with_capacity(limits.conns());
    let mut h = Hold::with(config);
    let slots = h.n.slots();
    assert!(
        slots + 4 <= limits.max_flows,
        "{slots} boost slots need more flows"
    );
    let l = h.listen(80);
    // すべての枠を同じ時刻に確立した保有者が持つ
    for i in 0..slots {
        let (c, _) = h.establish(l, 6000 + u16::try_from(i).expect("small"));
        conns.push(c);
        h.drop_output();
        h.check("accepted");
    }
    assert_eq!(h.held().boosted, slots, "every slot is lent");
    let reclaimed = |h: &mut Hold| h.n.stack().stats().boost_reclaimed;
    // 確立から 0.9 秒の要求では、どの保有者も回収の候補にならない
    h.advance(Duration::from_millis(900));
    h.drop_output();
    let (c, _) = h.establish(l, 7000);
    conns.push(c);
    h.drop_output();
    h.check("too early");
    assert_eq!(
        reclaimed(&mut h),
        0,
        "a holder idle for less than a second keeps its slot"
    );
    // 1 秒を過ぎた後の要求では、黙った保有者が枠を返す
    h.advance(Duration::from_millis(200));
    h.drop_output();
    let (c, _) = h.establish(l, 7001);
    conns.push(c);
    h.drop_output();
    h.check("reclaim");
    assert!(
        reclaimed(&mut h) > 0,
        "an idle holder returns its slot after a second"
    );
    assert!(h.held().boosted <= slots, "{:?}", h.held());
    for &c in &conns {
        let now = h.now();
        h.n.stack().abort(now, c);
    }
    h.drop_output();
    h.check("after the holders");
    assert_eq!(
        h.held().boosted,
        0,
        "the aborted connections return their slots"
    );
    h.finish();
    drop(conns);
}

/// 完成しない最初の断片を、送信元ごとに 1 つ送ります。
fn first_fragments(h: &mut Hold, count: u32, size: usize, sent: &mut u64) {
    for i in 0..count {
        let [_, b, c, d] = i.to_be_bytes();
        let src = SocketAddrV4::new(Ipv4Addr::new(172, 16 + b, c, d), 5353);
        let dg = ip::udp_packet(
            src,
            SocketAddrV4::new(DUT, 53),
            u16::try_from(i % 65536).expect("below 65536"),
            &vec![0x77; size + 8],
        );
        let first = ip::frag(&dg, 0, size);
        h.n.write(&first.marshal());
        drop((dg, first));
        *sent += 1;
        if i % 50 == 0 {
            h.drop_output();
            h.check("fragment flood");
        }
    }
    h.drop_output();
    h.check("fragment flood");
}

/// 断片の洪水:完成しない最初の断片を多数の送信元から送っても、再組み立ての表が項目の数と byte の上限で止まり、
/// 期限の後に空に戻ります。核は完成しない断片をすべて `fragments_dropped` に数えます。
fn fragment_flood() {
    let mut h = Hold::new(small_limits());
    let mut sent = 0;
    // 小さな断片では項目の数が先に尽きる
    first_fragments(&mut h, 2000, 600, &mut sent);
    assert_eq!(
        h.held().frag_bytes,
        h.limits.frag_entries * 600,
        "the table stops at its entries"
    );
    assert_eq!(
        h.n.stack().stats().fragments_dropped,
        sent,
        "every fragment is counted"
    );
    for _ in 0..120 {
        h.advance(Duration::from_secs(1));
        h.drop_output();
    }
    h.check("after the small fragments");
    assert_eq!(
        h.held().frag_bytes,
        0,
        "the table empties after its timeout"
    );
    // 大きな断片では byte の上限が先に尽きる。表の byte は項目ごとの管理領域も数えるので、止まる所は上限から
    // 断片 1 つと管理領域の分だけ手前になりうる。2 つの断片の分の内にあることを求める
    let size = 60_000;
    first_fragments(&mut h, 200, size, &mut sent);
    let cap = h.n.bound().frag;
    let held = h.held().frag_bytes as u64;
    assert!(
        held <= cap && cap - held < 2 * size as u64,
        "the table stops within two fragments of its byte cap {cap}: {held}"
    );
    assert_eq!(
        h.n.stack().stats().fragments_dropped,
        sent,
        "every fragment is counted"
    );
    for _ in 0..120 {
        h.advance(Duration::from_secs(1));
        h.drop_output();
    }
    h.check("after the flood");
    assert_eq!(
        h.held().frag_bytes,
        0,
        "the table empties after its timeout"
    );
    h.finish();
}

/// 読まない endpoint `u` に `size` byte の datagram を `count` 個送ります。
fn udp_datagrams(h: &mut Hold, port: u16, count: u32, size: usize) {
    for i in 0..count {
        let dg = ip::udp_packet(
            SocketAddrV4::new(PEER, 5000 + u16::try_from(i % 100).expect("below 100")),
            SocketAddrV4::new(DUT, port),
            u16::try_from(i % 65536).expect("below 65536"),
            &vec![0x55; size],
        );
        h.n.write(&dg.marshal());
        drop(dg);
        if i % 100 == 0 {
            h.drop_output();
            h.check("udp flood");
        }
    }
    h.drop_output();
    h.check("udp flood");
}

/// endpoint `u` の datagram をすべて読みます。
fn udp_read_all(h: &mut Hold, u: UdpId) {
    let mut buf = [0u8; 2048];
    loop {
        let now = h.now();
        match h.n.stack().recv_from(now, u, &mut buf) {
            Ok(_) => {}
            Err(Error::WouldBlock) => return,
            Err(e) => panic!("recv_from: {e}"),
        }
    }
}

/// 読まない UDP の endpoint への洪水:endpoint は datagram の数と byte のそれぞれで核の予算の 4 分の 1 で止まり、
/// 核の全体は予算で止まり、断った数が数えられ、読むと予約が返ります。
fn udp_flood() {
    let mut socks = Vec::with_capacity(8);
    let mut h = Hold::new(small_limits());
    for port in 53..59u16 {
        let now = h.now();
        socks.push(
            h.n.stack()
                .bind_udp(now, SocketAddrV4::new(DUT, port))
                .expect("bind"),
        );
    }
    // 小さな datagram では数の上限が先に尽きる
    let share = h.limits.udp_rx_datagrams / 4;
    udp_datagrams(&mut h, 53, 3000, 64);
    assert_eq!(
        h.held().udp_rx_datagrams,
        share,
        "the endpoint stops at its count share"
    );
    let st = h.n.stack().stats();
    assert_eq!(
        st.udp_endpoint_full,
        3000 - share as u64,
        "the refusals are counted: {st:?}"
    );
    udp_read_all(&mut h, socks[0]);
    h.check("read");
    let held = h.held();
    assert!(
        held.udp_rx_bytes == 0 && held.udp_rx_datagrams == 0,
        "reading returns the reservation: {held:?}"
    );
    // 大きな datagram では byte の上限が先に尽き、保持は平らになる
    udp_datagrams(&mut h, 53, 1500, 1000);
    let bytes = h.held().udp_rx_bytes;
    udp_datagrams(&mut h, 53, 1500, 1000);
    let held = h.held();
    assert!(
        held.udp_rx_bytes == bytes && held.udp_rx_datagrams < share,
        "the endpoint stops at its byte share {bytes}, before its count share: {held:?}"
    );
    udp_read_all(&mut h, socks[0]);
    // 5 つ以上の endpoint では核の全体の予算 (endpoint の上限の 4 倍) が先に尽きる
    for port in 53..59u16 {
        udp_datagrams(&mut h, port, 1500, 1000);
    }
    let held = h.held();
    let st = h.n.stack().stats();
    assert!(
        held.udp_rx_bytes <= 4 * bytes && st.udp_tunnel_full > 0,
        "the tunnel stops at its budget of four shares ({}): {held:?} {st:?}",
        4 * bytes
    );
    for &u in &socks {
        udp_read_all(&mut h, u);
        let now = h.now();
        h.n.stack().close_udp(now, u);
    }
    h.check("closed");
    assert!(h.held().udp_rx_bytes == 0, "{:?}", h.held());
    h.finish();
    drop(socks);
}

fn trial(name: &'static str, f: fn()) -> Trial {
    Trial::test(name, move || {
        f();
        Ok::<(), Failed>(())
    })
}

fn main() {
    let mut args = Arguments::from_args();
    // 確保の数えはプロセスで 1 つなので、試験を並べない
    args.test_threads = Some(1);
    let trials = vec![
        trial("syn_flood", syn_flood),
        trial("accept_backlog", accept_backlog),
        trial("time_wait_churn", time_wait_churn),
        trial("empty_ack_flood", empty_ack_flood),
        trial("ooo_flood", ooo_flood),
        trial("zero_window_peer", zero_window_peer),
        trial("unmatched_flood", unmatched_flood),
        trial("small_writes_slow_reader", small_writes_slow_reader),
        trial("output_stall", output_stall),
        trial("sack_ack_flood", sack_ack_flood),
        trial("idle_boost_holders", idle_boost_holders),
        trial("fragment_flood", fragment_flood),
        trial("udp_flood", udp_flood),
    ];
    libtest_mimic::run(&args, trials).exit();
}
