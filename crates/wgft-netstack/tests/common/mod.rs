//! 試験の道具:手で進む時計、2 つの端の間で packet を運ぶ代わりの駆動、台本の TCP の相手。
//!
//! 時計は tokio の止めた時計 (`start_paused`) で、全ての task が待つと次の期限まで進みます。核の時刻も同じ
//! 時計から取るので、遅延 ACK と RTO の待ちが試験の実時間を使いません。

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::task::Waker;
use std::time::Instant;

use tokio::sync::Notify;
use wgft_netstack::{Access, LocalNetstack, Netstack};
use wgft_wgstack::{Budget, Config, Hook, Limits, NoHook};

pub(crate) const A: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
pub(crate) const B: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
pub(crate) const MTU: usize = 1420;

/// 試験の時計です。tokio の止めた時計を読みます。
pub(crate) fn clock() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// 試験の表の大きさです。
pub(crate) fn limits() -> Limits {
    Limits {
        max_flows: 16,
        accept_queue: 8,
        syn_rows: 16,
        tw_rows: 32,
        ctl_slots: 16,
        ..Limits::default()
    }
}

/// アドレス `addr` の核を作ります。
pub(crate) fn netstack(addr: Ipv4Addr) -> LocalNetstack {
    netstack_with(addr, NoHook)
}

/// 設定を `edit` で変えたアドレス `addr` の核を作ります。
pub(crate) fn netstack_config(addr: Ipv4Addr, edit: impl FnOnce(&mut Config)) -> LocalNetstack {
    build(addr, NoHook, edit)
}

/// hook `hook` を持つアドレス `addr` の核を作ります。
pub(crate) fn netstack_with<H: Hook>(addr: Ipv4Addr, hook: H) -> LocalNetstack<H> {
    build(addr, hook, |_| {})
}

fn build<H: Hook>(addr: Ipv4Addr, hook: H, edit: impl FnOnce(&mut Config)) -> LocalNetstack<H> {
    let mut config = Config {
        limits: limits(),
        ..Config::new(addr, MTU)
    };
    edit(&mut config);
    let seed = [addr.octets()[3]; 64];
    let ns = Netstack::new(config, Budget::new().unwrap(), &seed, hook, clock(), clock).unwrap();
    LocalNetstack::new(ns)
}

/// 代わりの駆動が packet を運ぶ端です。
pub(crate) trait End {
    /// 時刻の来たタイマーを回します。
    fn timers(&self, now: Instant);
    /// 次に送る packet を `buf` に書きます。
    fn pull(&self, now: Instant, buf: &mut [u8]) -> Option<usize>;
    /// 相手の packet を受けます。
    fn push(&self, now: Instant, pkt: &[u8]);
    /// 次の期限です。
    fn deadline(&self) -> Option<Instant>;
    /// 起こす waker を移します。
    fn wakers(&self, out: &mut Vec<Waker>);
    /// 操作の知らせを待ちます。
    async fn woken(&self);
}

impl<H: Hook> End for LocalNetstack<H> {
    fn timers(&self, now: Instant) {
        self.with(|ns| {
            if ns.poll_timeout().is_some_and(|t| t <= now) {
                ns.handle_timeout(now);
            }
        });
    }

    fn pull(&self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        self.with(|ns| ns.poll_transmit(now, buf))
    }

    fn push(&self, now: Instant, pkt: &[u8]) {
        self.with(|ns| ns.handle_packet(now, pkt));
    }

    fn deadline(&self) -> Option<Instant> {
        self.with(|ns| ns.poll_timeout())
    }

    fn wakers(&self, out: &mut Vec<Waker>) {
        self.with(|ns| ns.poll_wakers(out));
    }

    async fn woken(&self) {
        self.driver_woken().await;
    }
}

/// 代わりの駆動:2 つの端の間で packet を運び、知らせの waker を借用を返した後に起こし、早い方の期限か
/// 操作の知らせまで待ちます。データプレーンの駆動の 1 回の起床と同じ順です。`drops` が真を返す packet は
/// 運ばずに捨てます。
pub(crate) async fn drive<X: End, Y: End>(x: X, y: Y, mut drops: impl FnMut(&[u8]) -> bool) {
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::new();
    loop {
        let now = clock();
        x.timers(now);
        y.timers(now);
        loop {
            let mut moved = false;
            while let Some(n) = x.pull(now, &mut buf) {
                moved = true;
                if !drops(&buf[..n]) {
                    y.push(now, &buf[..n]);
                }
            }
            while let Some(n) = y.pull(now, &mut buf) {
                moved = true;
                if !drops(&buf[..n]) {
                    x.push(now, &buf[..n]);
                }
            }
            if !moved {
                break;
            }
        }
        x.wakers(&mut wakers);
        y.wakers(&mut wakers);
        for w in wakers.drain(..) {
            w.wake();
        }
        let deadline = match (x.deadline(), y.deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let sleep = async {
            match deadline {
                Some(d) => tokio::time::sleep_until(d.into()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = sleep => {}
            () = x.woken() => {}
            () = y.woken() => {}
        }
    }
}

/// 落とさない運び手です。
pub(crate) fn no_drops(_: &[u8]) -> bool {
    false
}

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

/// 台本の TCP の相手の状態です。
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the flags of a scripted peer"
)]
pub(crate) struct PeerState {
    pub(crate) local: Option<SocketAddrV4>,
    pub(crate) remote: Option<SocketAddrV4>,
    pub(crate) established: bool,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    rcv_nxt: u32,
    /// 受けた中身です。
    pub(crate) received: Vec<u8>,
    pub(crate) fin_received: bool,
    pub(crate) rst_received: bool,
    /// 送る中身の残りです。
    to_send: VecDeque<u8>,
    fin_pending: bool,
    fin_sent: bool,
    /// 示す受信の窓です。
    pub(crate) window: u16,
    outbox: VecDeque<Vec<u8>>,
    ip_id: u16,
}

/// 台本の TCP の相手です。核は能動の open を持たないので、核に接続する側を手で書きます。順序どおりに届いた
/// segment をすべて受け、segment ごとに ACK を返します。packet を失わない運び手と組む前提で、再送しません。
#[derive(Clone, Debug)]
pub(crate) struct TcpPeer {
    pub(crate) state: Rc<RefCell<PeerState>>,
    notify: Rc<Notify>,
}

impl TcpPeer {
    /// `local` から `remote` に SYN を送ります。
    pub(crate) fn connect(local: SocketAddrV4, remote: SocketAddrV4) -> Self {
        Self::connect_with(Rc::default(), local, remote)
    }

    fn connect_with(notify: Rc<Notify>, local: SocketAddrV4, remote: SocketAddrV4) -> Self {
        let p = Self {
            state: Rc::default(),
            notify,
        };
        {
            let mut s = p.state.borrow_mut();
            s.local = Some(local);
            s.remote = Some(remote);
            s.window = 65535;
            s.snd_una = 1000;
            s.snd_nxt = 1001;
            let mss = 1380u16.to_be_bytes();
            let opts = [2, 4, mss[0], mss[1]];
            s.emit(1000, FLAG_SYN, &opts, &[]);
        }
        p.notify.notify_one();
        p
    }

    /// `data` を送ります。
    pub(crate) fn send(&self, data: &[u8]) {
        let mut s = self.state.borrow_mut();
        s.to_send.extend(data);
        s.flush();
        drop(s);
        self.notify.notify_one();
    }

    /// 送るものを送り終えた後に FIN を送ります。
    pub(crate) fn finish(&self) {
        let mut s = self.state.borrow_mut();
        s.fin_pending = true;
        s.flush();
        drop(s);
        self.notify.notify_one();
    }

    /// 送った中身と FIN を相手がすべて確認したかです。
    pub(crate) fn all_acked(&self) -> bool {
        let s = self.state.borrow();
        s.snd_una == s.snd_nxt && s.to_send.is_empty()
    }
}

impl PeerState {
    fn emit(&mut self, seq: u32, flags: u8, opts: &[u8], payload: &[u8]) {
        let (Some(l), Some(r)) = (self.local, self.remote) else {
            return;
        };
        let ack = if flags & FLAG_SYN == 0 || flags & FLAG_ACK != 0 {
            self.rcv_nxt
        } else {
            0
        };
        let flags = if flags & FLAG_SYN != 0 {
            flags
        } else {
            flags | FLAG_ACK
        };
        self.ip_id = self.ip_id.wrapping_add(1);
        self.outbox.push_back(build_tcp(
            l,
            r,
            self.ip_id,
            seq,
            ack,
            flags,
            self.window,
            opts,
            payload,
        ));
    }

    /// 窓の内で送れるものを送ります。
    fn flush(&mut self) {
        if !self.established {
            return;
        }
        while !self.to_send.is_empty() {
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
            if in_flight >= self.snd_wnd {
                return;
            }
            let room = usize::try_from(self.snd_wnd - in_flight).unwrap_or(usize::MAX);
            let n = self.to_send.len().min(1000).min(room);
            let chunk: Vec<u8> = self.to_send.drain(..n).collect();
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(u32::try_from(n).unwrap_or(0));
            self.emit(seq, FLAG_PSH, &[], &chunk);
        }
        if self.fin_pending && !self.fin_sent {
            self.fin_sent = true;
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.emit(seq, FLAG_FIN, &[], &[]);
        }
    }

    fn input(&mut self, pkt: &[u8]) {
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if pkt[9] != 6 {
            return;
        }
        let t = &pkt[ihl..];
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
        let off = usize::from(t[12] >> 4) * 4;
        let flags = t[13];
        let wnd = u32::from(u16::from_be_bytes([t[14], t[15]]));
        let payload = &t[off..];
        if flags & FLAG_RST != 0 {
            self.rst_received = true;
            self.established = false;
            return;
        }
        if flags & FLAG_SYN != 0 && flags & FLAG_ACK != 0 {
            if !self.established {
                self.established = true;
                self.rcv_nxt = seq.wrapping_add(1);
                self.snd_una = ack;
                self.snd_wnd = wnd;
            }
            self.emit(self.snd_nxt, 0, &[], &[]);
            self.flush();
            return;
        }
        if flags & FLAG_ACK != 0
            && ack.wrapping_sub(self.snd_una) <= self.snd_nxt.wrapping_sub(self.snd_una)
        {
            self.snd_una = ack;
            self.snd_wnd = wnd;
        }
        let len = u32::try_from(payload.len()).unwrap_or(0);
        let fin = flags & FLAG_FIN != 0;
        if (len > 0 || fin) && seq == self.rcv_nxt {
            self.received.extend_from_slice(payload);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(len);
            if fin {
                self.fin_received = true;
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            }
        }
        if len > 0 || fin {
            self.emit(self.snd_nxt, 0, &[], &[]);
        }
        self.flush();
    }
}

impl End for TcpPeer {
    fn timers(&self, _now: Instant) {}

    fn pull(&self, _now: Instant, buf: &mut [u8]) -> Option<usize> {
        let pkt = self.state.borrow_mut().outbox.pop_front()?;
        buf[..pkt.len()].copy_from_slice(&pkt);
        Some(pkt.len())
    }

    fn push(&self, _now: Instant, pkt: &[u8]) {
        self.state.borrow_mut().input(pkt);
    }

    fn deadline(&self) -> Option<Instant> {
        None
    }

    fn wakers(&self, _out: &mut Vec<Waker>) {}

    async fn woken(&self) {
        self.notify.notified().await;
    }
}

/// 1 つの核に向かう台本の相手の集まりです。packet を宛先のポートで相手に振り分けます。
#[derive(Clone, Debug, Default)]
pub(crate) struct Peers {
    peers: Rc<RefCell<Vec<TcpPeer>>>,
    notify: Rc<Notify>,
}

impl Peers {
    /// 集まりに相手を足し、`local` から `remote` に SYN を送ります。
    pub(crate) fn connect(&self, local: SocketAddrV4, remote: SocketAddrV4) -> TcpPeer {
        let p = TcpPeer::connect_with(Rc::clone(&self.notify), local, remote);
        self.peers.borrow_mut().push(p.clone());
        p
    }
}

impl End for Peers {
    fn timers(&self, _now: Instant) {}

    fn pull(&self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        let peers = self.peers.borrow().clone();
        peers.iter().find_map(|p| p.pull(now, buf))
    }

    fn push(&self, now: Instant, pkt: &[u8]) {
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        let port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        let peers = self.peers.borrow().clone();
        if let Some(p) = peers
            .iter()
            .find(|p| p.state.borrow().local.is_some_and(|l| l.port() == port))
        {
            p.push(now, pkt);
        }
    }

    fn deadline(&self) -> Option<Instant> {
        None
    }

    fn wakers(&self, _out: &mut Vec<Waker>) {}

    async fn woken(&self) {
        self.notify.notified().await;
    }
}

fn csum(data: &[u8], mut sum: u32) -> u16 {
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [b] = rest {
        sum += u32::from(*b) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

#[expect(
    clippy::too_many_arguments,
    clippy::many_single_char_names,
    reason = "the fields of one segment"
)]
fn build_tcp(
    l: SocketAddrV4,
    r: SocketAddrV4,
    ip_id: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    opts: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + opts.len() + payload.len();
    let total = 20 + tcp_len;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[4..6].copy_from_slice(&ip_id.to_be_bytes());
    p[6] = 0x40;
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&l.ip().octets());
    p[16..20].copy_from_slice(&r.ip().octets());
    let h = csum(&p[..20], 0);
    p[10..12].copy_from_slice(&h.to_be_bytes());
    let t = &mut p[20..];
    t[0..2].copy_from_slice(&l.port().to_be_bytes());
    t[2..4].copy_from_slice(&r.port().to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = u8::try_from((20 + opts.len()) / 4).unwrap() << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&window.to_be_bytes());
    t[20..20 + opts.len()].copy_from_slice(opts);
    t[20 + opts.len()..].copy_from_slice(payload);
    let mut pseudo = 0u32;
    for half in [l.ip().octets(), r.ip().octets()] {
        pseudo += u32::from(u16::from_be_bytes([half[0], half[1]]));
        pseudo += u32::from(u16::from_be_bytes([half[2], half[3]]));
    }
    pseudo += 6 + u32::try_from(tcp_len).unwrap();
    let c = csum(t, pseudo);
    t[16..18].copy_from_slice(&c.to_be_bytes());
    p
}

/// 決まった型の中身です。
pub(crate) fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from(i % 251).unwrap_or(0) ^ salt)
        .collect()
}
