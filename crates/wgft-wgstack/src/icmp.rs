//! ICMP (Go の `icmp.go`、packet-validation.md の ICMP の誤りの入口)。
//!
//! 自分のアドレス宛ての echo request には制御の輪から応答します。ping の endpoint は固定の数の表に置き、
//! endpoint 1 つが持つ応答は 1 つだけで、読まれる前に届いた次の応答は捨てます。ICMP の誤りは、外側の送信元が
//! 引用された datagram の宛先と一致するときだけ受け入れます。核が送る ICMP の誤りは、核の全体の速さの制限の
//! 内側で送ります。

use crate::fixed_vec::{AllocError, FixedVec};
use crate::stack::shared::{EV_PING, LogKind, Shared};
use crate::stack::{Error, Hook, Stack};
use crate::tcp::MIN_PMTU;
use crate::tcp::conn::State;
use crate::time::Time;
use crate::wire::{
    self, IP_HEADER_LEN, Icmp, Ipv4, PROTO_ICMP, PROTO_TCP, PayloadDrop, Tuple, be16,
};
use core::net::Ipv4Addr;

pub(crate) const ECHO_REPLY: u8 = 0;
pub(crate) const DST_UNREACH: u8 = 3;
const SRC_QUENCH: u8 = 4;
const REDIRECT: u8 = 5;
pub(crate) const ECHO: u8 = 8;
pub(crate) const TIME_EXCEEDED: u8 = 11;
pub(crate) const PARAM_PROBLEM: u8 = 12;
/// 1 秒あたりに送る ICMP の誤りの数です (gVisor の既定の ICMP の速さの制限と同じ値)。
const RATE_LIMIT: i64 = 1000;
/// ping の endpoint の表の大きさ N_ping です。
pub(crate) const PING_ENDPOINTS: usize = 16;
/// IPv4 の最小の再組み立ての大きさです。誤りの引用はこれに収めます。
const MIN_REASSEMBLY: usize = 576;

/// ping の endpoint の handle です。表の番号と 64 bit の世代の組で、閉じた後の handle は誤りになります。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PingId {
    pub(crate) slot: u8,
    pub(crate) generation: u64,
}

impl PingId {
    /// ping の endpoint の表の番号です。[`MAX_PINGS`](crate::MAX_PINGS) より小さく、呼び手が endpoint ごとの表を
    /// 核の外に持つ時の位置に使えます。
    pub fn index(&self) -> usize {
        usize::from(self.slot)
    }
}

/// ping の endpoint の行です。
#[derive(Clone, Copy, Debug, Default)]
struct PingEp {
    used: bool,
    generation: u64,
    ident: u16,
    raddr: u32,
    /// 持っている応答の長さです。0 なら無しです。
    n: u16,
}

/// ping の endpoint の固定の表です。行と、MTU の大きさの応答の置き場を表の大きさだけ作成の時に確保します。
/// 行は核の値に置かず、segment ごとの経路が触る核の欄の間に挟みません。
#[derive(Debug)]
pub(crate) struct Pings {
    eps: FixedVec<PingEp>,
    /// 次に試す識別子です。
    next: u16,
    replies: FixedVec<u8>,
    size: usize,
}

impl Pings {
    pub(crate) fn new(mtu: usize) -> Result<Self, AllocError> {
        Ok(Self {
            eps: FixedVec::try_filled(PING_ENDPOINTS, |_| PingEp::default())?,
            next: 0,
            replies: FixedVec::try_filled(PING_ENDPOINTS * mtu, |_| 0)?,
            size: mtu,
        })
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.eps.heap_bytes() + self.replies.heap_bytes()
    }

    /// endpoint の行 1 つの大きさです。上界が使います。
    pub(crate) fn ep_size() -> usize {
        size_of::<PingEp>()
    }

    /// 枠 `slot` の今の世代です。
    pub(crate) fn generation(&self, slot: usize) -> u64 {
        self.eps.get(slot).map_or(0, |e| e.generation)
    }

    /// 使っている endpoint の数です。
    pub(crate) fn used(&self) -> usize {
        self.eps.iter().filter(|e| e.used).count()
    }

    fn get(&mut self, id: PingId) -> Option<&mut PingEp> {
        self.eps
            .get_mut(usize::from(id.slot))
            .filter(|e| e.used && e.generation == id.generation)
    }

    /// すべての endpoint を閉じます。
    pub(crate) fn clear(&mut self) {
        for e in self.eps.iter_mut() {
            e.used = false;
            e.n = 0;
        }
    }

    /// 応答を持つ endpoint が使っている枠にあることを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        for e in self.eps.iter() {
            if (!e.used && e.n != 0) || usize::from(e.n) > self.size {
                return Err("a ping endpoint holds a reply it cannot hold");
            }
        }
        Ok(())
    }
}

impl Shared {
    /// 核の全体の ICMP の誤りの速さの制限から 1 つ取れたかを返します。
    fn icmp_allowed(&mut self, now: i64) -> bool {
        let sec = now / 1_000_000_000;
        if sec != self.icmp_sec {
            self.icmp_sec = sec;
            self.icmp_count = RATE_LIMIT;
        }
        if self.icmp_count <= 0 {
            return false;
        }
        self.icmp_count -= 1;
        true
    }

    /// 届いた packet `orig` への ICMP の誤り (Destination Unreachable、Time Exceeded、Parameter Problem) を制御の
    /// 輪に積みます。`rest` は ICMP の header の後半の 4 byte (pointer など) です。誤りの packet、先頭でない断片、
    /// 自分のアドレスでない宛先、broadcast と multicast の送信元には送りません (RFC 1122 3.2.2)。
    /// `later_fragment` が真なら、先頭でない断片にも送ります (後続の断片の option の誤りへの Parameter Problem)。
    pub(crate) fn send_icmp_error_raw(
        &mut self,
        orig: &[u8],
        typ: u8,
        code: u8,
        rest: u32,
        now: i64,
        later_fragment: bool,
    ) {
        if orig.len() < IP_HEADER_LEN {
            return;
        }
        let hlen = usize::from(orig[0] & 0x0f) * 4;
        if hlen < IP_HEADER_LEN || orig.len() < hlen {
            return;
        }
        let src = u32::from_be_bytes([orig[12], orig[13], orig[14], orig[15]]);
        let dst = u32::from_be_bytes([orig[16], orig[17], orig[18], orig[19]]);
        if dst != self.addr || src == 0 || src == u32::MAX || src >> 28 == 0xe {
            return;
        }
        if !later_fragment && be16(orig, 6) & 0x1fff != 0 {
            return;
        }
        if orig[9] == PROTO_ICMP
            && orig.len() > hlen
            && !matches!(orig[hlen], ECHO_REPLY | ECHO | 13..=16)
        {
            return; // ICMP の誤りに誤りを返しません
        }
        if !self.icmp_allowed(now) {
            self.stats.icmp_limited += 1;
            return;
        }
        let quote = &orig[..orig
            .len()
            .min(MIN_REASSEMBLY.min(self.config.mtu) - IP_HEADER_LEN - 8)];
        let id = self.next_id();
        let Some(b) = self.out.ctl.slot() else {
            self.refused(LogKind::CtlDropped, now);
            return;
        };
        let total = IP_HEADER_LEN + 8 + quote.len();
        if total > b.len() {
            return;
        }
        wire::write_ipv4_header(b, total, id, PROTO_ICMP, dst, src);
        let m = &mut b[IP_HEADER_LEN..total];
        m[0] = typ;
        m[1] = code;
        m[4..8].copy_from_slice(&rest.to_be_bytes());
        m[8..].copy_from_slice(quote);
        wire::finish_icmp(m);
        self.out.ctl.commit(total);
    }

    /// 届いた packet `ip` への ICMP の誤りを積みます。
    pub(crate) fn send_icmp_error(
        &mut self,
        ip: &Ipv4<'_>,
        typ: u8,
        code: u8,
        rest: u32,
        now: i64,
    ) {
        self.send_icmp_error_raw(ip.packet, typ, code, rest, now, false);
    }

    /// 自分のアドレス宛ての echo request に、制御の輪から echo reply を返します。
    fn echo_reply(&mut self, ip: &Ipv4<'_>, now: i64) {
        let payload = ip.payload();
        let total = IP_HEADER_LEN + payload.len();
        if total > self.config.mtu {
            self.stats.icmp_dropped += 1;
            return;
        }
        let id = self.next_id();
        let Some(b) = self.out.ctl.slot() else {
            self.refused(LogKind::CtlDropped, now);
            return;
        };
        wire::write_ipv4_header(b, total, id, PROTO_ICMP, ip.dst, ip.src);
        wire::clear_df(b); // echo の応答は DF を立てません (Linux と同じく PMTU discovery を使いません)
        let m = &mut b[IP_HEADER_LEN..total];
        m.copy_from_slice(payload);
        m[0] = ECHO_REPLY;
        wire::finish_icmp(m);
        self.out.ctl.commit(total);
    }

    /// echo reply を、識別子と送信元の合う endpoint に渡します。応答を 1 つ持っていれば捨てます。
    fn ping_reply(&mut self, ip: &Ipv4<'_>) {
        let payload = ip.payload();
        let ident = be16(payload, 4);
        let p = &mut self.pings;
        let Some(i) = p
            .eps
            .iter()
            .position(|e| e.used && e.ident == ident && e.raddr == ip.src)
        else {
            self.stats.icmp_dropped += 1;
            return;
        };
        let e = &mut p.eps[i];
        if e.n != 0 || payload.len() > p.size {
            self.stats.icmp_dropped += 1;
            return;
        }
        p.replies[i * p.size..i * p.size + payload.len()].copy_from_slice(payload);
        e.n = u16::try_from(payload.len()).unwrap_or(0);
        let t = self.ping_target(i);
        self.events.raise(t, EV_PING);
    }

    /// ping の endpoint `i` の知らせの対象です。接続の枠と待ち受けのポートの後に並べます。
    pub(crate) fn ping_target(&self, i: usize) -> u32 {
        u32::try_from(self.qlinks.len() + crate::tcp::listen::PORTS + i).unwrap_or(0)
    }
}

impl<H: Hook> Stack<H> {
    /// ICMP の入口です (Go の `inputICMP`)。
    pub(crate) fn input_icmp(&mut self, ip: &Ipv4<'_>, now: i64) {
        let m = match wire::parse_icmp(ip) {
            Ok(m) => m,
            Err(PayloadDrop::Malformed | PayloadDrop::BadChecksum) => {
                self.s.stats.icmp_dropped += 1;
                return;
            }
        };
        match m.typ {
            ECHO => self.s.echo_reply(ip, now),
            ECHO_REPLY => self.s.ping_reply(ip),
            DST_UNREACH | SRC_QUENCH | REDIRECT | TIME_EXCEEDED | PARAM_PROBLEM => {
                self.icmp_error(ip, &m, now);
            }
            _ => self.s.stats.icmp_dropped += 1,
        }
    }

    /// ICMP の誤りを受けます。外側の送信元が引用の宛先と一致し、引用の送信元が自分であるときだけ受け入れます。
    /// TCP の Fragmentation Needed は PMTU を下げます。ほかの誤りは数えて捨てます。UDP の endpoint は接続しない
    /// ので、Port Unreachable を知らせる相手がいません。
    fn icmp_error(&mut self, ip: &Ipv4<'_>, m: &Icmp<'_>, now: i64) {
        let q = m.body;
        if q.len() < IP_HEADER_LEN || q[0] >> 4 != 4 {
            self.s.stats.icmp_dropped += 1;
            return;
        }
        let qsrc = u32::from_be_bytes([q[12], q[13], q[14], q[15]]);
        let qdst = u32::from_be_bytes([q[16], q[17], q[18], q[19]]);
        if qdst != ip.src || qsrc != ip.dst {
            self.s.stats.icmp_dropped += 1;
            return;
        }
        if m.typ != DST_UNREACH || m.code != 4 {
            self.s.stats.icmp_dropped += 1;
            return;
        }
        let qhl = usize::from(q[0] & 0x0f) * 4;
        if qhl < IP_HEADER_LEN || q.len() < qhl + 8 || q[9] != PROTO_TCP {
            self.s.stats.icmp_dropped += 1;
            return;
        }
        let mtu = m.rest & 0xffff;
        if mtu < MIN_PMTU {
            self.s.stats.icmp_dropped += 1;
            return;
        }
        let t = &q[qhl..];
        let tup = Tuple {
            laddr: qsrc,
            raddr: qdst,
            lport: be16(t, 0),
            rport: be16(t, 2),
        };
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let Some((id, generation)) = self.s.conn_idx.find(tup) else {
            self.s.stats.icmp_dropped += 1;
            return;
        };
        let c = self.conns.tcb(id);
        if c.generation == generation && c.in_index && c.state != State::Free {
            self.conn(id).pmtu_drop(seq, mtu, now);
        }
    }

    /// トンネルのアドレスから `raddr` への ICMP の echo の endpoint を作ります。表が満杯なら誤りを返します。
    pub fn open_ping(&mut self, now: Time, raddr: Ipv4Addr) -> Result<PingId, Error> {
        self.clock(now);
        let p = &mut self.s.pings;
        let Some(free) = p.eps.iter().position(|e| !e.used) else {
            return Err(Error::TableFull);
        };
        let mut ident = p.next;
        loop {
            ident = ident.wrapping_add(1);
            if !p.eps.iter().any(|e| e.used && e.ident == ident) {
                break;
            }
        }
        p.next = ident;
        let e = &mut p.eps[free];
        e.used = true;
        e.ident = ident;
        e.raddr = raddr.to_bits();
        e.n = 0;
        e.generation = e.generation.wrapping_add(1);
        let id = PingId {
            slot: u8::try_from(free).unwrap_or(u8::MAX),
            generation: e.generation,
        };
        let t = self.s.ping_target(free);
        self.s.events.reset(t);
        Ok(id)
    }

    /// ICMP の echo request の message `msg` を送ります。識別子はこの endpoint の値に書き換えます。制御の輪が
    /// 満杯なら [`Error::NoBufferSpace`] を返します。
    pub fn send_ping(&mut self, now: Time, id: PingId, msg: &[u8]) -> Result<usize, Error> {
        self.clock(now);
        let s = &mut self.s;
        if msg.len() < 8 || msg[0] != ECHO || IP_HEADER_LEN + msg.len() > s.config.mtu {
            return Err(Error::InvalidMessage);
        }
        let Some(e) = s.pings.get(id) else {
            return Err(Error::Closed);
        };
        let (ident, dst) = (e.ident, e.raddr);
        let total = IP_HEADER_LEN + msg.len();
        let ip_id = s.next_id();
        let src = s.addr;
        let Some(b) = s.out.ctl.slot() else {
            return Err(Error::NoBufferSpace);
        };
        wire::write_ipv4_header(b, total, ip_id, PROTO_ICMP, src, dst);
        let m = &mut b[IP_HEADER_LEN..total];
        m.copy_from_slice(msg);
        m[4..6].copy_from_slice(&ident.to_be_bytes());
        wire::finish_icmp(m);
        s.out.ctl.commit(total);
        Ok(msg.len())
    }

    /// 応答の message を 1 つ `dst` に写し、写した長さを返します。`dst` より長い応答は切ります。応答が無ければ
    /// `WouldBlock` です。
    pub fn recv_ping(&mut self, now: Time, id: PingId, dst: &mut [u8]) -> Result<usize, Error> {
        self.clock(now);
        let p = &mut self.s.pings;
        let size = p.size;
        let Some(e) = p
            .eps
            .get_mut(usize::from(id.slot))
            .filter(|e| e.used && e.generation == id.generation)
        else {
            return Err(Error::Closed);
        };
        if e.n == 0 {
            return Err(Error::WouldBlock);
        }
        let n = usize::from(e.n).min(dst.len());
        e.n = 0;
        let at = usize::from(id.slot) * size;
        dst[..n].copy_from_slice(&p.replies[at..at + n]);
        Ok(n)
    }

    /// endpoint を閉じ、識別子を空けます。古い handle では何もしません。
    pub fn close_ping(&mut self, now: Time, id: PingId) {
        self.clock(now);
        if let Some(e) = self.s.pings.get(id) {
            e.used = false;
            e.n = 0;
            let t = self.s.ping_target(usize::from(id.slot));
            self.s.events.reset(t);
        }
    }
}
