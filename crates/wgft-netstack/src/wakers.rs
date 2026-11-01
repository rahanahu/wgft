//! waker の表 (wgstack-rs.md の「データプレーンの駆動」と「handle の層で決めたこと」)。
//!
//! 核の知らせ ([`Event`]) を、待っている task の waker に引き当てます。表は核の対象と同じ番号で引き、
//! 知らせ 1 つの手間は配列の 1 回の参照です。
//!
//! - 接続:接続の枠ごとに読みと書きの waker を 1 つずつ持ちます。作成の時に枠の数だけ確保します
//! - ポート:TCP の待ち受けの accept と UDP の endpoint の読みの waker を、256 個のポートの頁に分けて持ちます。
//!   頁は、そのポートの範囲で初めて待ち受けか endpoint を開く時に確保し、核を閉じるまで持ちます。
//!   65,536 個のポートの分を作成の時に確保すると、待ち受けの少ない agent で使わない表が大きくなるためです
//! - ping:核の ping の表と同じ数の waker を持ちます
//! - UDP の送り:核は送信の予約が 1 つ返ると、待つ endpoint すべてに `UdpWritable` を出します。
//!   endpoint 1 つの送り手は複数の task (UDP の中継のセッション) なので、1 つの [`Notify`] を全 endpoint で
//!   分け合い、知らせでその待ち手をすべて起こします。待ち手の節は待つ future の中にあり、表は伸びません
//!
//! 同じ方向を待つ task は、接続、待ち受け、UDP の受け取り、ping でそれぞれ 1 つです。handle の読み書きは
//! `&mut self` を取るので、1 つの handle から同じ方向を 2 つの task で待つことはありません。
//! waker を登録したまま future が落ちても、表は次の知らせかその handle を閉じる時に waker を捨てるだけで、
//! 核の状態に触りません。

use std::sync::Arc;
use std::task::{Wake, Waker};

use tokio::sync::Notify;
use wgft_wgstack::{ConnId, Event, MAX_PINGS};

/// ポートの頁の大きさです。
const PAGE: usize = 256;
/// ポートの頁の数です。
const PAGES: usize = (u16::MAX as usize + 1) / PAGE;

/// 1 つの対象の 2 つの方向の waker です。接続では読みと書き、ポートでは accept と UDP の読みです。
#[derive(Debug, Default)]
struct Pair {
    first: Option<Waker>,
    second: Option<Waker>,
}

/// UDP の送りを待つ task を起こす waker の中身です。駆動の層は借用を返した後にこの waker を起こすので、
/// 待ち手を起こすのも借用の外です。
#[derive(Debug, Default)]
pub(crate) struct UdpWrite(pub(crate) Notify);

impl Wake for UdpWrite {
    fn wake(self: Arc<Self>) {
        self.0.notify_waiters();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_waiters();
    }
}

/// `slot` の waker を `w` にします。同じ task の waker なら写しません。
fn set(slot: &mut Option<Waker>, w: &Waker) {
    if !slot.as_ref().is_some_and(|old| old.will_wake(w)) {
        *slot = Some(w.clone());
    }
}

fn take(slot: &mut Option<Waker>, out: &mut Vec<Waker>) {
    if let Some(w) = slot.take() {
        out.push(w);
    }
}

/// 表の確保に失敗しました。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocError;

/// `n` 個の `T` を、失敗を返す確保で作ります。容量はちょうど `n` で、後から伸ばしません。
fn try_filled<T>(n: usize, f: impl Fn() -> T) -> Result<Vec<T>, AllocError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| AllocError)?;
    v.extend(std::iter::repeat_with(f).take(n));
    Ok(v)
}

/// `Arc` の確保の大きさです。2 つの数えと中身です。
const ARC_BYTES: usize = 2 * size_of::<usize>() + size_of::<UdpWrite>();

/// waker の表です。表は作成の時と頁を開く時にだけ確保し、伸ばしません。
#[derive(Debug)]
pub(crate) struct Wakers {
    conns: Vec<Pair>,
    ports: Vec<Option<Vec<Pair>>>,
    pings: Vec<Option<Waker>>,
    udp_write: Arc<UdpWrite>,
    udp_write_waker: Waker,
}

impl Wakers {
    /// 接続の枠 `conns` 個の表を作ります。送りの待ちの `Arc` は小さいので失敗を返さない確保で作ります。
    pub(crate) fn new(conns: usize) -> Result<Self, AllocError> {
        let udp_write = Arc::new(UdpWrite::default());
        Ok(Self {
            conns: try_filled(conns, Pair::default)?,
            ports: try_filled(PAGES, || None)?,
            pings: try_filled(MAX_PINGS, || None)?,
            udp_write_waker: Waker::from(Arc::clone(&udp_write)),
            udp_write,
        })
    }

    /// 表が持つ確保の byte (要求の大きさ) です。
    pub(crate) fn heap_bytes(&self) -> usize {
        let pages: usize = self.ports.iter().flatten().map(Vec::capacity).sum();
        size_of::<Pair>() * (self.conns.capacity() + pages)
            + size_of::<Option<Vec<Pair>>>() * self.ports.capacity()
            + size_of::<Option<Waker>>() * self.pings.capacity()
            + ARC_BYTES
    }

    /// 表が持ちうる確保の byte の上限です。ポートの頁をすべて確保した時の大きさです。
    pub(crate) fn bound_bytes(conns: usize) -> usize {
        size_of::<Pair>() * (conns + PAGES * PAGE)
            + size_of::<Option<Vec<Pair>>>() * PAGES
            + size_of::<Option<Waker>>() * MAX_PINGS
            + ARC_BYTES
    }

    /// 1 回の [`Wakers::collect`] の列で移しうる waker の数の上限です。表の行の数と、UDP の送りの待ち手の
    /// 1 つです。
    pub(crate) fn slots(conns: usize) -> usize {
        2 * (conns + PAGES * PAGE) + MAX_PINGS + 1
    }

    pub(crate) fn conn_read(&mut self, id: ConnId, w: &Waker) {
        if let Some(p) = self.conns.get_mut(id.index()) {
            set(&mut p.first, w);
        }
    }

    pub(crate) fn conn_write(&mut self, id: ConnId, w: &Waker) {
        if let Some(p) = self.conns.get_mut(id.index()) {
            set(&mut p.second, w);
        }
    }

    /// 接続を閉じた handle の waker を捨てます。
    pub(crate) fn clear_conn(&mut self, id: ConnId) {
        if let Some(p) = self.conns.get_mut(id.index()) {
            *p = Pair::default();
        }
    }

    /// ポート `port` の頁を確保します。待ち受けか endpoint を開く前に呼びます。
    pub(crate) fn open_port(&mut self, port: u16) -> Result<(), AllocError> {
        let page = &mut self.ports[usize::from(port) / PAGE];
        if page.is_none() {
            *page = Some(try_filled(PAGE, Pair::default)?);
        }
        Ok(())
    }

    fn port(&mut self, port: u16) -> Option<&mut Pair> {
        let p = usize::from(port);
        self.ports[p / PAGE]
            .as_mut()
            .map(|page| &mut page[p % PAGE])
    }

    pub(crate) fn accept(&mut self, port: u16, w: &Waker) {
        if let Some(p) = self.port(port) {
            set(&mut p.first, w);
        }
    }

    pub(crate) fn clear_accept(&mut self, port: u16) {
        if let Some(p) = self.port(port) {
            p.first = None;
        }
    }

    pub(crate) fn udp_read(&mut self, port: u16, w: &Waker) {
        if let Some(p) = self.port(port) {
            set(&mut p.second, w);
        }
    }

    pub(crate) fn clear_udp_read(&mut self, port: u16) {
        if let Some(p) = self.port(port) {
            p.second = None;
        }
    }

    pub(crate) fn ping(&mut self, slot: usize, w: &Waker) {
        if let Some(p) = self.pings.get_mut(slot) {
            set(p, w);
        }
    }

    pub(crate) fn clear_ping(&mut self, slot: usize) {
        if let Some(p) = self.pings.get_mut(slot) {
            *p = None;
        }
    }

    /// UDP の送りの待ち手が待つ [`Notify`] です。
    pub(crate) fn udp_write(&self) -> Arc<UdpWrite> {
        Arc::clone(&self.udp_write)
    }

    /// 知らせ `ev` で起こす waker を `out` に移します。`udp_writable` は、この起床の中で UDP の送りの待ち手を
    /// 起こす waker を既に移したかの印です。知らない種類の知らせは無視します。
    pub(crate) fn collect(&mut self, ev: Event, out: &mut Vec<Waker>, udp_writable: &mut bool) {
        match ev {
            Event::Readable(id) => {
                if let Some(p) = self.conns.get_mut(id.index()) {
                    take(&mut p.first, out);
                }
            }
            Event::Writable(id) => {
                if let Some(p) = self.conns.get_mut(id.index()) {
                    take(&mut p.second, out);
                }
            }
            Event::Closed(id) => {
                if let Some(p) = self.conns.get_mut(id.index()) {
                    take(&mut p.first, out);
                    take(&mut p.second, out);
                }
            }
            Event::Acceptable(l) => {
                if let Some(p) = self.port(l.port()) {
                    take(&mut p.first, out);
                }
            }
            Event::UdpReadable(u) => {
                if let Some(p) = self.port(u.port()) {
                    take(&mut p.second, out);
                }
            }
            Event::UdpWritable(_) => {
                if !*udp_writable {
                    *udp_writable = true;
                    out.push(self.udp_write_waker.clone());
                }
            }
            Event::PingReply(id) => {
                if let Some(p) = self.pings.get_mut(id.index()) {
                    take(p, out);
                }
            }
            // dial の側が足す `Connected` と `ConnectFailed` のような知らない知らせを、黙って捨てないよう
            // 試験と debug の build で止めます。製品の build では捨てます。
            other => debug_assert!(false, "the waker table does not handle {other:?}"),
        }
    }
}
