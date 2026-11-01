//! トンネルへ待たずに送る `send_to_latest` が datagram ごとにヒープを確保しないことの試験。
//!
//! 出力を運ばないので、送信の予算が尽き、送るたびに最も古い datagram を捨てる形になります。慣らしの後は、
//! 確保が 1 回も起きないことを、スレッドごとの測りの窓の最大値で確かめます。数えはプロセスで 1 つなので、
//! この試験は自分の試験のバイナリに 1 つだけ置きます。

#[expect(dead_code, reason = "this binary uses only the hand-driven helpers")]
mod common;

use std::net::SocketAddrV4;
use std::time::Duration;

use common::{A, B, netstack};
use wgft_alloc_count::{CountingAlloc, ThreadWindow};
use wgft_netstack::{Access, UdpSocket};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

#[test]
fn send_to_latest_does_not_allocate_once_the_budget_is_full() {
    let far = netstack(B);
    let ub = UdpSocket::bind(&far, SocketAddrV4::new(B, 5353)).unwrap();
    let tx = ub.sender();
    let to = SocketAddrV4::new(A, 53);
    let msg = common::pattern(1000, 5);
    // 慣らし:予算が尽きて捨てる形になるまで送る
    for _ in 0..2000 {
        tx.send_to_latest(&msg, to, Duration::from_millis(100))
            .unwrap();
    }
    let st = far.with(|n| n.core().stats());
    assert!(st.udp_send_evicted > 0, "the budget never filled");
    let window = ThreadWindow::open();
    for i in 0..5000 {
        let size = 1 + (i * 37) % msg.len();
        tx.send_to_latest(&msg[..size], to, Duration::from_millis(100))
            .unwrap();
        assert_eq!(window.peak(), 0, "send {i} allocated");
    }
    assert_eq!(window.grown(), 0);
    far.with(|n| n.core().check_invariants()).unwrap();
}
