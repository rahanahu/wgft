//! wgft の TCP/IP の stack、wgstack の Rust 版の核です。
//!
//! 核は sans-IO です。入力は時刻、packet、アプリケーションの操作で、出力は packet、次に起こす時刻、
//! 知らせです。核の中にスレッド、実時間のタイマー、ソケット、OS の乱数を置きません。
//! 設計は `docs/design/v2/wgstack-rs.md` にあり、振る舞いの正本は凍結した Go の wgstack
//! (`internal/wgstack`) とその設計文書です。移行の間は Go の wgstack と同じ入力に同じ packet を返します。
//!
//! 核は段を踏んで作ります。今の段は、受動の open、閉じる手順と TIME_WAIT、アプリケーションの操作と知らせ、
//! データの送受信 (受け手の ACK と窓の自動調整、RTO、窓の probe)、SACK による回復と D-SACK、RACK-TLP、不要な
//! 再送の取り消し、CUBIC と NewReno、boost の取得と回収、UDP の endpoint と予算、echo と ping、ICMP の誤りと PMTU、
//! 断片の再組み立ての入口までです。
//!
//! 依存と確保の規則:この crate は標準ライブラリだけに依り、unsafe を使いません。
//! 可変長の保持は容量を作成の時に決める配列だけで持ち、容量を自動で伸ばす API を使いません。
//! この規則は `clippy.toml` の禁止の一覧と、source を走査する試験が確かめます。

#![forbid(unsafe_code)]
// 表の大きさを数える `heap_bytes` と一部の小さな部品は上界と不変条件の試験だけが使い、試験の道具の一部の欄は
// Go の試験の道具の形を写しただけで読みません。
#![expect(
    dead_code,
    reason = "heap_bytes and a few small helpers serve only the bound and invariant tests"
)]

mod bitset;
mod bound;
mod budget;
mod buf;
mod config;
mod event;
mod fixed_vec;
mod frag;
mod icmp;
mod index;
mod output;
mod rng;
mod seq;
mod siphash;
mod stack;
mod tcp;
mod time;
mod udp;
mod wheel;
mod wire;

pub use bound::{Bound, Held};
pub use budget::{Budget, BudgetError};
pub use config::{BoostPolicy, Config, ConfigError, Congestion, Limits, MAX_MTU, MIN_MTU};
pub use icmp::PingId;
pub use stack::{
    Closed, Error, Event, Hook, InvariantError, ListenerId, LogKind, LogLine, NewError,
    NewErrorKind, NoHook, Stack, Stats,
};
pub use tcp::conn::ConnId;
pub use time::Time;
pub use udp::{UdpFault, UdpId};

/// cargo-fuzz の target が呼ぶ入口です。`--cfg fuzzing` の build だけにあり、製品の API ではありません。
#[cfg(fuzzing)]
pub mod fuzz {
    /// `parse` の target:packet の解釈と checksum と再組み立ての表に任意の bytes を通します。
    pub fn parse(data: &[u8]) {
        crate::wire::fuzz_parse(data);
    }
}

#[cfg(test)]
mod boost_tests;
#[cfg(test)]
mod cc_tests;
#[cfg(test)]
mod golden_tests;
#[cfg(test)]
mod icmp_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod rack_tests;
#[cfg(test)]
mod sack_tests;
#[cfg(test)]
mod sackpeer_tests;
#[cfg(test)]
mod scan_tests;
#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
mod testnet_tests;
#[cfg(test)]
mod undo_tests;
