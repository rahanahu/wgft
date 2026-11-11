#![doc = include_str!("../README.md")]
// 内部の注:核は wgft の Go の wgstack の Rust への移植で、設計は `docs/design/v2/wgstack-rs.md` にあります。
// 依存と確保の規則:この crate は標準ライブラリだけに依り、unsafe を使いません。可変長の保持は容量を作成の時に
// 決める配列だけで持ち、容量を自動で伸ばす API を使いません。この規則は `clippy.toml` の禁止の一覧と、source を
// 走査する試験が確かめます。
#![forbid(unsafe_code)]

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
#[cfg(any(test, feature = "harness"))]
#[doc(hidden)]
pub use stack::{Spare, TouchedCheck};
#[cfg(feature = "harness")]
#[doc(hidden)]
pub use stack::{
    go_compat_core_challenge, go_compat_dsack_snd_una, go_compat_echo_drop,
    go_compat_pmtu_keep_cwnd, go_compat_row_rst, go_compat_rto_l2, go_compat_sent_at_zero,
    go_compat_shared_id, go_compat_synack_rto, go_compat_tw_no_paws, go_compat_tw_no_ts_recent,
    go_compat_tw_reuse_strict, set_go_compat_core_challenge, set_go_compat_dsack_snd_una,
    set_go_compat_echo_drop, set_go_compat_pmtu_keep_cwnd, set_go_compat_row_rst,
    set_go_compat_rto_l2, set_go_compat_sent_at_zero, set_go_compat_shared_id,
    set_go_compat_synack_rto, set_go_compat_tw_no_paws, set_go_compat_tw_no_ts_recent,
    set_go_compat_tw_reuse_strict,
};
pub use tcp::conn::ConnId;
pub use time::Time;
pub use udp::{UdpFault, UdpId};

/// The number of ping endpoints a stack has; [`PingId::index`] is below it.
pub const MAX_PINGS: usize = icmp::PING_ENDPOINTS;
/// The smallest MSS a SYN may announce. A SYN with a smaller MSS is dropped and counted as
/// [`LogKind::MssFloor`].
pub const MIN_MSS: usize = 536;
const _: () = assert!(MIN_MSS as u64 == buf::MIN_MSS);
/// One UDP endpoint may use 1 / `UDP_ENDPOINT_SHARE` of the stack's UDP receive and send budgets.
pub const UDP_ENDPOINT_SHARE: usize = udp::ENDPOINT_SHARE;

/// この crate が整数の溢れを検査する build かを、この crate の中で実際に溢れさせて確かめます。検査ありなら溢れの
/// 足し算が panic し、検査なしなら回り込んで返ります。試験と fuzz の道具 (feature `harness`) が、
/// `-C overflow-checks=off` や `--config 'profile.release.package.wgft-wgstack.overflow-checks=false'` が
/// 核に本当に効いたかを判じる canary です。設定は crate ごとに効くので、呼び手の crate ではなく核の中で試します。
/// release の profile 全体に検査を入れているので、後者の指定が外すのは核の generic でない部分だけです。
/// generic な部分は使う側の crate の設定で決まるため、全体を外すには `profile.release.overflow-checks=false`
/// か `-C overflow-checks=off` を使います。
/// panic は呼び手の hook を一時的に外して受けます。
#[cfg(feature = "harness")]
#[doc(hidden)]
#[must_use]
#[inline(never)]
#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "a harness-only probe; the empty hook allocates nothing that matters and the core's data path never calls it"
)]
pub fn overflow_checks_enabled() -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let panicked = std::panic::catch_unwind(|| {
        core::hint::black_box(core::hint::black_box(u32::MAX) + core::hint::black_box(1))
    })
    .is_err();
    std::panic::set_hook(prev);
    panicked
}

// A stack without a hook can move to another thread; it has no thread-bound state.
const _: fn() = || {
    fn send<T: Send>() {}
    send::<Stack<NoHook>>();
    send::<Budget>();
};

/// Entry points for the cargo-fuzz targets; only in `--cfg fuzzing` builds and not part of the API.
#[cfg(fuzzing)]
pub mod fuzz {
    /// The `parse` target: runs arbitrary bytes through packet parsing, checksums and reassembly.
    pub fn parse(data: &[u8]) {
        crate::wire::fuzz_parse(data);
    }
}

#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod boost_tests;
#[cfg(test)]
mod cc_tests;
#[cfg(test)]
mod challenge_budget_tests;
#[cfg(test)]
mod dnat_peer_tests;
#[cfg(test)]
mod golden_tests;
#[cfg(test)]
mod icmp_tests;
#[cfg(test)]
mod ipv4_id_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod listen_tests;
#[cfg(test)]
mod netsim_tests;
#[cfg(test)]
mod overflow_tests;
#[cfg(test)]
mod rack_tests;
#[cfg(test)]
mod rfc6191_tests;
#[cfg(test)]
mod rto_l1_tests;
#[cfg(test)]
mod rto_wire_tests;
#[cfg(test)]
mod sack_tests;
#[cfg(test)]
mod sackpeer_tests;
#[cfg(test)]
mod scan_tests;
#[cfg(test)]
mod send_window_tests;
#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
mod testnet_tests;
#[cfg(test)]
mod touched_tests;
#[cfg(test)]
mod undo_tests;
#[cfg(test)]
mod whitebox_tests;
#[cfg(test)]
mod wscale_tests;
