//! TCP (Go の `tcb.go`、`tcpin.go`、`tcpout.go`、`ack.go`、`timers.go` などの写し)。
//!
//! 表 (接続の枠、握手の途中の表、TIME_WAIT の表、待ち受けの表) と、表を使う TCP の規則を持ちます。
//! 接続の規則は [`ctx::Conn`] の view のメソッドで、Go のファイルごとに module を分けます。
//! 値は Go の wgstack (`const.go`) と同じで、参照の実装の Linux の既定に合わせます。

pub(crate) mod ack;
pub(crate) mod ack_policy;
pub(crate) mod cc;
pub(crate) mod conn;
pub(crate) mod ctx;
pub(crate) mod input;
pub(crate) mod listen;
pub(crate) mod output;
pub(crate) mod rack;
pub(crate) mod rcv_window;
pub(crate) mod sack;
pub(crate) mod syn;
pub(crate) mod timers;
pub(crate) mod timewait;
pub(crate) mod undo;

/// 接続の枠に固定で埋め込むタイマーの数です (再送と窓の probe、遅延 ACK、TIME_WAIT と FIN_WAIT_2 の期限、
/// 用意だけの keepalive)。タイマーの輪の節は枠の番号 × この数 + 種類です。
pub(crate) const NUM_TIMERS: usize = 4;
/// [`NUM_TIMERS`] の `u32` の値です。
pub(crate) const NUM_TIMERS32: u32 = 4;

/// 空きの list `free` の番号が範囲の内にあり、重ならず、使っていない行を指すことを確かめます。
pub(crate) fn check_free_list(
    free: &[u32],
    rows: usize,
    used: impl Fn(usize) -> bool,
) -> Result<(), &'static str> {
    let mut seen = crate::fixed_vec::FixedVec::try_filled(rows, |_| false)
        .map_err(|_| "allocation failed while checking")?;
    for &i in free {
        let mark = seen
            .get_mut(i as usize)
            .ok_or("a free list number is out of range")?;
        if *mark {
            return Err("a row is twice in a free list");
        }
        *mark = true;
        if used(i as usize) {
            return Err("a free list holds a used row");
        }
    }
    Ok(())
}

/// SYN-ACK の再送の回数 (Linux の tcp_synack_retries) です。握手の途中の表は回数ごとに list を持ちます。
pub(crate) const SYNACK_RETRIES: usize = 5;

/// 1 ms の ns です。
pub(crate) const MS: i64 = 1_000_000;
/// 1 秒の ns です。
pub(crate) const SEC: i64 = 1_000 * MS;

/// SYN の MSS の下限で、MSS の option が無いときの値です (RFC 1122)。
pub(crate) const MIN_MSS: u32 = 536;
/// IPv4 と TCP の header の和です。
pub(crate) const IP_TCP_HEADERS: u32 = 40;
/// NOP NOP TS の 12 byte です。
pub(crate) const TS_OPTION_LEN: u32 = 12;
/// boost の 4 MiB を広告できる窓の scale です。
pub(crate) const RCV_WINDOW_SHIFT: u8 = 7;

pub(crate) const RTO_INIT: i64 = SEC;
pub(crate) const RTO_MIN: i64 = 200 * MS;
pub(crate) const RTO_MAX: i64 = 120 * SEC;
/// Linux の TCP_DELACK_MIN です。
pub(crate) const DELACK_TIMEOUT: i64 = 40 * MS;
/// TIME_WAIT の長さ (Linux の TCP_TIMEWAIT_LEN) です。
pub(crate) const TW_TIMEOUT: i64 = 60 * SEC;
/// 閉じた後の FIN_WAIT_2 の長さ (Linux の tcp_fin_timeout) です。
pub(crate) const FIN_TIMEOUT: i64 = 60 * SEC;
/// 最初の SYN-ACK の再送までの時間 (Linux の TCP_TIMEOUT_INIT) です。
pub(crate) const SYNACK_RTO: i64 = SEC;
/// Linux の tcp_retries2 です。
pub(crate) const RETRIES2: u32 = 15;
/// 応答の無い窓の probe の上限です。
pub(crate) const PROBE_RETRIES: i64 = 15;
/// 閉じた接続の窓の probe の後退の上限です。
pub(crate) const ORPHAN_RETRIES: u32 = 8;
/// IW10 (RFC 6928) です。
pub(crate) const INITIAL_WINDOW_SEGS: u32 = 10;
/// TS.Recent を古いとみなすまでの時間 (RFC 7323 5.5 の 24 日) です。
pub(crate) const PAWS_IDLE: i64 = 24 * 24 * 3600 * SEC;

/// Linux の tcp_model_timeout と同じく、最小の RTO から倍にしていった retries2 回の再送が使う時間です。
pub(crate) const RETRANSMIT_DEADLINE: i64 = {
    let mut total = 0;
    let mut rto = RTO_MIN;
    let mut i = 0;
    while i <= RETRIES2 {
        total += rto;
        rto = if rto * 2 < RTO_MAX { rto * 2 } else { RTO_MAX };
        i += 1;
    }
    total
};

/// 再送の原因です。[`crate::Stats::retrans`] の添字です。
pub(crate) const RTX_FAST: u8 = 0;
pub(crate) const RTX_PARTIAL: u8 = 1;
pub(crate) const RTX_RTO: u8 = 2;
pub(crate) const RTX_PMTU: u8 = 3;
pub(crate) const RTX_TLP: u8 = 4;

/// timestamp の時計です。1 ms ごとに進みます。
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "Go keeps the low 32 bits of the millisecond clock"
)]
pub(crate) fn ts_clock(now: i64) -> u32 {
    (now / MS) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retransmit_deadline_matches_linux() {
        // 0.2 + 0.4 + ... + 102.4 秒の 10 回と、上限の 120 秒の 6 回。
        assert_eq!(RETRANSMIT_DEADLINE, 204_600 * MS + 6 * RTO_MAX);
    }
}
