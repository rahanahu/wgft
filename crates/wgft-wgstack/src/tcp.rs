//! TCP の表:接続の枠、握手の途中の表、TIME_WAIT の表、待ち受けの表。
//!
//! この段は表の置き場と出し入れだけを持ちます。表を使う TCP の規則 (受け入れ、握手、閉じる手順) は核の段
//! (PR 4a 以降) が足します。

pub(crate) mod conn;
pub(crate) mod listen;
pub(crate) mod syn;
pub(crate) mod timewait;

/// 接続の枠に固定で埋め込むタイマーの数です (再送と窓の probe、遅延 ACK、TIME_WAIT と FIN_WAIT_2 の期限、
/// 用意だけの keepalive)。タイマーの輪の節は枠の番号 × この数 + 種類です。
pub(crate) const NUM_TIMERS: usize = 4;
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
