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
/// SYN-ACK の再送の回数 (Linux の tcp_synack_retries) です。握手の途中の表は回数ごとに list を持ちます。
pub(crate) const SYNACK_RETRIES: usize = 5;
