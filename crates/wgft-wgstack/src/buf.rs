//! 接続ごとのバッファ:chunk の置き場、送受信の輪、順序外の区間の treap、送信の記録の輪。
//!
//! 値は Go の wgstack (`const.go`) と同じで、設定の項目にしません。

pub(crate) mod chunk;
pub(crate) mod records;
pub(crate) mod recv;
pub(crate) mod ring;

/// 送信のバッファの floor (f_s) です。
pub(crate) const SEND_FLOOR: u64 = 256 << 10;
/// 受信のバッファの floor (f_r) です。
pub(crate) const RECV_FLOOR: u64 = 256 << 10;
/// boost の段の送信と受信のバッファの大きさ (floor + d_s、floor + d_r) です。
pub(crate) const BOOST_SIZE: u64 = 4 << 20;
/// boost の枠の数 (B) です。プロセスで 1 つの集まりです。
pub(crate) const BOOST_SLOTS: usize = 16;
/// 送り残しを分ける大きさの下限です。送信の記録の輪の容量は、送信のバッファの予約をこの値で割った数です。
pub(crate) const MIN_SEG_PAYLOAD: u64 = 472;
/// SYN の MSS の下限です。区間の数の上限の計算に使います。
pub(crate) const MIN_MSS: u64 = 536;
/// floor の送信の記録の輪の容量です。
#[expect(clippy::cast_possible_truncation, reason = "a small table size")]
pub(crate) const FLOOR_RECORDS: usize = SEND_FLOOR.div_ceil(MIN_SEG_PAYLOAD) as usize;
/// boost の送信の記録の輪の容量です。
#[expect(clippy::cast_possible_truncation, reason = "a small table size")]
pub(crate) const BOOST_RECORDS: usize = BOOST_SIZE.div_ceil(MIN_SEG_PAYLOAD) as usize;
/// floor の順序外の区間の数の上限 (H) です。MSS の下限の segment が 1 つおきに失われる最悪の場合を覆います。
#[expect(clippy::cast_possible_truncation, reason = "a small table size")]
pub(crate) const FLOOR_INTERVALS: usize = RECV_FLOOR.div_ceil(2 * MIN_MSS) as usize;
/// boost の順序外の区間の数の上限です。
#[expect(clippy::cast_possible_truncation, reason = "a small table size")]
pub(crate) const BOOST_INTERVALS: usize = BOOST_SIZE.div_ceil(2 * MIN_MSS) as usize;

const _: () = {
    assert!(FLOOR_RECORDS == 556 && BOOST_RECORDS == 8887);
    assert!(FLOOR_INTERVALS == 245 && BOOST_INTERVALS == 3913);
};
