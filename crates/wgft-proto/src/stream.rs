//! stream (`GET /api/v1/agents/stream` の WebSocket) のメッセージ (Go の `proto/stream.go`)。

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::gotime::GoTime;
use crate::state::State;

/// メッセージの種類。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    /// エージェントから server へ。接続の直後の最初のメッセージ。
    PublicKey,
    /// server からエージェントへ。全体状態。
    State,
    /// エージェントから server へ。30 秒ごとと適用の直後。
    Heartbeat,
}

impl MessageType {
    /// JSON の `type` の値。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MessageType::PublicKey => "pubkey",
            MessageType::State => "state",
            MessageType::Heartbeat => "heartbeat",
        }
    }
}

/// stream の 1 メッセージ。`type` で中身を選ぶ。
///
/// `type` は知らない値も読めるように文字列で持つ。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// メッセージの種類。
    #[serde(rename = "type", default)]
    pub kind: String,
    /// `pubkey` の WireGuard の公開鍵 (base64)。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    /// `state` の全体状態。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    /// `heartbeat` の中身。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<Heartbeat>,
    /// `pubkey` に載る版の範囲の下端。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_min: Option<i64>,
    /// `pubkey` に載る版の範囲の上端。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_max: Option<i64>,
    /// `pubkey` に載る capability。無いこと (legacy v0) と空の列を区別する。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

/// stream の 1 通を読んだときの誤り。
#[derive(Debug)]
pub struct DecodeError(String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

impl Message {
    /// stream の 1 通を読む。Go の writer が書く形はすべて受ける。Go の writer が書かない形のうち、
    /// 大文字か ASCII でない文字を含むキーはメッセージごと拒む。Go はそのキーを case folding で既知の
    /// フィールドに当てるので、serde の既定のように知らないキーとして読み飛ばすと、Go と違う値になる。
    /// 重複したキー、スカラーの `null`、型の違いは serde の誤りで拒む
    /// (`docs/design/spec/encoding.md` の「拒んでよい形」)。
    ///
    /// # Errors
    ///
    /// JSON として読めないか、上の形に当たれば誤りを返す。
    ///
    /// キーの検査は値を組み立てずに 1 回読み、型の値はその後に読む。検査の側は値を捨て、エスケープの無い
    /// キーは入力を借りて調べるので、確保はエスケープを含むキー 1 つ分の作業域だけである。汎用の値の木を
    /// 経由すると、小さな値を並べた 1 通が入力の数十倍の一時の確保になるためである。
    pub fn decode(text: &str) -> Result<Message, DecodeError> {
        serde_json::from_str::<KeyCheck>(text).map_err(|e| DecodeError(e.to_string()))?;
        serde_json::from_str(text).map_err(|e| DecodeError(e.to_string()))
    }

    /// stream の 1 通を byte 列から読む。不正な UTF-8 は Go の writer が書かない形なので拒む。
    /// WebSocket の text のフレームは UTF-8 なので、stream の上ではここに来る前に拒まれる。
    ///
    /// # Errors
    ///
    /// UTF-8 でないか、[`Message::decode`] の誤りに当たれば誤りを返す。
    pub fn decode_bytes(b: &[u8]) -> Result<Message, DecodeError> {
        Message::decode(str::from_utf8(b).map_err(|e| DecodeError(e.to_string()))?)
    }

    /// 種類が `t` かどうか。
    #[must_use]
    pub fn is(&self, t: MessageType) -> bool {
        self.kind == t.as_str()
    }
}

/// エージェントが stream を繋ぎ直す待ちの上限。
pub const RECONNECT_BACKOFF_MAX: Duration = Duration::from_mins(5);

/// オブジェクトのキーが、Go の writer が書く小文字の ASCII の形かどうかを確かめる。値は読み捨てる。
/// 入れ子の深さは serde_json の再帰の上限 (128) が抑える。
struct KeyCheck;

impl<'de> Deserialize<'de> for KeyCheck {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(KeyCheckVisitor)
    }
}

struct KeyCheckVisitor;

impl<'de> serde::de::Visitor<'de> for KeyCheckVisitor {
    type Value = KeyCheck;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<KeyCheck, E> {
        Ok(KeyCheck)
    }

    fn visit_i64<E>(self, _: i64) -> Result<KeyCheck, E> {
        Ok(KeyCheck)
    }

    fn visit_u64<E>(self, _: u64) -> Result<KeyCheck, E> {
        Ok(KeyCheck)
    }

    fn visit_f64<E>(self, _: f64) -> Result<KeyCheck, E> {
        Ok(KeyCheck)
    }

    fn visit_str<E>(self, _: &str) -> Result<KeyCheck, E> {
        Ok(KeyCheck)
    }

    fn visit_unit<E>(self) -> Result<KeyCheck, E> {
        Ok(KeyCheck)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<KeyCheck, A::Error> {
        while seq.next_element::<KeyCheck>()?.is_some() {}
        Ok(KeyCheck)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<KeyCheck, A::Error> {
        while map.next_key::<LowerKey>()?.is_some() {
            map.next_value::<KeyCheck>()?;
        }
        Ok(KeyCheck)
    }
}

/// Go の writer が書く形のキー。読むだけで持たない。
struct LowerKey;

impl<'de> Deserialize<'de> for LowerKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(LowerKeyVisitor)
    }
}

struct LowerKeyVisitor;

impl serde::de::Visitor<'_> for LowerKeyVisitor {
    type Value = LowerKey;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E: serde::de::Error>(self, k: &str) -> Result<LowerKey, E> {
        if k.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        {
            Ok(LowerKey)
        } else {
            Err(E::custom(format_args!(
                "key {k:?} is not a lower-case key a Go writer emits"
            )))
        }
    }
}

/// stream の 1 通の大きさの上限 (byte)。agent が読む全体状態はこの 1 通に収まる。
pub const STREAM_READ_LIMIT: usize = 4 << 20;

/// 読んだ 1 通が持つ確保の、入力の長さに対する倍率の上限。読む間の確保の最大値もこの内に収まる。
/// 最も密な形は空の文字列を並べた capability の列で、3 byte ごとに `String` の 24 byte を持ち、列の容量は
/// 長さの 2 倍まで育つので 16 倍である。ルールの列は 3 倍未満に収まる。試験 `tests/decode_held.rs` が
/// 確かめ、agent のメモリの上界の全体状態の項がこの値を使う。
pub const STATE_HELD_FACTOR: usize = 16;

/// ハートビート。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// 最後に受け取って処理した世代。
    #[serde(default)]
    pub generation: u64,
    /// トンネルの状態。
    #[serde(default)]
    pub tunnel: TunnelStatus,
    /// ルールごとの状態。Go のエージェントは空でも `[]` を書く。`null` は Go と同じく空として読む。
    #[serde(default, deserialize_with = "crate::state::null_as_empty")]
    pub rules: Vec<RuleStatus>,
}

/// 状態の値 `ok`。
pub const STATUS_OK: &str = "ok";
/// 状態の値 `error`。
pub const STATUS_ERROR: &str = "error";

/// トンネルの状態。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// `ok` か `error`。
    #[serde(default)]
    pub state: String,
    /// 理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// 解決したエンドポイント (`ip:port`)。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// 最終ハンドシェイク。Go は `omitempty` でも零の値を書くので、ここも常に書く。
    #[serde(default)]
    pub last_handshake: GoTime,
}

/// ルールごとの状態。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleStatus {
    /// ルールの ID。
    pub id: String,
    /// `ok` か `error`。
    pub state: String,
    /// 理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// ハートビートの理由の長さの上限 (byte)。切ったときの印はこの外に付く。
pub const REASON_MAX_BYTES: usize = 512;

/// WebSocket の close のコード (4000 番台はアプリケーション用)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseCode {
    /// 4000: 同じエージェントの新しい接続に置き換わった。
    Superseded,
    /// 4001: 恒久トークンが無効にされた。
    Revoked,
    /// 4002: ハートビートが 90 秒届かなかった。
    HeartbeatTimeout,
    /// 4003: 版の範囲の共通部分が無い。
    ProtocolMismatch,
    /// 4004: 版の宣言が壊れている。
    ProtocolMalformed,
}

impl CloseCode {
    /// 数値のコード。
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            CloseCode::Superseded => 4000,
            CloseCode::Revoked => 4001,
            CloseCode::HeartbeatTimeout => 4002,
            CloseCode::ProtocolMismatch => 4003,
            CloseCode::ProtocolMalformed => 4004,
        }
    }

    /// 数値のコードから。知らないコードは `None`。
    #[must_use]
    pub fn from_code(c: u16) -> Option<Self> {
        Some(match c {
            4000 => CloseCode::Superseded,
            4001 => CloseCode::Revoked,
            4002 => CloseCode::HeartbeatTimeout,
            4003 => CloseCode::ProtocolMismatch,
            4004 => CloseCode::ProtocolMalformed,
            _ => return None,
        })
    }
}

/// WebSocket の標準の close のコード 1008 (policy violation)。server は最初のメッセージが `pubkey` で
/// ないとき、公開鍵の検証に失敗したとき、鍵の変更の頻度の上限で断るときに使う。
pub const CLOSE_POLICY_VIOLATION: u16 = 1008;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_message_matches_the_go_agent_bytes() {
        // Go の agent が書く pubkey のメッセージ (proto.Message のフィールドの順)
        let m = Message {
            kind: MessageType::PublicKey.as_str().into(),
            public_key: "AAAA".into(),
            protocol_min: Some(1),
            protocol_max: Some(1),
            capabilities: Some(vec![]),
            ..Message::default()
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"type":"pubkey","public_key":"AAAA","protocol_min":1,"protocol_max":1,"capabilities":[]}"#
        );
    }

    #[test]
    fn heartbeat_writes_zero_time_and_empty_rules() {
        let m = Message {
            kind: MessageType::Heartbeat.as_str().into(),
            heartbeat: Some(Heartbeat {
                generation: 2,
                tunnel: TunnelStatus {
                    state: STATUS_ERROR.into(),
                    reason: "no tunnel".into(),
                    ..Default::default()
                },
                rules: vec![],
            }),
            ..Message::default()
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"type":"heartbeat","heartbeat":{"generation":2,"tunnel":{"state":"error","reason":"no tunnel","last_handshake":"0001-01-01T00:00:00Z"},"rules":[]}}"#
        );
    }

    #[test]
    fn close_codes_round_trip() {
        for c in [
            CloseCode::Superseded,
            CloseCode::Revoked,
            CloseCode::HeartbeatTimeout,
            CloseCode::ProtocolMismatch,
            CloseCode::ProtocolMalformed,
        ] {
            assert_eq!(CloseCode::from_code(c.code()), Some(c));
        }
        assert_eq!(CloseCode::from_code(1000), None);
    }
}
