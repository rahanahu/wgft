//! 登録 API `POST /api/v1/agents/register` の本文 (Go の `internal/agent/enroll` と
//! `internal/vpsd/agentapi`)。

use serde::{Deserialize, Serialize};

/// 登録の要求。Go のエージェントは名前が空でも `name` を送る。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    /// エージェント名。空ならトークンに結び付いた名前になる。
    pub name: String,
    /// 接続文字列の 1 回限りのトークン。
    pub token: String,
}

impl std::fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("token", &"<redacted>")
            .field("name", &self.name)
            .finish()
    }
}

/// 登録の応答。
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    /// 恒久トークン。
    #[serde(default)]
    pub permanent_token: String,
    /// 割り当てたトンネルのアドレス。
    #[serde(default)]
    pub address: String,
    /// 確定したエージェント名。
    #[serde(default)]
    pub name: String,
}

impl std::fmt::Debug for RegisterResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterResponse")
            .field("permanent_token", &"<redacted>")
            .field("address", &self.address)
            .field("name", &self.name)
            .finish()
    }
}

/// 登録の応答を読む量の上限 (byte)。
pub const REGISTER_RESPONSE_LIMIT: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape() {
        // Go の json.Marshal(map[string]string) はキーを辞書順に書く
        let r = RegisterRequest {
            token: "t".into(),
            name: String::new(),
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"name":"","token":"t"}"#
        );
    }
}
