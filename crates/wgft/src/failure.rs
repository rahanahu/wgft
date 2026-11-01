//! コマンドの失敗と終了コード (仕様 `cli-config.md` の終了コード)。
//!
//! 標準エラーに `Error: <文>` の 1 行を書き、終了コードは拒否が 3、報告を作れなかった失敗が 2、
//! それ以外が 1 である。拒否を別の誤りが包んでも 3 のままである。

use wgft_agent::AgentError;

/// 終了コード付きの失敗。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// `Error: ` の後ろに書く文。
    pub message: String,
    /// プロセスの終了コード。
    pub code: u8,
}

impl Failure {
    /// 文と終了コードから作る。
    #[must_use]
    pub fn new(message: impl Into<String>, code: u8) -> Self {
        Failure {
            message: message.into(),
            code,
        }
    }

    /// 求められた報告を作れなかった失敗。`agent doctor` だけが使う。
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Failure::new(message, 2)
    }
}

impl From<AgentError> for Failure {
    fn from(e: AgentError) -> Self {
        Failure::new(e.to_string(), u8::try_from(e.exit_code()).unwrap_or(1))
    }
}
