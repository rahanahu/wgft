//! 起動の拒否と、それ以外の誤り。
//!
//! 起動の拒否は再起動では直らない失敗で、`wgft` は終了コード 3 で終わる。同梱の systemd の unit の
//! `RestartPreventExitStatus=3` が再起動を止める。それ以外の誤りは終了コード 1 で、再起動で直りうる。

use std::fmt;

/// 起動の拒否の種類 (Go の `internal/startup` の `Category`)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    /// 設定の値の誤り。
    Config,
    /// 環境の前提の不足。
    Prerequisite,
    /// 他の状態との食い違い。
    Conflict,
}

impl Category {
    fn as_str(self) -> &'static str {
        match self {
            Category::Config => "config",
            Category::Prerequisite => "prerequisite",
            Category::Conflict => "conflict",
        }
    }
}

/// 起動の拒否。文面は Go の `startup.Refusal` と同じ形にする。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// 種類。
    pub category: Category,
    /// 対象の設定の名前。
    pub subject: String,
    /// 理由。
    pub reason: String,
}

impl Refusal {
    /// 設定の値の誤り。
    #[must_use]
    pub fn config(subject: &str, reason: impl Into<String>) -> Self {
        Refusal {
            category: Category::Config,
            subject: subject.to_owned(),
            reason: reason.into(),
        }
    }

    /// 環境の前提の不足。
    #[must_use]
    pub fn prerequisite(subject: &str, reason: impl Into<String>) -> Self {
        Refusal {
            category: Category::Prerequisite,
            subject: subject.to_owned(),
            reason: reason.into(),
        }
    }

    /// 他の状態との食い違い。
    #[must_use]
    pub fn conflict(subject: &str, reason: impl Into<String>) -> Self {
        Refusal {
            category: Category::Conflict,
            subject: subject.to_owned(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refusing to start [{}", self.category.as_str())?;
        if !self.subject.is_empty() {
            write!(f, " {}", self.subject)?;
        }
        write!(f, "]: {}", self.reason)
    }
}

impl std::error::Error for Refusal {}

/// agent の誤り。
#[derive(Debug)]
pub enum AgentError {
    /// 起動の拒否。終了コード 3。
    Refused(Refusal),
    /// それ以外。終了コード 1。
    Other(String),
}

impl AgentError {
    /// プロセスの終了コード。
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            AgentError::Refused(_) => 3,
            AgentError::Other(_) => 1,
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Refused(r) => r.fmt(f),
            AgentError::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<Refusal> for AgentError {
    fn from(r: Refusal) -> Self {
        AgentError::Refused(r)
    }
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        AgentError::Other(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_text_matches_go() {
        let r = Refusal::config(
            "WGFT_JOIN",
            "not registered and no join string; provide via WGFT_JOIN or --join",
        );
        assert_eq!(
            r.to_string(),
            "refusing to start [config WGFT_JOIN]: not registered and no join string; provide via WGFT_JOIN or --join"
        );
        assert_eq!(AgentError::from(r).exit_code(), 3);
    }
}
