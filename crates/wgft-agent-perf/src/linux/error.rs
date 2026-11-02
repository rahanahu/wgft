//! The tool's one error type; every failure ends in a line on stderr.

use std::fmt;

#[derive(Debug)]
pub(super) enum Error {
    /// A system call or socket failed; printed as the operating system describes it.
    Io(std::io::Error),
    /// Anything else, with its own sentence.
    Failed(String),
}

impl Error {
    pub(super) fn failed(msg: impl Into<String>) -> Self {
        Self::Failed(msg.into())
    }

    /// An I/O failure with a leading sentence: `what: reason`.
    pub(super) fn context(what: &str, e: &impl fmt::Display) -> Self {
        Self::Failed(format!("{what}: {e}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Failed(m) => f.write_str(m),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
