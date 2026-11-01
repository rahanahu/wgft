//! OS ごとの層。既定のパス、ファイルの保護 (Windows の DACL)、制御ソケットの搬送、ファイル記述子の上限を
//! 持つ。Linux、macOS、Windows の差はこの module に閉じ込め、他の module は OS を見分けない。
//! 作りは `docs/design/v2/agent-parity.md` の「platform の層」に書く。

pub mod ctlsock;
pub mod fdlimit;
pub mod paths;
#[cfg(windows)]
pub mod winsec;
