//! OS ごとの層。既定のパス、ファイルの保護 (Windows の DACL)、制御ソケットの搬送、ファイル記述子の上限を
//! 持つ。Linux、macOS、Windows の差はこの module に閉じ込め、他の module は OS を見分けない。
//! 作りは `docs/design/v2/agent-parity.md` の「platform の層」に書く。

pub mod ctlsock;
pub mod fdlimit;
pub mod paths;
#[cfg(windows)]
pub mod winsec;

/// NUL で終わる UTF-16 の文字列を読む。
///
/// # Safety
///
/// `p` は NUL で終わる有効な UTF-16 の列を指し、呼び出しの間は読めること。
#[cfg(windows)]
pub(crate) unsafe fn utf16z_to_string(p: *const u16) -> String {
    let mut n = 0;
    // SAFETY: 呼び出し側の約束で、NUL まで読める
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: 上で数えた n 個の要素は読める
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}
