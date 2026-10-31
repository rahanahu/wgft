//! wgft の共有コードの置き場。移行の間はまだ空に近い。

/// ビルドした wgft の版。
///
/// ```
/// assert!(!wgft::VERSION.is_empty());
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
