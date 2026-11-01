//! 設定ファイルの権限に関する 2 つの文。読めなかったときの事実の並べと、世界に読める dotenv の警告。

use std::path::Path;

/// Go の `*os.PathError` の文。Unix の `strerror` の文は Go の `syscall.Errno` の文と、先頭の大文字だけが
/// 違う。Windows の文は Go も OS の文のままである。
pub fn go_style_path_error(op: &str, path: &Path, e: &std::io::Error) -> String {
    let msg = crate::oserror::os_text(e);
    let msg = if cfg!(unix) {
        crate::oserror::lower_first(&msg)
    } else {
        msg
    };
    format!("{op} {}: {msg}", path.display())
}

/// 設定ファイルを読めなかったときに、原因を見分けるための事実を 1 句で返す。読んだプロセスの実効 uid と
/// gid、ファイルの持ち主とパーミッションを並べ、どちらの側に原因があるかは述べない。
pub(super) fn read_facts(path: &Path) -> String {
    config_file_perm_facts(path).0
}

/// [`read_facts`] の句と、ファイル自身の持ち主とパーミッションを読めたかどうか (Go の
/// `configFilePermFacts`)。読めなかった場合は上の階層のディレクトリが通り抜けを拒んでいる。
#[cfg(unix)]
#[must_use]
pub fn config_file_perm_facts(path: &Path) -> (String, bool) {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid と getegid は引数を取らず、失敗しない。
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let who = format!("this process runs as uid {uid}, gid {gid}");
    match std::fs::metadata(path) {
        // パーミッションは常に 4 桁で書く
        Ok(m) => (
            format!(
                "{who}, and the file is mode {:04o} with owner uid {} and group gid {}",
                m.mode() & 0o777,
                m.uid(),
                m.gid()
            ),
            true,
        ),
        Err(e) => (
            format!(
                "{who}, and the file's own owner and mode could not be read, so a directory above it refuses the way in: {}",
                go_style_path_error("stat", path, &e)
            ),
            false,
        ),
    }
}

/// Windows では、読めるかを決める DACL を評価しない。ファイル自身を読んでいないので第 2 の値は偽である。
#[cfg(not(unix))]
#[must_use]
pub fn config_file_perm_facts(_path: &Path) -> (String, bool) {
    (
        "who may read it is decided by the file's DACL, which this build does not evaluate"
            .to_owned(),
        false,
    )
}

/// ファイルを other が読めるか。判定は `0o007` のビットだけで、group のビットは見ない。
/// 推奨の配置は root 所有でグループ wgft の 0640 で、これは意図した共有である。Windows では判定しない。
#[cfg(unix)]
#[must_use]
pub fn readable_by_other(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|m| m.mode() & 0o007 != 0)
}

/// Windows では判定しない。
#[cfg(not(unix))]
#[must_use]
pub fn readable_by_other(_path: &Path) -> bool {
    false
}

/// 秘密の値を持つ dotenv を other が読めるときの警告の 1 行。
#[must_use]
pub fn insecure_file_warning(path: &Path) -> String {
    format!(
        "warning: {} is readable by other users on this host and holds a secret value, WGFT_JOIN; recommended mode is 0600, or 0640 owned by root and a dedicated group; see docs/design.md 11a",
        path.display()
    )
}
