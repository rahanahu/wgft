//! dotenv の読み取り (仕様 `cli-config.md` の dotenv の構文)。
//!
//! systemd、Docker の `--env-file`、compose の `env_file` の解釈が一致する範囲だけを受ける。誤りの文面は
//! 行の中身も値も出さない。行が `WGFT_JOIN` の接続文字列のような秘密を含みうるためである。

use std::collections::HashMap;
use std::path::Path;

use crate::error::Refusal;

/// 読み取った対応表。同じキーが複数あれば最後の行が勝つ。
pub type Map = HashMap<String, String>;

/// 構文の誤り。最初に誤った行で止まる。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    /// 1 から数えた行番号。CRLF の行も 1 行と数える。
    pub line: usize,
    /// 理由の文面。行の中身も値も含まない。
    pub reason: String,
}

/// 本文を読む。
pub fn parse(text: &str) -> Result<Map, SyntaxError> {
    let mut out = Map::new();
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |reason: String| SyntaxError {
            line: i + 1,
            reason,
        };
        let Some((key, val)) = line.split_once('=').filter(|(k, _)| !k.is_empty()) else {
            return Err(at(
                "not in KEY=value form; the line is not shown, since it may hold a secret".into(),
            ));
        };
        // 前後の Unicode の空白と、キーの中の空白とタブ。垂直タブなどが中にあるキーは通す
        if key.trim() != key || key.contains([' ', '\t']) {
            return Err(at("key name may not contain whitespace; the line is not shown, since it may hold a secret".into()));
        }
        if val.starts_with(['"', '\'']) {
            return Err(at(format!(
                "do not quote the value of {}; Docker keeps quotes as part of the value",
                key_label(key)
            )));
        }
        if val.contains([' ', '\t']) {
            return Err(at(format!(
                "the value of {} may not contain whitespace",
                key_label(key)
            )));
        }
        out.insert(key.to_owned(), val.to_owned());
    }
    Ok(out)
}

/// 構文の誤りの文面に出すキー。ASCII の英数字と `_` だけならそのまま、それ以外は出さない。
/// 行が壊れていると、`=` より前に値の一部が入りうるためである。
fn key_label(key: &str) -> &str {
    if !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        key
    } else {
        "this key"
    }
}

/// 読み取りの失敗。
#[derive(Debug)]
pub enum ReadError {
    /// 構文の誤り。種別 `config`、対象 `パス:行` の拒否で、終了コード 3。
    Syntax(Refusal),
    /// 権限で読めない。種別 `config`、対象パスの拒否。呼び手が直し方を足す。`agent doctor` は拒否にせず所見にする。
    Permission(Refusal),
    /// その他。パスがディレクトリの場合など。終了コード 1。
    Other(String),
}

impl ReadError {
    /// 拒否か普通の誤りにする。
    #[must_use]
    pub fn into_error(self) -> crate::AgentError {
        match self {
            ReadError::Syntax(r) | ReadError::Permission(r) => r.into(),
            ReadError::Other(s) => crate::AgentError::Other(s),
        }
    }
}

/// ファイルを読む。無ければ空の対応表である。ENOENT だけが無いことを表し、ENOTDIR は普通の誤りになる。
pub fn read(path: &Path) -> Result<Map, ReadError> {
    let shown = path.display().to_string();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let os = os_error_text(&e);
            return Err(ReadError::Permission(Refusal::config(
                &shown,
                format!("open {shown}: {os}; {}", super::perms::read_facts(path)),
            )));
        }
        Err(e) => {
            return Err(ReadError::Other(format!(
                "read {shown}: {}",
                strip_os_suffix(&e.to_string())
            )));
        }
    };
    // 仕様はバイト列を UTF-8 として扱う。UTF-8 でない設定は、黙って別の値に化かさず拒む (Go との差)
    let Ok(text) = String::from_utf8(bytes) else {
        return Err(ReadError::Syntax(Refusal::config(
            &shown,
            "is not valid UTF-8; the file is not shown, since it may hold a secret",
        )));
    };
    parse(&text)
        .map_err(|e| ReadError::Syntax(Refusal::config(&format!("{shown}:{}", e.line), e.reason)))
}

/// Go の `*os.PathError` の末尾の文。権限の誤りは Unix では `permission denied` で、
/// Windows では OS の文 (末尾の句点と空白は除く)。
fn os_error_text(e: &std::io::Error) -> String {
    if cfg!(unix) {
        "permission denied".to_owned()
    } else {
        strip_os_suffix(&e.to_string())
            .trim_end_matches(['.', ' '])
            .to_owned()
    }
}

/// `std::io::Error` の文から `(os error N)` の接尾辞を除く。
pub(super) fn strip_os_error(e: &std::io::Error) -> String {
    strip_os_suffix(&e.to_string())
}

fn strip_os_suffix(s: &str) -> String {
    match s.rfind(" (os error ") {
        Some(i) if s.ends_with(')') => s[..i].to_owned(),
        _ => s.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_duplicate_wins_and_inner_equals_is_kept() {
        let m = parse("A=1\nA=2\nB=x=y\n").unwrap();
        assert_eq!(m["A"], "2");
        assert_eq!(m["B"], "x=y");
    }

    #[test]
    fn unicode_whitespace_around_a_key_is_refused() {
        // 前後の Unicode の空白は拒む。中の垂直タブは通す (Go の TrimSpace と ContainsAny の差)
        assert!(parse("\u{3000}A=1\n").is_err());
        assert!(parse("A\u{b}=1\n").is_err());
        assert!(parse("A\u{b}B=1\n").is_ok());
    }

    #[test]
    fn missing_file_is_empty_and_directory_is_not() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(&dir.path().join("none.env")).unwrap().is_empty());
        assert!(matches!(read(dir.path()), Err(ReadError::Other(_))));
    }

    #[test]
    fn a_path_through_a_file_is_an_ordinary_error() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, "A=1\n").unwrap();
        assert!(matches!(read(&f.join("x")), Err(ReadError::Other(_))));
    }

    #[test]
    fn invalid_utf8_is_a_syntax_refusal_without_content() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.env");
        std::fs::write(&f, b"WGFT_JOIN=\xff\xfe\n").unwrap();
        let Err(ReadError::Syntax(r)) = read(&f) else {
            panic!("expected a syntax refusal");
        };
        assert!(!r.to_string().contains("WGFT_JOIN="));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_gives_the_facts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.env");
        std::fs::write(&f, "A=1\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        // root は権限に関係なく読めるので、読めた場合は確かめない
        if let Err(ReadError::Permission(r)) = read(&f) {
            let s = r.to_string();
            assert!(
                s.starts_with(&format!(
                    "refusing to start [config {p}]: open {p}: permission denied; this process runs as uid ",
                    p = f.display()
                )),
                "{s}"
            );
            assert!(
                s.contains("and the file is mode 0000 with owner uid "),
                "{s}"
            );
        }
    }
}
