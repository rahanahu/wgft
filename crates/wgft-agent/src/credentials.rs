//! 認証情報 (`agent.json`)。Go の `internal/agent/credentials` と同じファイルを読み書きする。
//!
//! Go の v1 の agent が書いたファイルをそのまま読み、Rust の agent が書いたファイルを Go の v1 の agent が
//! 読めるようにする。カーネルモードの記録のように試作が使わない項目は、形を持たずに保存し直す。
//! 知らないキーも捨てずに保存し直す。

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use wgft_proto::State;

/// 認証情報のファイル名。
pub const FILE_NAME: &str = "agent.json";

/// 読み書きの大きさの上限 (Go の `credentials.MaxFileSize`)。
pub const MAX_FILE_SIZE: u64 = 512 << 20;

/// 保存の一時ファイルの名前の接頭辞。Go の agent と同じにし、どちらの片付けも同じファイルを見つける。
pub const TEMP_PREFIX: &str = ".wgft-credentials-";

/// `agent.json` の中身。フィールドの順は Go の構造体の宣言の順。
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    /// エージェント名。
    #[serde(default)]
    pub name: String,
    /// エージェント用 API の `host:port`。
    #[serde(default)]
    pub endpoint: String,
    /// エージェント用 API の証明書の SHA-256 (hex)。
    #[serde(default)]
    pub cert_sha256: String,
    /// 恒久トークン。
    #[serde(default)]
    pub permanent_token: String,
    /// 使用済みの登録トークンの SHA-256 (hex)。
    #[serde(default)]
    pub used_join_token_sha256: String,
    /// WireGuard の秘密鍵 (base64)。
    #[serde(default)]
    pub wg_private_key: String,
    /// 最後に処理した全体状態。Go は `null` も書く。
    #[serde(default)]
    pub last_state: Option<State>,
    /// 転送の方式の記録。空はユーザー空間モード。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    /// カーネルモードの 1 つ前の秘密鍵。試作は使わず保存し直すだけ。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous_wg_private_key: String,
    /// カーネルモードの記録。試作は使わず保存し直すだけ。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_forward_enabled_at: Option<Value>,
    /// カーネルモードの記録。試作は使わず保存し直すだけ。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_publication: Option<Value>,
    /// カーネルモードの記録。試作は使わず保存し直すだけ。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_unconverged: Option<Value>,
    /// 登録で割り当てられたトンネルのアドレスの記録。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tunnel_address: String,
    /// 知らないキー。保存し直す。
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// 恒久トークンと鍵を Debug に出さない
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("cert_sha256", &self.cert_sha256)
            .field("permanent_token", &"<redacted>")
            .field("wg_private_key", &"<redacted>")
            .field("mode", &self.mode)
            .field("tunnel_address", &self.tunnel_address)
            .finish_non_exhaustive()
    }
}

/// 認証情報の読み書きの誤り。
#[derive(Debug)]
pub enum CredentialsError {
    /// ファイルが無い。
    NotFound,
    /// 別のプロセスがロックを持っている。
    Locked,
    /// それ以外。
    Other(String),
}

impl std::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialsError::NotFound => f.write_str("the credentials file does not exist"),
            CredentialsError::Locked => {
                f.write_str("credentials file is in use by another process")
            }
            CredentialsError::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for CredentialsError {}

fn other(path: &Path, e: impl std::fmt::Display) -> CredentialsError {
    CredentialsError::Other(format!("credentials file {}: {e}", path.display()))
}

/// `path` を開く。最後の要素が symlink なら辿らず (Unix は `O_NOFOLLOW`)、開いた記述子の fstat で
/// 通常のファイルであることを確かめる。名前を差し替えられても、確かめたのは開いたファイルである。
fn open_regular(path: &Path, opts: &mut OpenOptions) -> std::io::Result<(File, fs::Metadata)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        // symlink を辿らず、リンク自身を開く。通常のファイルの検査で拒まれる
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(all(not(unix), not(windows)))]
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other("is a symbolic link"));
    }
    #[cfg(unix)]
    let f = opts.open(path).map_err(|e| {
        // O_NOFOLLOW は symlink に ELOOP を返す
        if e.raw_os_error() == Some(libc::ELOOP) {
            std::io::Error::other("is a symbolic link")
        } else {
            e
        }
    })?;
    #[cfg(windows)]
    let f = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
        // DACL をこの handle に付け直せるように WRITE_DAC つきで開く
        opts.access_mode(GENERIC_READ | WRITE_DAC | READ_CONTROL)
            .open(path)?
    };
    #[cfg(all(not(unix), not(windows)))]
    let f = opts.open(path)?;
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::other("is not a regular file"));
    }
    Ok((f, meta))
}

/// 読むだけのために `path` を開く。誤りの種類は開けなかった理由のままで、symlink と通常のファイルでない
/// ものは `Other` である。最後の要素の symlink を辿らず、通常のファイルでないものは拒む。
/// Windows でも DACL を付け直す権限を求めない。
pub fn open_regular_read(path: &Path) -> std::io::Result<(File, fs::Metadata)> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // FIFO を開いた時点で止まらないよう O_NONBLOCK も付ける。通常のファイルの読みには効かない
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(all(not(unix), not(windows)))]
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other(NOT_FOLLOWED));
    }
    #[cfg(unix)]
    let f = opts.open(path).map_err(|e| {
        // O_NOFOLLOW は symlink に ELOOP を返す
        if e.raw_os_error() == Some(libc::ELOOP) {
            std::io::Error::other(format!(
                "{} is a symbolic link, which wgft does not follow: not a regular file",
                path.display()
            ))
        } else {
            e
        }
    })?;
    #[cfg(not(unix))]
    let f = opts.open(path)?;
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file but {}: not a regular file",
            path.display(),
            describe_type(&meta)
        )));
    }
    Ok((f, meta))
}

#[cfg(all(not(unix), not(windows)))]
const NOT_FOLLOWED: &str = "is a symbolic link, which wgft does not follow";

/// 通常のファイルでないものの種別を 1 語で表す (Go の `flock.describeType`)。
fn describe_type(m: &fs::Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_symlink() {
        return "a symbolic link";
    }
    if t.is_dir() {
        return "a directory";
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if t.is_fifo() {
            return "a named pipe";
        }
        if t.is_socket() {
            return "a socket";
        }
        if t.is_block_device() || t.is_char_device() {
            return "a device";
        }
    }
    "an irregular file"
}

/// 認証情報ファイルを読むだけの誤り。
#[derive(Debug)]
pub enum ReadFileError {
    /// 開けないか読めない。種類は `kind` で見分ける。
    Io(std::io::Error),
    /// symlink、通常のファイルでないもの、大きすぎるもの。agent も同じ理由で起動しない。
    Refused(String),
}

impl std::fmt::Display for ReadFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadFileError::Io(e) => e.fmt(f),
            ReadFileError::Refused(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for ReadFileError {}

/// 認証情報ファイルの中身を読むだけの読み (Go の `credentials.ReadFile`)。symlink を辿らず、通常の
/// ファイルでないものと大きすぎるものを開いた記述子で拒む。Windows でも DACL を付け直さないので、
/// `agent doctor` と、稼働中の agent の横で鍵を読む `agent pubkey` が使う。
///
/// # Errors
///
/// 開けないか読めなければ誤りを返す。無ければ `NotFound` の [`ReadFileError::Io`] である。
pub fn read_file(path: &Path) -> Result<(Vec<u8>, fs::Metadata), ReadFileError> {
    let (f, meta) = open_regular_read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::Other {
            ReadFileError::Refused(e.to_string())
        } else {
            ReadFileError::Io(e)
        }
    })?;
    if meta.len() > MAX_FILE_SIZE {
        return Err(ReadFileError::Refused(format!(
            "{} is {} bytes, larger than wgft ever writes",
            path.display(),
            meta.len()
        )));
    }
    let mut b = Vec::new();
    f.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut b)
        .map_err(ReadFileError::Io)?;
    if b.len() as u64 > MAX_FILE_SIZE {
        return Err(ReadFileError::Refused(format!(
            "{} grew while being read, past what wgft ever writes",
            path.display()
        )));
    }
    Ok((b, meta))
}

/// agent.json の書き方。Go の `json.MarshalIndent(f, "", "  ")` と同じく 2 文字で字下げし、`<`、`>`、
/// `&`、U+2028、U+2029 を `<` の形で書く。
struct GoIndent {
    inner: serde_json::ser::PrettyFormatter<'static>,
}

impl serde_json::ser::Formatter for GoIndent {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let esc = match c {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            w.write_all(&fragment.as_bytes()[start..i])?;
            w.write_all(esc.as_bytes())?;
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }
    fn begin_array<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.inner.begin_array(w)
    }
    fn end_array<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.inner.end_array(w)
    }
    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.inner.begin_array_value(w, first)
    }
    fn end_array_value<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.inner.end_array_value(w)
    }
    fn begin_object<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.inner.begin_object(w)
    }
    fn end_object<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.inner.end_object(w)
    }
    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.inner.begin_object_key(w, first)
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.inner.begin_object_value(w)
    }
    fn end_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.inner.end_object_value(w)
    }
}

impl Credentials {
    /// 読む。無ければ [`CredentialsError::NotFound`]。symlink と通常のファイルでないものは拒む。
    ///
    /// Windows では、開いたファイルの DACL を呼び出した利用者の SID で付け直す (付けられなければ
    /// 拒む)。純粋な読みではないので、`agent doctor` や制御ソケットの段のように、持ち主でない
    /// 利用者や権限の無い利用者が読むだけの呼び出しは、この関数を使わず別の読み (Go の `ReadFile`
    /// に当たるもの) を使うこと。
    ///
    /// # Errors
    ///
    /// 読めないか JSON として読めなければ誤りを返す。
    pub fn load(path: &Path) -> Result<Credentials, CredentialsError> {
        let (f, meta) = match open_regular(path, OpenOptions::new().read(true)) {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CredentialsError::NotFound);
            }
            Err(e) => return Err(other(path, e)),
        };
        tighten_existing(&f).map_err(|e| other(path, format!("secure credentials file: {e}")))?;
        if meta.len() > MAX_FILE_SIZE {
            return Err(other(path, "is larger than wgft ever writes"));
        }
        let mut b = Vec::new();
        f.take(MAX_FILE_SIZE + 1)
            .read_to_end(&mut b)
            .map_err(|e| other(path, e))?;
        if b.len() as u64 > MAX_FILE_SIZE {
            return Err(other(path, "grew while being read"));
        }
        serde_json::from_slice(&b).map_err(|e| other(path, e))
    }

    /// 読む。無ければ空の値を返す。
    ///
    /// # Errors
    ///
    /// 無いこと以外の読みの誤りを返す。
    pub fn load_or_new(path: &Path) -> Result<Credentials, CredentialsError> {
        match Credentials::load(path) {
            Err(CredentialsError::NotFound) => Ok(Credentials::default()),
            r => r,
        }
    }

    /// Go の v1 の agent と同じ byte 列にする。
    ///
    /// # Errors
    ///
    /// 書けない値があれば誤りを返す。
    pub fn to_go_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut out = Vec::new();
        let fmt = GoIndent {
            inner: serde_json::ser::PrettyFormatter::with_indent(b"  "),
        };
        let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
        self.serialize(&mut ser)?;
        Ok(out)
    }

    /// 一時ファイルに書いて rename する。Unix では作った瞬間から 0600。既にあるファイルの持ち主と
    /// group は保つ (root が書き直す場合)。
    ///
    /// # Errors
    ///
    /// 書けなければ誤りを返す。既にある `path` が通常のファイルでなければ何も書かずに拒む。
    pub fn save(&self, path: &Path) -> Result<(), CredentialsError> {
        let b = self.to_go_json().map_err(|e| other(path, e))?;
        if b.len() as u64 > MAX_FILE_SIZE {
            return Err(other(path, "would be larger than wgft ever writes"));
        }
        let old = match fs::symlink_metadata(path) {
            Ok(m) if !m.file_type().is_file() => {
                return Err(other(
                    path,
                    "is not a regular file, so it was left untouched",
                ));
            }
            Ok(m) => Some(m),
            Err(_) => None,
        };
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let (tmp_path, mut tmp) = create_temp(dir)
            .map_err(|e| other(path, format!("create temp credentials file: {e}")))?;
        let result = tmp
            .write_all(&b)
            .and_then(|()| tmp.sync_all())
            .and_then(|()| keep_owner(&tmp, old.as_ref()))
            .and_then(|()| {
                drop(tmp);
                fs::rename(&tmp_path, path)
            });
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp_path);
            return Err(other(path, e));
        }
        // rename をディスクに残すため、ディレクトリも fsync する (Unix)
        #[cfg(unix)]
        if let Err(e) = File::open(dir).and_then(|d| d.sync_all()) {
            return Err(other(path, format!("sync the data directory: {e}")));
        }
        Ok(())
    }

    /// 今の鍵を 1 つ前の鍵として移す (Go の `KeepPreviousKey`)。カーネルモードの記録を持つファイルで
    /// だけ移し、今の鍵が空なら 1 つ前の鍵を空で上書きしない。ユーザー空間モードはカーネルに鍵を残さない
    /// ので、1 つ前の鍵を持つ理由が無い。
    pub fn keep_previous_key(&mut self) {
        if self.recorded_mode() != "kernel" || self.wg_private_key.is_empty() {
            return;
        }
        self.previous_wg_private_key
            .clone_from(&self.wg_private_key);
    }

    /// 記録されたモード。空はユーザー空間モード。
    #[must_use]
    pub fn recorded_mode(&self) -> &str {
        if self.mode.is_empty() {
            "userspace"
        } else {
            &self.mode
        }
    }
}

/// root が書き直すとき、新しいファイルの持ち主と group を前のファイルに合わせる。開いた記述子に対して
/// 行うので、名前を差し替えられても他のファイルに触らない。
#[cfg(unix)]
fn keep_owner(tmp: &File, old: Option<&fs::Metadata>) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // 一時ファイルはこのプロセスの実効 uid が持つので、持ち主が 0 なら root で動いている
    let mine = tmp.metadata()?;
    if let Some(m) = old
        && mine.uid() == 0
        && (m.uid(), m.gid()) != (mine.uid(), mine.gid())
    {
        std::os::unix::fs::fchown(tmp, Some(m.uid()), Some(m.gid()))?;
    }
    Ok(())
}

/// Windows では持ち主を変えない。ファイルの ACL は試作では扱わない。
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the Unix version"
)]
fn keep_owner(_tmp: &File, _old: Option<&fs::Metadata>) -> std::io::Result<()> {
    Ok(())
}

fn create_temp(dir: &Path) -> std::io::Result<(PathBuf, File)> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut seed = [0u8; 8];
    for attempt in 0..16u32 {
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
            .map_err(|_| std::io::Error::other("no randomness for the temporary file name"))?;
        let name = format!("{TEMP_PREFIX}{}", u64::from_le_bytes(seed) % 10_000_000_000);
        let p = dir.join(name);
        match open_new_private(&p, &opts) {
            Ok(f) => return Ok((p, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 15 => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("cannot pick a temporary file name"))
}

/// 前の保存が途中で止まって残した一時ファイルを消す。ロックを取った後に呼ぶので、消すのは動いている
/// agent の書きかけではない。通常のファイルだけを消す。
pub fn remove_leftover_temps(credentials: &Path) {
    let dir = credentials.parent().unwrap_or_else(|| Path::new("."));
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let is_temp = e
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(TEMP_PREFIX));
        if is_temp && e.file_type().is_ok_and(|t| t.is_file()) {
            match fs::remove_file(e.path()) {
                Ok(()) => crate::logf!(
                    "removed the leftover temporary credentials file {}",
                    e.path().display()
                ),
                Err(err) => crate::logf!(
                    "cannot remove the leftover temporary credentials file {}: {err}",
                    e.path().display()
                ),
            }
        }
    }
}

/// 隣の `.lock` ファイルの排他ロック。Go の agent と同じく Unix は `flock`、Windows は `LockFileEx`
/// (Rust の標準の `File::try_lock`) なので、Go の agent と Rust の agent は同じデータディレクトリで
/// 同時に動かない。
#[derive(Debug)]
pub struct Lock {
    _file: File,
}

/// 認証情報のファイルに対応するロックファイルの場所。
#[must_use]
pub fn lock_path(credentials: &Path) -> PathBuf {
    let mut s = credentials.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// ロックファイルの状態 (Go の `flock.State`)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState {
    /// ロックファイルが無い。稼働している証拠が無いことだけを示す。
    Absent,
    /// ロックファイルがあり、誰もロックを持っていない。
    Unlocked,
    /// 別のプロセスが排他ロックを持っている。
    Locked,
}

/// ロックファイルを作らずにロックの状態を読む (Go の `flock.Inspect`)。ファイルがあれば共有ロックを一瞬
/// 取って放ち、排他ロックの持ち主の有無を見る。symlink と通常のファイルでないものは誤りにする。
///
/// # Errors
///
/// 無いこと以外で開けないか、ロックを試せなければ誤りを返す。
pub fn inspect_lock(credentials: &Path) -> std::io::Result<LockState> {
    let p = lock_path(credentials);
    let f = match open_regular_read(&p) {
        Ok((f, _)) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LockState::Absent),
        Err(e) => return Err(e),
    };
    match f.try_lock_shared() {
        // f を閉じると共有ロックも消える
        Ok(()) => Ok(LockState::Unlocked),
        Err(TryLockError::WouldBlock) => Ok(LockState::Locked),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

/// 停止中に CLI が認証情報ファイルを書くための排他 (Go の `credentials.LockWhileStopped`)。
#[derive(Debug)]
pub enum WhileStopped {
    /// 別のプロセスがロックを持つ。多くは稼働中の agent で、呼び手は書かない。
    Running,
    /// 止まっている。ロックファイルがあれば取ったロックを持ち、無ければ作らずに `None` である。
    /// 作ると呼び出し元の権限のロックファイルが残り、非特権で動く agent の起動を塞ぐためである。
    Stopped(Option<Lock>),
}

/// 判定はロックファイルを作らない [`inspect_lock`] で行い、ロックファイルがあって誰も持っていなければ
/// ロックを取る。判定の後に起動した agent がロックを取っていれば、稼働中として扱う。
///
/// # Errors
///
/// ロックファイルを読めないか、ロックを取れない誤りを返す。
pub fn lock_while_stopped(credentials: &Path) -> Result<WhileStopped, CredentialsError> {
    match inspect_lock(credentials).map_err(|e| other(&lock_path(credentials), e))? {
        LockState::Locked => Ok(WhileStopped::Running),
        LockState::Absent => Ok(WhileStopped::Stopped(None)),
        LockState::Unlocked => match acquire(credentials) {
            Ok(l) => Ok(WhileStopped::Stopped(Some(l))),
            Err(CredentialsError::Locked) => Ok(WhileStopped::Running),
            Err(e) => Err(e),
        },
    }
}

/// ロックを取る。取れなければ [`CredentialsError::Locked`]。ロックファイルの symlink と通常のファイル
/// でないものは拒む。ロックを取った後に、その名前が今も同じファイルを指すことを確かめ、別のプロセスが
/// 消して作り直していれば取り直す (Go の `flock` と同じく 4 回まで)。
///
/// # Errors
///
/// ロックファイルを開けないか、別のプロセスがロックを持っていれば誤りを返す。
pub fn acquire(credentials: &Path) -> Result<Lock, CredentialsError> {
    let p = lock_path(credentials);
    for _ in 0..4 {
        let (f, opened) = open_lock(&p).map_err(|e| other(&p, e))?;
        match f.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(CredentialsError::Locked),
            Err(TryLockError::Error(e)) => return Err(other(&p, e)),
        }
        // 締められなければ、ロックを渡さずに拒む。f はここで閉じてロックも離す
        tighten_existing(&f).map_err(|e| other(&p, format!("secure lock file: {e}")))?;
        if same_file(&opened, &p) {
            return Ok(Lock { _file: f });
        }
    }
    Err(other(
        &p,
        "the lock file kept being replaced while it was being locked",
    ))
}

/// ロックファイルを開く (無ければ作る)。Windows は作成の時点から DACL つきで作る。
fn open_lock(p: &Path) -> std::io::Result<(File, fs::Metadata)> {
    #[cfg(windows)]
    {
        let f = crate::platform::winsec::create_private_file(p, false)?;
        let meta = f.metadata()?;
        if !meta.file_type().is_file() {
            return Err(std::io::Error::other("is not a regular file"));
        }
        Ok((f, meta))
    }
    #[cfg(not(windows))]
    {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        open_regular(p, &mut opts)
    }
}

/// 開いたファイル `opened` と、今の `path` が同じファイルかどうか。
fn same_file(opened: &fs::Metadata, path: &Path) -> bool {
    let Ok(now) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        opened.dev() == now.dev() && opened.ino() == now.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = opened;
        now.file_type().is_file()
    }
}

/// データディレクトリを作る。既にあれば触らない。
///
/// # Errors
///
/// 作れなければ誤りを返す。
pub fn ensure_data_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        // 新しく作ったディレクトリにだけ DACL を付ける。既にあれば触らない
        if dir.is_dir() {
            return Ok(());
        }
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        match crate::platform::winsec::create_private_dir(dir) {
            // 競合で他が先に作った場合だけ許す。ディレクトリでないものは誤り
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
            r => r,
        }
    }
    #[cfg(not(windows))]
    {
        let mut b = fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(dir)
    }
}

/// 一時ファイルを作る。Unix は 0600、Windows は作成の時点から 3 者だけの DACL で作る。
fn open_new_private(path: &Path, opts: &OpenOptions) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        let _ = opts;
        crate::platform::winsec::create_private_file(path, true)
    }
    #[cfg(not(windows))]
    {
        opts.open(path)
    }
}

/// 開いたファイルの保護を締め直す。Windows は開いた handle に DACL を付け直す。Unix では何もしない
/// (既にあるファイルの権限は変えない)。
#[cfg_attr(
    not(windows),
    expect(
        clippy::unnecessary_wraps,
        reason = "the same signature as the Windows version"
    )
)]
fn tighten_existing(f: &File) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        crate::platform::winsec::restrict_open_file(f)
    }
    #[cfg(not(windows))]
    {
        let _ = f;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wgft-agent-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    // Go の v1 の agent が書いた形 (カーネルモードの記録と、この版が知らないキーを含む)
    const GO_FILE: &str = r#"{
  "name": "home",
  "endpoint": "203.0.113.1:8443",
  "cert_sha256": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  "permanent_token": "secret",
  "used_join_token_sha256": "aa",
  "wg_private_key": "KEY",
  "last_state": {
    "generation": 4,
    "wg": {
      "server_pubkey": "S",
      "endpoint": "203.0.113.1:51820",
      "address": "10.200.0.2/24",
      "mtu": 1420,
      "keepalive": 25,
      "udp_timeout": 30,
      "udp_timeout_stream": 120
    },
    "rules": [
      {
        "id": "r_01JABC",
        "proto": "tcp",
        "listen_port": "39971",
        "target": "192.168.50.3:25565",
        "enabled": true
      }
    ],
    "server_protocol_version": 1,
    "server_capabilities": []
  },
  "kernel_publication": {"a": [1, 2]},
  "tunnel_address": "10.200.0.2/24",
  "future_key": "kept"
}"#;

    #[test]
    fn reads_a_go_file_and_writes_it_back_unchanged_in_meaning() {
        let d = tmpdir("roundtrip");
        let p = d.join(FILE_NAME);
        fs::write(&p, GO_FILE).unwrap();
        let c = Credentials::load(&p).unwrap();
        assert_eq!(c.name, "home");
        assert_eq!(
            c.last_state.as_ref().unwrap().rules[0].listen_port.lo,
            39971
        );
        assert_eq!(c.recorded_mode(), "userspace");
        c.save(&p).unwrap();
        let before: Value = serde_json::from_str(GO_FILE).unwrap();
        let after: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        assert_eq!(before, after);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(d).unwrap();
    }

    /// 仕様の fixture (Go の v1 の agent が書いたファイル) を読んで書くと、同じ byte 列に戻る。
    #[test]
    fn spec_files_round_trip_byte_for_byte() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/spec/credentials");
        let mut n = 0;
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let want = fs::read_to_string(&p).unwrap().replace("\r\n", "\n");
            let c: Credentials = serde_json::from_str(&want).unwrap();
            assert_eq!(
                String::from_utf8(c.to_go_json().unwrap()).unwrap(),
                want,
                "{}",
                p.display()
            );
            assert!(!format!("{c:?}").contains(&c.permanent_token) || c.permanent_token.is_empty());
            n += 1;
        }
        assert!(n > 0);
    }

    #[test]
    fn writes_html_characters_escaped_like_go() {
        let c = Credentials {
            name: "a<b>&c\u{2028}".into(),
            ..Credentials::default()
        };
        let s = String::from_utf8(c.to_go_json().unwrap()).unwrap();
        assert!(
            s.contains(r#""name": "a\u003cb\u003e\u0026c\u2028""#),
            "{s}"
        );
    }

    #[test]
    fn refuses_a_symlinked_file_and_lock() {
        let d = tmpdir("symlink");
        let real = d.join("real.json");
        fs::write(&real, "{}").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, d.join(FILE_NAME)).unwrap();
            assert!(matches!(
                Credentials::load(&d.join(FILE_NAME)),
                Err(CredentialsError::Other(_))
            ));
            std::os::unix::fs::symlink(&real, lock_path(&d.join("other.json"))).unwrap();
            assert!(acquire(&d.join("other.json")).is_err());
        }
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn removes_leftover_temps() {
        let d = tmpdir("temps");
        fs::write(d.join(format!("{TEMP_PREFIX}123")), "x").unwrap();
        fs::write(d.join("keep.json"), "x").unwrap();
        remove_leftover_temps(&d.join(FILE_NAME));
        let names: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("keep.json")]);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn empty_credentials_write_null_last_state_like_go() {
        let s = serde_json::to_string(&Credentials::default()).unwrap();
        assert_eq!(
            s,
            r#"{"name":"","endpoint":"","cert_sha256":"","permanent_token":"","used_join_token_sha256":"","wg_private_key":"","last_state":null}"#
        );
    }

    #[test]
    fn missing_file_is_new() {
        let d = tmpdir("missing");
        let c = Credentials::load_or_new(&d.join(FILE_NAME)).unwrap();
        assert_eq!(c, Credentials::default());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn second_lock_is_refused() {
        let d = tmpdir("lock");
        let p = d.join(FILE_NAME);
        let held = acquire(&p).unwrap();
        assert!(matches!(acquire(&p), Err(CredentialsError::Locked)));
        drop(held);
        assert!(acquire(&p).is_ok());
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(windows)]
    mod windows {
        use super::*;
        use crate::platform::winsec::{assert_private, dacl_is_private, restrict_file};

        #[test]
        fn saved_file_and_lock_carry_the_private_dacl() {
            let d = tmpdir("win-save");
            let p = d.join(FILE_NAME);
            let _lock = acquire(&p).unwrap();
            assert_private(&lock_path(&p), false);
            Credentials::default().save(&p).unwrap();
            assert_private(&p, false);
            // 既存のファイルへの rename が置き換える
            let c = Credentials {
                name: "second".into(),
                ..Credentials::default()
            };
            c.save(&p).unwrap();
            assert_eq!(Credentials::load(&p).unwrap().name, "second");
            assert_private(&p, false);
            fs::remove_dir_all(d).unwrap();
        }

        #[test]
        fn reading_and_locking_tighten_old_files() {
            let d = tmpdir("win-tighten");
            let p = d.join(FILE_NAME);
            // 親から継承した ACL のまま作られた古いファイル
            fs::write(&p, Credentials::default().to_go_json().unwrap()).unwrap();
            fs::write(lock_path(&p), b"").unwrap();
            assert!(!dacl_is_private(&p, false).unwrap());
            Credentials::load(&p).unwrap();
            assert_private(&p, false);
            let _lock = acquire(&p).unwrap();
            assert_private(&lock_path(&p), false);
            // 締め直しは内容を変えない
            restrict_file(&p, true).unwrap();
            fs::remove_dir_all(d).unwrap();
        }

        #[test]
        fn new_data_dir_gets_the_inheriting_dacl_but_an_old_one_is_untouched() {
            let d = tmpdir("win-dir");
            let fresh = d.join("a").join("wgft");
            ensure_data_dir(&fresh).unwrap();
            assert_private(&fresh, true);
            let before = crate::platform::winsec::read_dacl_sddl(&d).unwrap();
            ensure_data_dir(&d).unwrap();
            assert_eq!(crate::platform::winsec::read_dacl_sddl(&d).unwrap(), before);
            fs::remove_dir_all(d).unwrap();
        }
    }
}
