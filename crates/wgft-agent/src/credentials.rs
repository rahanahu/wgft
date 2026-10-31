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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
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

impl Credentials {
    /// 読む。無ければ [`CredentialsError::NotFound`]。symlink と通常のファイルでないものは拒む。
    ///
    /// # Errors
    ///
    /// 読めないか JSON として読めなければ誤りを返す。
    pub fn load(path: &Path) -> Result<Credentials, CredentialsError> {
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CredentialsError::NotFound);
            }
            Err(e) => return Err(other(path, e)),
        };
        if !meta.file_type().is_file() {
            return Err(other(path, "is not a regular file"));
        }
        if meta.len() > MAX_FILE_SIZE {
            return Err(other(path, "is larger than wgft ever writes"));
        }
        let mut b = Vec::new();
        File::open(path)
            .and_then(|f| f.take(MAX_FILE_SIZE + 1).read_to_end(&mut b))
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

    /// 一時ファイルに書いて rename する。Unix では作った瞬間から 0600。
    /// Go の `json.MarshalIndent(f, "", "  ")` と同じ 2 文字の字下げで書く。
    ///
    /// # Errors
    ///
    /// 書けなければ誤りを返す。既にある `path` が通常のファイルでなければ何も書かずに拒む。
    pub fn save(&self, path: &Path) -> Result<(), CredentialsError> {
        let b = serde_json::to_vec_pretty(self).map_err(|e| other(path, e))?;
        if b.len() as u64 > MAX_FILE_SIZE {
            return Err(other(path, "would be larger than wgft ever writes"));
        }
        if let Ok(m) = fs::symlink_metadata(path)
            && !m.file_type().is_file()
        {
            return Err(other(
                path,
                "is not a regular file, so it was left untouched",
            ));
        }
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let (tmp_path, mut tmp) = create_temp(dir)
            .map_err(|e| other(path, format!("create temp credentials file: {e}")))?;
        let result = tmp
            .write_all(&b)
            .and_then(|()| tmp.sync_all())
            .and_then(|()| {
                drop(tmp);
                fs::rename(&tmp_path, path)
            });
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp_path);
            return Err(other(path, e));
        }
        Ok(())
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
        match opts.open(&p) {
            Ok(f) => return Ok((p, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 15 => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("cannot pick a temporary file name"))
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

/// ロックを取る。取れなければ [`CredentialsError::Locked`]。
///
/// # Errors
///
/// ロックファイルを開けないか、別のプロセスがロックを持っていれば誤りを返す。
pub fn acquire(credentials: &Path) -> Result<Lock, CredentialsError> {
    let p = lock_path(credentials);
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(&p).map_err(|e| other(&p, e))?;
    match f.try_lock() {
        Ok(()) => Ok(Lock { _file: f }),
        Err(TryLockError::WouldBlock) => Err(CredentialsError::Locked),
        Err(TryLockError::Error(e)) => Err(other(&p, e)),
    }
}

/// データディレクトリを作る。既にあれば触らない。
///
/// # Errors
///
/// 作れなければ誤りを返す。
pub fn ensure_data_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
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
}
