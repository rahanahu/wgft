//! 制御ソケットの搬送。`<データディレクトリ>/agent.json.sock` の AF_UNIX の待ち受けと接続を、Linux、
//! macOS、Windows で同じ口にする。要求と応答の中身は持たない。契約は `docs/design/spec/control-socket.md`。
//!
//! 受け口は専用の OS のスレッドで [`Listener::accept`] を呼ぶ使い方を想定する (tokio は Windows の
//! AF_UNIX を持たない)。Windows の AF_UNIX の実行時の挙動は未確認で、Windows の CI で確かめる。

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use socket2::{Domain, SockAddr, Socket, Type};

/// どの OS でも `sun_path` に収まるパスの長さの上限 (byte)。
pub const MAX_PATH_LEN: usize = 103;

/// 接続 1 つの読みと書きの全体の期限の既定。
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

/// 待ち受けを開けなかった理由。
#[derive(Debug)]
pub enum BindError {
    /// パスが [`MAX_PATH_LEN`] を超える。呼び出し側は制御ソケットを使わずに動く。
    PathTooLong(usize),
    /// Windows で DACL を付けられなかった。ソケットは閉じて消してある。
    Security(io::Error),
    /// それ以外。
    Io(io::Error),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::PathTooLong(n) => {
                write!(
                    f,
                    "socket path is {n} bytes, over the limit of {MAX_PATH_LEN}"
                )
            }
            BindError::Security(e) => write!(f, "restrict the socket to its owner: {e}"),
            BindError::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BindError {}

fn check_len(path: &Path) -> Result<(), BindError> {
    let n = path.as_os_str().as_encoded_bytes().len();
    if n > MAX_PATH_LEN {
        Err(BindError::PathTooLong(n))
    } else {
        Ok(())
    }
}

/// 待ち受けているソケット。drop でソケットを閉じ、ファイルを消す。
#[derive(Debug)]
pub struct Listener {
    socket: Socket,
    path: PathBuf,
}

impl Listener {
    /// `path` に待ち受けを開く。同じパスの古いファイルは先に消す。権限は Unix では 0600 (失敗は無視)、
    /// Windows では開いた直後に 3 者だけの DACL を付け、付けられなければ閉じて [`BindError::Security`]
    /// を返す。
    ///
    /// # Errors
    ///
    /// パスが長すぎるか、開けなければ誤りを返す。
    pub fn bind(path: &Path) -> Result<Listener, BindError> {
        check_len(path)?;
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(BindError::Io(e)),
        }
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(BindError::Io)?;
        let addr = SockAddr::unix(path).map_err(BindError::Io)?;
        socket.bind(&addr).map_err(BindError::Io)?;
        // ここから先の失敗ではファイルを残さない
        let l = Listener {
            socket,
            path: path.to_owned(),
        };
        l.restrict()?;
        l.socket.listen(16).map_err(BindError::Io)?;
        Ok(l)
    }

    #[cfg(unix)]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the same signature as the Windows version"
    )]
    fn restrict(&self) -> Result<(), BindError> {
        use std::os::unix::fs::PermissionsExt;
        // 失敗は無視する。ディレクトリが 0700 なので、他の利用者はもともと届かない
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }

    #[cfg(windows)]
    fn restrict(&self) -> Result<(), BindError> {
        super::winsec::restrict_file(&self.path, false).map_err(BindError::Security)
    }

    /// ソケットのパス。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 接続を 1 つ受ける。接続した相手の読みと書きには [`DEFAULT_DEADLINE`] の全体の期限が付く。
    ///
    /// # Errors
    ///
    /// accept の誤りを返す。
    pub fn accept(&self) -> io::Result<Stream> {
        let (socket, _) = self.socket.accept()?;
        Ok(Stream::new(socket, DEFAULT_DEADLINE))
    }

    /// 止めるために、accept で止まっているスレッドを起こす。自分のソケットへ 1 回接続して閉じる。
    /// 呼び出し側が先に止める印を立て、スレッドは accept が戻ったらその印を見る。
    ///
    /// # Errors
    ///
    /// 接続できなければ誤りを返す。
    pub fn wake(path: &Path) -> io::Result<()> {
        connect(path, Duration::from_secs(1)).map(drop)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 接続した 1 本の stream。読みも書きも、作ってからの全体の期限を超えると `TimedOut` で失敗する。
#[derive(Debug)]
pub struct Stream {
    socket: Socket,
    deadline: Instant,
}

impl Stream {
    fn new(socket: Socket, total: Duration) -> Stream {
        Stream {
            socket,
            deadline: Instant::now() + total,
        }
    }

    /// 期限までの残りを socket の期限に設定する。
    fn arm(&self, write: bool) -> io::Result<()> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "control socket deadline"))?;
        if write {
            self.socket.set_write_timeout(Some(left))
        } else {
            self.socket.set_read_timeout(Some(left))
        }
    }

    /// 全体の期限を `total` に置き直す。
    pub fn set_deadline(&mut self, total: Duration) {
        self.deadline = Instant::now() + total;
    }

    /// 書く側を閉じる。相手に入力の終わりを知らせる。
    ///
    /// # Errors
    ///
    /// shutdown の誤りを返す。
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.socket.shutdown(std::net::Shutdown::Write)
    }
}

fn timed_out(e: io::Error) -> io::Error {
    // Unix は WouldBlock、Windows は TimedOut で期限切れを返す。呼び出し側には 1 つの種類で見せる
    if e.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "control socket deadline")
    } else {
        e
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm(false)?;
        self.socket.read(buf).map_err(timed_out)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm(true)?;
        self.socket.write(buf).map_err(timed_out)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `path` の制御ソケットに接続する。接続した stream の読みと書きには [`DEFAULT_DEADLINE`] の全体の期限が
/// 付く。接続自体は `timeout` で打ち切る。
///
/// # Errors
///
/// パスが長すぎるか、接続できなければ誤りを返す。
pub fn connect(path: &Path, timeout: Duration) -> io::Result<Stream> {
    check_len(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.connect_timeout(&SockAddr::unix(path)?, timeout)?;
    Ok(Stream::new(socket, DEFAULT_DEADLINE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    /// 短い名前のディレクトリ。macOS の一時ディレクトリは長く、`sun_path` に収まりにくい。
    fn short_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wgft-cs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn echo_once(l: &Listener) {
        let mut s = l.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&mut s).read_line(&mut line).unwrap();
        s.write_all(format!("echo {}", line.trim()).as_bytes())
            .unwrap();
        s.write_all(b"\n").unwrap();
    }

    #[test]
    fn round_trips_one_request_and_response() {
        let d = short_dir("rt");
        let p = d.join("a.sock");
        let l = Listener::bind(&p).unwrap();
        std::thread::scope(|sc| {
            sc.spawn(|| echo_once(&l));
            let mut c = connect(&p, Duration::from_secs(5)).unwrap();
            c.write_all(b"doctor\n").unwrap();
            let mut got = String::new();
            BufReader::new(&mut c).read_line(&mut got).unwrap();
            assert_eq!(got, "echo doctor\n");
        });
        drop(l);
        assert!(!p.exists(), "the socket file must be removed on close");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn replaces_a_stale_file_at_the_same_path() {
        let d = short_dir("stale");
        let p = d.join("a.sock");
        std::fs::write(&p, b"stale").unwrap();
        let l = Listener::bind(&p).unwrap();
        std::thread::scope(|sc| {
            sc.spawn(|| echo_once(&l));
            let mut c = connect(&p, Duration::from_secs(5)).unwrap();
            c.write_all(b"x\n").unwrap();
            let mut got = String::new();
            BufReader::new(&mut c).read_line(&mut got).unwrap();
            assert_eq!(got, "echo x\n");
        });
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_a_path_over_the_limit() {
        let d = short_dir("long");
        let p = d.join("x".repeat(MAX_PATH_LEN));
        assert!(matches!(Listener::bind(&p), Err(BindError::PathTooLong(_))));
        assert!(connect(&p, Duration::from_secs(1)).is_err());
        // 上限ちょうどは長さの検査を通る (開けるかは OS の sun_path の長さで決まる)
        let edge = PathBuf::from("a".repeat(MAX_PATH_LEN));
        assert!(check_len(&edge).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn deadline_cuts_off_a_silent_peer() {
        let d = short_dir("dl");
        let p = d.join("a.sock");
        let l = Listener::bind(&p).unwrap();
        std::thread::scope(|sc| {
            let h = sc.spawn(|| {
                let mut conn = l.accept().unwrap();
                conn.set_deadline(Duration::from_millis(200));
                let mut buf = [0u8; 8];
                let started = Instant::now();
                let err = conn.read(&mut buf).unwrap_err();
                (err.kind(), started.elapsed())
            });
            // 何も送らず、閉じもしない
            let _c = connect(&p, Duration::from_secs(5)).unwrap();
            let (kind, took) = h.join().unwrap();
            assert_eq!(kind, io::ErrorKind::TimedOut);
            assert!(took < Duration::from_secs(5), "{took:?}");
        });
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wake_unblocks_a_thread_stuck_in_accept() {
        let d = short_dir("wake");
        let p = d.join("a.sock");
        let l = Listener::bind(&p).unwrap();
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|sc| {
            let h = sc.spawn(|| {
                loop {
                    let _s = l.accept().unwrap();
                    if stop.load(std::sync::atomic::Ordering::SeqCst) {
                        return;
                    }
                }
            });
            std::thread::sleep(Duration::from_millis(100));
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            Listener::wake(l.path()).unwrap();
            h.join().unwrap();
        });
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn socket_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = short_dir("perm");
        let p = d.join("a.sock");
        let _l = Listener::bind(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn socket_file_carries_the_private_dacl() {
        let d = short_dir("dacl");
        let p = d.join("a.sock");
        let _l = Listener::bind(&p).unwrap();
        super::super::winsec::assert_private(&p, false);
        let _ = std::fs::remove_dir_all(&d);
    }
}
