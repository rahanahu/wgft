//! 制御ソケットの受け口。契約は `docs/design/spec/control-socket.md`、作りは
//! `docs/design/v2/agent-parity.md` の「制御ソケットの受け口」に書く。
//!
//! 専用の OS のスレッドが [`platform::ctlsock`](crate::platform::ctlsock) で待ち受ける。tokio は Windows の
//! AF_UNIX を持たないためである。接続はそれぞれ短命のスレッドで扱い、同時に扱う数に上限を置く。黙った
//! 相手が 1 つあっても、次の `doctor` は待たない。要求は容量の決まった channel で実行時の側へ渡し、応答を
//! std の channel で待つ。実行時の側が応答を返さずに落ちれば (panic を含む)、送り手が消えたことで知り、
//! 失敗の 1 行を返す。

use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;

use crate::controlapi::{
    self, DOCTOR_COMMAND, ROTATE_KEY_COMMAND, UNKNOWN_COMMAND_REPLY, control_path,
};
use crate::logf;
use crate::platform::ctlsock::{self, BindError, Listener};

/// 要求の 1 行の上限 (byte)。知っている要求はどれも短い。上限まで改行が来なければ知らない要求として
/// 扱う。Go の v1 は上限を持たずに改行まで読むが、どちらも `error: unknown command` を返す。
const REQUEST_MAX_BYTES: usize = 1024;

/// 要求の 1 行を読む期限と、応答を書く期限。CLI は繋いだ直後に書いて読むので短くてよい。黙った相手が
/// スレッドを長く持たない。
const REQUEST_DEADLINE: Duration = Duration::from_secs(2);

/// `doctor` の応答を実行時の側から待つ長さ。実行時の側は排他を 2 秒まで待って応答を組むので、その上に
/// 余裕を足し、CLI が応答を待つ 10 秒より短くする。
const DOCTOR_REPLY_WAIT: Duration = Duration::from_secs(5);

/// `rotate-key` が始まるのを待つ長さ。これを過ぎて始まっていなければ、要求を取り下げる。
const ROTATE_KEY_START_WAIT: Duration = Duration::from_secs(20);

/// 始まった `rotate-key` の終わりを待つ長さの上限。要求を受けてからの長さで、CLI が要求と応答の全体に
/// 掛ける 30 秒の中に応答を書き終える。
const ROTATE_KEY_REPLY_WAIT: Duration = Duration::from_secs(26);

/// 同時に扱う接続の上限。相手は同じホストの CLI だけである。
const MAX_CONNECTIONS: usize = 4;

/// 上限を超えた接続の要求を読む期限。待ち受けのスレッドが読むので短くする。CLI は繋いだ直後に書く。
const OVER_LIMIT_READ_DEADLINE: Duration = Duration::from_millis(200);

/// 上限を超えた接続への応答の理由。
const TOO_MANY_CONNECTIONS: &str =
    "the agent is serving too many control connections; run this again in a moment";

/// `doctor` の要求。応答の 1 行 (改行を含む) を返す。
#[derive(Debug)]
pub(crate) struct DoctorRequest {
    pub(crate) reply: SyncSender<Vec<u8>>,
}

/// `rotate-key` の要求。成功なら新しい公開鍵、失敗なら文言を返す。
///
/// 要求の状態は、実行時の側が鍵を変え始める (`Started`) か、受け口が始まるのを待ち切れずに取り下げる
/// (`Abandoned`) かの、どちらか一方だけに `Pending` から移る。取り下げた要求で実行時の側は何もしない。
/// 待つのを諦めた要求が後で鍵を変えると、CLI の打ち直しと重なって server の鍵の変更の頻度の上限に
/// 当たりうるためである。始まった要求の終わりは、CLI の期限の中で待つ。
#[derive(Debug)]
pub(crate) struct RotateKeyRequest {
    pub(crate) reply: SyncSender<Result<String, String>>,
    pub(crate) state: Arc<RotateState>,
}

/// `rotate-key` の要求の状態。
#[derive(Debug, Default)]
pub(crate) struct RotateState(AtomicU8);

const PENDING: u8 = 0;
const STARTED: u8 = 1;
const ABANDONED: u8 = 2;

impl RotateState {
    /// 実行時の側が鍵を変え始める。取り下げられていれば偽を返し、何もしてはならない。
    pub(crate) fn start(&self) -> bool {
        self.0
            .compare_exchange(PENDING, STARTED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// 受け口が要求を取り下げる。既に始まっていれば偽を返す。
    fn abandon(&self) -> bool {
        self.0
            .compare_exchange(PENDING, ABANDONED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// 取り下げられたか。
    pub(crate) fn abandoned(&self) -> bool {
        self.0.load(Ordering::SeqCst) == ABANDONED
    }
}

/// 試験のために、受け口の側の取り下げを行う。
#[cfg(test)]
pub(crate) fn abandon_for_test(state: &RotateState) -> bool {
    state.abandon()
}

/// 実行時の側への送り手。
#[derive(Clone, Debug)]
pub(crate) struct Senders {
    pub(crate) doctor: Sender<DoctorRequest>,
    pub(crate) rotate_key: Sender<RotateKeyRequest>,
}

/// 待ち受けているスレッド。[`Server::stop`] で止める。drop でも止める。
#[derive(Debug)]
pub(crate) struct Server {
    thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    path: PathBuf,
}

impl Server {
    /// `credentials` の隣に制御ソケットを開き、スレッドを立てる。開けなければその旨をログに出して
    /// `None` を返し、agent は制御ソケットを使わずに動く。
    pub(crate) fn start(credentials: &Path, tx: Senders) -> Option<Server> {
        let path = control_path(credentials);
        let listener = match Listener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                let what = if matches!(e, BindError::Security(_)) {
                    "secure"
                } else {
                    "open"
                };
                logf!(
                    "cannot {what} control socket {}: {e}; rotate-key works only while the agent is stopped, and agent doctor cannot read this agent's live state",
                    path.display()
                );
                return None;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("wgft-control".into())
            .spawn(move || serve(&listener, &flag, &tx));
        match thread {
            Ok(t) => Some(Server {
                thread: Some(t),
                stop,
                path,
            }),
            Err(e) => {
                logf!(
                    "cannot start the control socket thread: {e}; rotate-key works only while the agent is stopped, and agent doctor cannot read this agent's live state"
                );
                None
            }
        }
    }

    /// 止める印を立て、自分のソケットに 1 回接続して accept を起こし、待ち受けのスレッドを待つ。スレッドは
    /// 待ち受けを閉じ、ソケットのファイルを消して終わる。扱い中の接続のスレッドは待たない。どれも要求の
    /// 期限と応答の待ちの長さで終わる。認証情報のロックを手放す前に呼ぶこと。
    pub(crate) fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let Some(t) = self.thread.take() else { return };
        self.stop.store(true, Ordering::SeqCst);
        if let Err(e) = Listener::wake(&self.path) {
            // 起こせなければスレッドは accept で止まったままなので、待たずに手放す。ファイルはプロセスの
            // 終わりに残り、次の起動が消す
            logf!(
                "cannot wake the control socket thread to stop it: {e}; leaving it to the process exit"
            );
            return;
        }
        let _ = t.join();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 接続を受け、それぞれを短命のスレッドに渡す。止める印を見たら戻り、`listener` は呼び手の側で drop
/// されてファイルが消える。
fn serve(listener: &Listener, stop: &AtomicBool, tx: &Senders) {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let conn = listener.accept();
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                logf!("control socket: accept: {e}");
                // 誤りが続く場合に回り続けない
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            refuse_over_limit(conn);
            continue;
        }
        let (tx, count) = (tx.clone(), Arc::clone(&active));
        let spawned = std::thread::Builder::new()
            .name("wgft-control-conn".into())
            .spawn(move || {
                serve_conn(conn, &tx);
                count.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            active.fetch_sub(1, Ordering::SeqCst);
            logf!("control socket: cannot start a thread for a connection: {e}");
        }
    }
}

/// 上限を超えた接続に、理由の 1 行を書いて閉じる。応答の形は要求で決まるので、短い期限で要求を読む。
/// 読めなければ書かずに閉じる。
fn refuse_over_limit(mut conn: ctlsock::Stream) {
    conn.set_deadline(OVER_LIMIT_READ_DEADLINE);
    let Some(line) = read_request(&mut conn) else {
        return;
    };
    let reply = match line.trim() {
        ROTATE_KEY_COMMAND => format!("error: {TOO_MANY_CONNECTIONS}\n").into_bytes(),
        DOCTOR_COMMAND => controlapi::error_line(TOO_MANY_CONNECTIONS),
        _ => format!("{UNKNOWN_COMMAND_REPLY}\n").into_bytes(),
    };
    conn.set_deadline(OVER_LIMIT_READ_DEADLINE);
    let _ = conn.write_all(&reply);
}

/// 1 つの接続を扱う。応答を組む処理の panic でスレッドを落とさない。
fn serve_conn(mut conn: ctlsock::Stream, tx: &Senders) {
    if catch_unwind(AssertUnwindSafe(|| handle(&mut conn, tx))).is_err() {
        logf!("control socket: recovered from a panic while answering a request");
        let _ = conn.write_all(&controlapi::error_line(
            "the agent panicked while answering this request",
        ));
    }
}

/// 1 つの接続の要求を読み、応答の 1 行を書く。要求の読みには短い期限が付く。
fn handle(conn: &mut ctlsock::Stream, tx: &Senders) {
    conn.set_deadline(REQUEST_DEADLINE);
    let Some(line) = read_request(conn) else {
        return;
    };
    let reply = match line.trim() {
        ROTATE_KEY_COMMAND => rotate_key(tx),
        DOCTOR_COMMAND => doctor(tx),
        _ => format!("{UNKNOWN_COMMAND_REPLY}\n").into_bytes(),
    };
    // 書くのは応答を得た後なので、書きの期限は改めて置く
    conn.set_deadline(REQUEST_DEADLINE);
    let _ = conn.write_all(&reply);
}

fn rotate_key(tx: &Senders) -> Vec<u8> {
    let (rtx, rrx) = sync_channel(1);
    let state = Arc::new(RotateState::default());
    let req = RotateKeyRequest {
        reply: rtx,
        state: Arc::clone(&state),
    };
    match tx.rotate_key.try_send(req) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            return b"error: the agent is busy with another key rotation; run this again in a moment\n"
                .to_vec();
        }
        Err(TrySendError::Closed(_)) => return b"error: the agent is shutting down\n".to_vec(),
    }
    let r = wait_rotate_key(&rrx, &state, ROTATE_KEY_START_WAIT, ROTATE_KEY_REPLY_WAIT);
    match r {
        Ok(Ok(public)) => format!("ok {public}\n").into_bytes(),
        Ok(Err(e)) => format!("error: {e}\n").into_bytes(),
        Err(RotateWait::NotStarted) => {
            b"error: the agent did not start rotating the key in time, so it was not rotated; run this again\n"
                .to_vec()
        }
        Err(RotateWait::StillRunning) => {
            b"error: the agent started rotating the key but did not finish in time; read its log for the result before running this again\n"
                .to_vec()
        }
        Err(RotateWait::Stopped) => b"error: the agent stopped before it answered\n".to_vec(),
    }
}

/// `rotate-key` の応答を待てなかった理由。
#[derive(Debug, PartialEq, Eq)]
enum RotateWait {
    /// 始まる前に取り下げた。鍵は変わっていない。
    NotStarted,
    /// 始まったが、終わりを待ち切れなかった。鍵は変わったかもしれない。
    StillRunning,
    /// 実行時の側が応答を返さずに終わった。
    Stopped,
}

/// `start_wait` まで応答を待ち、来なければ要求を取り下げる。取り下げより先に実行時の側が始めていれば、
/// 要求を受けてから `total_wait` まで終わりを待つ。
fn wait_rotate_key(
    rrx: &std::sync::mpsc::Receiver<Result<String, String>>,
    state: &RotateState,
    start_wait: Duration,
    total_wait: Duration,
) -> Result<Result<String, String>, RotateWait> {
    let started = Instant::now();
    match rrx.recv_timeout(start_wait) {
        Ok(r) => return Ok(r),
        Err(RecvTimeoutError::Disconnected) => return Err(RotateWait::Stopped),
        Err(RecvTimeoutError::Timeout) => {}
    }
    if state.abandon() {
        return Err(RotateWait::NotStarted);
    }
    match rrx.recv_timeout(total_wait.saturating_sub(started.elapsed())) {
        Ok(r) => Ok(r),
        Err(RecvTimeoutError::Disconnected) => Err(RotateWait::Stopped),
        Err(RecvTimeoutError::Timeout) => Err(RotateWait::StillRunning),
    }
}

fn doctor(tx: &Senders) -> Vec<u8> {
    let (rtx, rrx) = sync_channel(1);
    match tx.doctor.try_send(DoctorRequest { reply: rtx }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            return controlapi::error_line("the agent is answering other doctor requests");
        }
        Err(TrySendError::Closed(_)) => {
            return controlapi::error_line("the agent is shutting down");
        }
    }
    match rrx.recv_timeout(DOCTOR_REPLY_WAIT) {
        Ok(line) => line,
        Err(RecvTimeoutError::Timeout) => controlapi::error_line(&format!(
            "the agent did not collect its state within {}s",
            DOCTOR_REPLY_WAIT.as_secs()
        )),
        Err(RecvTimeoutError::Disconnected) => controlapi::error_line(
            "the agent failed while collecting its state; its log has the panic",
        ),
    }
}

/// 改行で終わる要求の 1 行を読む。改行の前に閉じられるか期限が来れば `None`。上限まで改行が来なければ
/// 知らない要求として空でない値を返す。
fn read_request(conn: &mut impl Read) -> Option<String> {
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 256];
    while buf.len() < REQUEST_MAX_BYTES {
        let n = conn.read(&mut byte).ok()?;
        if n == 0 {
            return None;
        }
        if let Some(i) = byte[..n].iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&byte[..i]);
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
        buf.extend_from_slice(&byte[..n]);
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn short_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wgft-cs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ask(path: &Path, req: &[u8]) -> String {
        let mut c = ctlsock::connect(path, Duration::from_secs(5)).unwrap();
        c.write_all(req).unwrap();
        let mut got = String::new();
        BufReader::new(&mut c).read_line(&mut got).unwrap();
        got
    }

    type Receivers = (
        tokio::sync::mpsc::Receiver<DoctorRequest>,
        tokio::sync::mpsc::Receiver<RotateKeyRequest>,
    );

    fn channels() -> (Senders, Receivers) {
        let (dtx, drx) = tokio::sync::mpsc::channel(4);
        let (rtx, rrx) = tokio::sync::mpsc::channel(1);
        (
            Senders {
                doctor: dtx,
                rotate_key: rtx,
            },
            (drx, rrx),
        )
    }

    /// 実行時の側を、要求ごとに決めた応答を返すスレッドで代える。2 つ目の `doctor` には応答を返さずに
    /// 落ちる。
    fn fake_runtime(rx: Receivers) -> (JoinHandle<usize>, JoinHandle<usize>) {
        let (mut drx, mut rrx) = rx;
        let d = std::thread::spawn(move || {
            let mut n = 0;
            while let Some(r) = drx.blocking_recv() {
                n += 1;
                if n == 2 {
                    drop(r);
                } else {
                    let _ = r.reply.send(b"{\"error\":\"x\"}\n".to_vec());
                }
            }
            n
        });
        let r = std::thread::spawn(move || {
            let mut n = 0;
            while let Some(r) = rrx.blocking_recv() {
                n += 1;
                let _ = r.reply.send(if n == 1 {
                    Ok("PUB".into())
                } else {
                    Err("save failed".into())
                });
            }
            n
        });
        (d, r)
    }

    #[test]
    fn answers_rotate_key_doctor_and_unknown_requests_and_stops() {
        let d = short_dir("srv");
        let creds = d.join("agent.json");
        let (tx, rx) = channels();
        let (dt, rt) = fake_runtime(rx);
        let srv = Server::start(&creds, tx).unwrap();
        let sock = control_path(&creds);
        assert_eq!(ask(&sock, b"rotate-key\n"), "ok PUB\n");
        assert_eq!(ask(&sock, b"  rotate-key \r\n"), "error: save failed\n");
        assert_eq!(ask(&sock, b"doctor\n"), "{\"error\":\"x\"}\n");
        let failed = ask(&sock, b"doctor\n");
        assert!(
            failed.starts_with("{\"error\":\"the agent failed"),
            "{failed}"
        );
        assert_eq!(ask(&sock, b"teardown\n"), "error: unknown command\n");
        let long = vec![b'x'; REQUEST_MAX_BYTES + 10];
        assert_eq!(ask(&sock, &long), "error: unknown command\n");
        srv.stop();
        assert!(!sock.exists(), "the socket file must be removed on stop");
        // 送り手はスレッドと一緒に消えるので、実行時の側も終わる
        assert_eq!(dt.join().unwrap(), 2);
        assert_eq!(rt.join().unwrap(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 黙ったまま繋ぎ続ける相手がいても、次の `doctor` は待たずに答え、止めるのも待たない。
    #[test]
    fn a_silent_client_does_not_hold_up_doctor_or_stop() {
        let d = short_dir("silent");
        let creds = d.join("agent.json");
        let (tx, rx) = channels();
        let (dt, _rt) = fake_runtime(rx);
        let srv = Server::start(&creds, tx).unwrap();
        let sock = control_path(&creds);
        let _silent = ctlsock::connect(&sock, Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        assert_eq!(ask(&sock, b"doctor\n"), "{\"error\":\"x\"}\n");
        assert!(
            started.elapsed() < REQUEST_DEADLINE,
            "{:?}",
            started.elapsed()
        );
        let started = Instant::now();
        srv.stop();
        assert!(
            started.elapsed() < REQUEST_DEADLINE,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(dt.join().unwrap(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 応答を返さない実行時の側に対して、`doctor` は CLI の 10 秒より前に失敗の 1 行を返す。
    #[test]
    fn doctor_gives_up_before_the_cli_does() {
        let d = short_dir("slow");
        let creds = d.join("agent.json");
        let (tx, (mut drx, _rrx)) = channels();
        // 要求を受け取ったまま答えない
        let held = std::thread::spawn(move || {
            let r = drx.blocking_recv();
            std::thread::sleep(DOCTOR_REPLY_WAIT + Duration::from_secs(1));
            drop(r);
        });
        let srv = Server::start(&creds, tx).unwrap();
        let started = Instant::now();
        let got = ask(&control_path(&creds), b"doctor\n");
        assert!(got.contains("did not collect its state within 5s"), "{got}");
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(srv);
        held.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_closed_runtime_is_reported_as_shutting_down() {
        let d = short_dir("closed");
        let creds = d.join("agent.json");
        let (tx, rx) = channels();
        drop(rx);
        let srv = Server::start(&creds, tx).unwrap();
        let sock = control_path(&creds);
        assert_eq!(
            ask(&sock, b"rotate-key\n"),
            "error: the agent is shutting down\n"
        );
        assert!(ask(&sock, b"doctor\n").contains("shutting down"));
        drop(srv);
        assert!(!sock.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_path_over_the_limit_runs_without_the_socket() {
        let d = short_dir("long");
        let creds = d.join("x".repeat(200)).join("agent.json");
        let (tx, _rx) = channels();
        assert!(Server::start(&creds, tx).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 取り下げが先なら実行時の側は始められず、受け口は鍵が変わっていないと答える。
    #[test]
    fn an_abandoned_rotate_key_cannot_start() {
        let (_tx, rx) = sync_channel(1);
        let state = RotateState::default();
        let r = wait_rotate_key(
            &rx,
            &state,
            Duration::from_millis(20),
            Duration::from_secs(1),
        );
        assert_eq!(r, Err(RotateWait::NotStarted));
        assert!(
            !state.start(),
            "the runtime must not start an abandoned request"
        );
        assert!(state.abandoned());
    }

    /// 始まりが先なら、受け口は始まるのを待つ長さを過ぎても、終わりを待って結果を返す。
    #[test]
    fn a_started_rotate_key_is_waited_for_past_the_start_wait() {
        let (tx, rx) = sync_channel(1);
        let state = Arc::new(RotateState::default());
        let runtime = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                assert!(state.start());
                // 鍵の保存とトンネルの作り直しが、始まるのを待つ長さを越える
                std::thread::sleep(Duration::from_millis(100));
                let _ = tx.send(Ok("PUB".to_owned()));
            })
        };
        let r = wait_rotate_key(
            &rx,
            &state,
            Duration::from_millis(20),
            Duration::from_secs(5),
        );
        assert_eq!(r, Ok(Ok("PUB".to_owned())));
        runtime.join().unwrap();
        // 終わりも待ち切れなければ、鍵は変わったかもしれないと答える
        let (_tx, rx) = sync_channel(1);
        let state = RotateState::default();
        assert!(state.start());
        let r = wait_rotate_key(
            &rx,
            &state,
            Duration::from_millis(10),
            Duration::from_millis(40),
        );
        assert_eq!(r, Err(RotateWait::StillRunning));
    }

    /// 上限を超えた接続にも、要求の形に合わせた理由の 1 行を返す。
    #[test]
    fn connections_over_the_limit_get_a_reason() {
        let d = short_dir("limit");
        let creds = d.join("agent.json");
        let (tx, rx) = channels();
        let (dt, _rt) = fake_runtime(rx);
        let srv = Server::start(&creds, tx).unwrap();
        let sock = control_path(&creds);
        // 黙った相手で上限を埋める
        let held: Vec<_> = (0..MAX_CONNECTIONS)
            .map(|_| ctlsock::connect(&sock, Duration::from_secs(5)).unwrap())
            .collect();
        std::thread::sleep(Duration::from_millis(100));
        let doctor = ask(&sock, b"doctor\n");
        assert!(
            doctor.starts_with("{\"error\":\"the agent is serving too many control connections"),
            "{doctor}"
        );
        assert!(
            ask(&sock, b"rotate-key\n")
                .starts_with("error: the agent is serving too many control connections"),
        );
        drop(held);
        drop(srv);
        assert_eq!(dt.join().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_request_closed_before_its_newline_gets_no_reply() {
        assert_eq!(read_request(&mut &b"doctor"[..]), None);
        assert_eq!(
            read_request(&mut &b"doctor\nx"[..]).as_deref(),
            Some("doctor")
        );
    }
}
