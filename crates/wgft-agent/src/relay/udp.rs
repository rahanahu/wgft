//! UDP の中継 (agent-parity.md の「UDP の中継」、Go の `relay/udp.go`)。
//!
//! 待ち受け 1 つにつき、データプレーンのスレッドの local の task が 1 つ動く。task は wgstack の UDP の
//! endpoint から datagram を受け、送信元の IPv4 のアドレスとポートでセッションを引く。新しい送信元の
//! 最初の datagram で、フロー数の予算の枠を取り、宛先の名前を解決して判定し、OS の UDP のソケットを宛先へ
//! 接続してセッションを作る。名前の解決はこの task の中で待つので、その間この待ち受けの受け取りは止まり、
//! datagram は wgstack の endpoint の上限の中に溜まる (v1 と同じ)。
//!
//! 宛先からの応答は、セッションごとの task がバッファを持たずに読みの準備と誤りを待ち、準備が来てから
//! 応答のバッファの枠 ([`super::replies`]) を借りて datagram の全体を読み、wgstack の endpoint から送信元へ
//! 送る。宛先の Port Unreachable はソケットの誤りとして届くので、セッションを閉じ、トンネルへ ICMP は
//! 送らない。同じ送信元の次の datagram が新しいセッションを作る。
//!
//! セッションは、どちらの向きの datagram も無い時間が無通信の期限を超えると閉じる。点検は期限の 4 分の
//! 1 ごとで、20 ミリ秒を下限にする。

use std::cell::Cell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::SocketAddrV4;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::Interest;
use tokio::net::UdpSocket as LanSocket;
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;
use wgft_netstack::{UdpSender, UdpSocket};

use super::replies::{Replies, UDP_BUF};
use super::{Gate, Held, Key, Running, Session, Shared, Spec};
use crate::flowpool::{self, Denied};
use crate::logf;
use crate::targets::{Targets, join_host_port};
use crate::tunnel::Net;

/// The idle timeout when the full state gives none or an unusable value (Go's default). The log
/// line names it the way Go prints it, `2m0s`.
pub(crate) const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(120);

/// The largest `wg.udp_timeout_stream` the agent takes, in seconds: the server keeps the value as a
/// 32-bit int (Go's `udpTimeoutStreamMaxSeconds`).
const UDP_IDLE_MAX_SECS: i64 = i32::MAX as i64;

/// The floor of the idle sweep's interval (Go's `minSweepInterval`).
pub(crate) const MIN_SWEEP: Duration = Duration::from_millis(20);

/// The idle timeout from the full state's `wg.udp_timeout_stream` seconds (Go's
/// `secondsToDuration`): 0 is the default without a word, as an older server sends no value; a
/// negative value or one above the 32-bit range is the default with a log line.
#[must_use]
pub(crate) fn udp_idle_timeout(seconds: i64) -> Duration {
    match seconds {
        0 => DEFAULT_UDP_IDLE,
        1..=UDP_IDLE_MAX_SECS => Duration::from_secs(seconds.unsigned_abs()),
        _ => {
            logf!(
                "wg.udp_timeout_stream {seconds} is out of the accepted range 1-{UDP_IDLE_MAX_SECS} seconds; using the default 2m0s instead"
            );
            DEFAULT_UDP_IDLE
        }
    }
}

/// The idle sweep's interval for an idle timeout: a quarter of it, at least [`MIN_SWEEP`] (Go's
/// `sweepInterval`).
#[must_use]
pub(crate) fn sweep_interval(idle: Duration) -> Duration {
    (idle / 4).max(MIN_SWEEP)
}

/// The first wait after a failed read, doubled up to [`RETRY_MAX`] (Go's `retryMin`).
const RETRY_MIN: Duration = Duration::from_millis(5);
/// The longest wait between two failed reads (Go's `retryMax`).
const RETRY_MAX: Duration = Duration::from_secs(1);

fn next_retry(d: Duration) -> Duration {
    (d * 2).clamp(RETRY_MIN, RETRY_MAX)
}

/// データプレーンのスレッドの上で、核に UDP の待ち受けを開き、受け取りの task を立てる。予算の枠は
/// 開けてから受け付けにする。
pub(super) fn start(net: &Net, s: Spec) -> Result<Running, String> {
    let sock = UdpSocket::bind(net, s.addr).map_err(|e| format!("bind udp {}: {e}", s.addr))?;
    s.budget.accept();
    let (stop, stopped) = oneshot::channel();
    let target = join_host_port(&s.host, s.tport);
    let listener = Listener {
        key: s.key,
        sender: sock.sender(),
        sock,
        host: s.host,
        tport: s.tport,
        target,
        budget: s.budget,
        shared: s.shared,
        targets: s.targets,
        idle: s.udp_idle,
        replies: s.replies,
        sessions: HashMap::new(),
        tasks: JoinSet::new(),
        cap_log: Gate::default(),
        dial_log: Gate::default(),
        write_log: Gate::default(),
        read_log: Gate::default(),
    };
    let task = tokio::task::spawn_local(serve(listener, stopped));
    Ok(Running { stop, task })
}

/// セッション 1 つ。落とすと、宛先のソケットを閉じ、フロー数の枠とセッションの数えを返す。応答の task は
/// 呼び手が止める。
struct Conn {
    lan: Rc<LanSocket>,
    /// どちらかの向きの datagram を最後に見た時刻。応答の task と分け合う。
    seen: Rc<Cell<Instant>>,
    reply: AbortHandle,
    _held: Held,
}

/// 待ち受け 1 つの受け取りの task が持つもの。
struct Listener {
    key: Key,
    sock: UdpSocket<Net>,
    sender: UdpSender<Net>,
    host: String,
    tport: u16,
    /// ログに出す宛先 (`host:port`)。
    target: String,
    budget: Arc<flowpool::Listener>,
    shared: Arc<Shared>,
    targets: Arc<Targets>,
    idle: Duration,
    replies: &'static Replies,
    sessions: HashMap<SocketAddrV4, Conn>,
    /// セッションごとの応答の task。終わると送信元を返す。
    tasks: JoinSet<SocketAddrV4>,
    /// 予算で拒んだログの門。
    cap_log: Gate,
    /// 宛先への接続の失敗のログの門。
    dial_log: Gate,
    /// 宛先への書き込みの失敗のログの門。
    write_log: Gate,
    /// トンネルの側の読み取りの失敗のログの門。
    read_log: Gate,
}

async fn serve(mut l: Listener, mut stopped: oneshot::Receiver<()>) {
    let mut buf = vec![0u8; UDP_BUF].into_boxed_slice();
    let every = sweep_interval(l.idle);
    let mut sweep = tokio::time::interval_at(Instant::now() + every, every);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut delay = Duration::ZERO;
    // 止める知らせではこの task が終わり、セッションと応答の task と待ち受けが一緒に落ちる。応答の task
    // は JoinSet が落ちるときに止まり、落ちた handle の Drop が待ち受けを閉じる
    loop {
        tokio::select! {
            biased;
            _ = &mut stopped => return,
            Some(done) = l.tasks.join_next_with_id(), if !l.tasks.is_empty() => l.reply_ended(done),
            _ = sweep.tick() => l.sweep(),
            r = l.sock.recv_from(&mut buf) => match r {
                Ok((n, from)) => {
                    delay = Duration::ZERO;
                    // 宛先の名前の解決と書き込みを待つ間も、止める知らせで止める
                    tokio::select! {
                        biased;
                        _ = &mut stopped => return,
                        () = l.datagram(&buf[..n], from) => {}
                    }
                }
                Err(e) => {
                    // 待ち受けを閉じた以外の失敗では、TCP の accept と同じく、待ち受けを開いたまま後退して
                    // 試し直す (Go と同じ)。世代の終わりの後は、スレッドとともにこの task も落ちる
                    if l.read_log.allow() {
                        logf!("{}: read failed: {e}; the listener stays open and retries", l.key);
                    }
                    delay = next_retry(delay);
                    tokio::select! {
                        biased;
                        _ = &mut stopped => return,
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            },
        }
    }
}

impl Listener {
    /// トンネルから届いた datagram 1 つ。既存のセッションなら宛先へ書き、新しい送信元ならセッションを
    /// 作ってから書く。
    async fn datagram(&mut self, data: &[u8], from: SocketAddrV4) {
        let lan = match self.sessions.get(&from) {
            Some(c) => {
                c.seen.set(Instant::now());
                Rc::clone(&c.lan)
            }
            None => match self.open(from).await {
                Some(lan) => lan,
                None => return,
            },
        };
        if let Err(e) = lan.send(data).await {
            if self.write_log.allow() {
                logf!(
                    "{}: write {} bytes to {}: {}; closing session",
                    self.key,
                    data.len(),
                    self.target,
                    write_error(&lan, &e)
                );
            }
            #[cfg(test)]
            self.shared
                .write_closes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.close(from);
        }
    }

    /// 新しい送信元のセッションを作り、宛先へのソケットを返す。作れなければ datagram を捨て、ICMP は
    /// 返さない。
    async fn open(&mut self, from: SocketAddrV4) -> Option<Rc<LanSocket>> {
        // フロー数の上限。拒んだ新しい送信元の datagram は捨てる。既存のセッションは追い出さない
        let lease = match self.budget.take() {
            Ok(x) => x,
            // 閉じる途中の待ち受け。予算の拒否ではないので、数にもログにも入れない
            Err(Denied::NotAccepting) => return None,
            Err(Denied::Refused(r)) => {
                if self.cap_log.allow() {
                    logf!("{}: {r}; dropping new flows", self.key);
                }
                return None;
            }
        };
        // 宛先のホスト名はセッションを作るときに解決する (DNS の変更は新しいセッションだけに効く)
        let dial = self.targets.connect_udp(&self.host, self.tport).await;
        self.shared.note(dial.as_ref().map(|_| ()));
        let lan = match dial {
            Ok(s) => Rc::new(s),
            Err(e) => {
                if self.dial_log.allow() {
                    logf!("{}: dial {}: {e}", self.key, self.target);
                }
                return None;
            }
        };
        raise_send_buffer(&lan);
        let seen = Rc::new(Cell::new(Instant::now()));
        let reply = self.tasks.spawn_local(reply_loop(Replying {
            lan: Rc::clone(&lan),
            sender: self.sender.clone(),
            to: from,
            seen: Rc::clone(&seen),
            replies: self.replies,
        }));
        let held = Held {
            _lease: lease,
            _session: Session::new(&self.shared),
        };
        // 名前の解決の間に同じ送信元のセッションができることは無い (この task だけが作る)
        self.sessions.insert(
            from,
            Conn {
                lan: Rc::clone(&lan),
                seen,
                reply,
                _held: held,
            },
        );
        Some(lan)
    }

    /// セッションを閉じる。応答の task を止め、宛先のソケットとフロー数の枠を返す。
    fn close(&mut self, from: SocketAddrV4) {
        if let Some(c) = self.sessions.remove(&from) {
            c.reply.abort();
        }
        self.shrink();
    }

    /// 応答の task が終わった。宛先の誤りで終わったセッションを閉じる。止めた task の終わりは、表の
    /// セッションが別の task のものになっているので触らない。
    fn reply_ended(
        &mut self,
        done: Result<(tokio::task::Id, SocketAddrV4), tokio::task::JoinError>,
    ) {
        let (id, from) = match done {
            Ok(x) => x,
            Err(e) if e.is_cancelled() => return,
            // panic した応答の task。どのセッションのものかを表から探す
            Err(e) => {
                let id = e.id();
                let Some(from) = self
                    .sessions
                    .iter()
                    .find(|(_, c)| c.reply.id() == id)
                    .map(|(k, _)| *k)
                else {
                    return;
                };
                (id, from)
            }
        };
        if let Entry::Occupied(o) = self.sessions.entry(from)
            && o.get().reply.id() == id
        {
            o.remove();
            self.shrink();
        }
    }

    /// 無通信の期限を過ぎたセッションを閉じる。
    fn sweep(&mut self) {
        let Some(cutoff) = Instant::now().checked_sub(self.idle) else {
            return;
        };
        let before = self.sessions.len();
        self.sessions.retain(|_, c| {
            let keep = c.seen.get() >= cutoff;
            if !keep {
                c.reply.abort();
            }
            keep
        });
        if self.sessions.len() != before {
            self.shrink();
        }
    }

    /// セッションの表の容量を、今の数の 4 倍と少しまでに抑える。表は自分では縮まないので、一度多くの
    /// セッションを持った待ち受けが、その容量を持ち続けないためである。上界はセッションの数に比例する。
    fn shrink(&mut self) {
        let n = self.sessions.len();
        if self.sessions.capacity() > 4 * n + SHRINK_SLACK {
            self.sessions.shrink_to(2 * n);
        }
    }
}

/// 表を縮めない容量の余裕。少ないセッションの待ち受けで、閉じるたびに縮め直さないため。
const SHRINK_SLACK: usize = 64;

/// 応答の task が持つもの。
struct Replying {
    lan: Rc<LanSocket>,
    sender: UdpSender<Net>,
    /// 応答を送る送信元。
    to: SocketAddrV4,
    seen: Rc<Cell<Instant>>,
    replies: &'static Replies,
}

/// 1 つのセッションの応答をトンネルへ返す。宛先の誤り (Port Unreachable を含む) か、トンネルへの送信の
/// 失敗で終わり、送信元を返す。待ちはバッファを持たずに行い、読める準備が来てから枠を借りる。
async fn reply_loop(r: Replying) -> SocketAddrV4 {
    let _ = reply_until_error(&r).await;
    r.to
}

async fn reply_until_error(r: &Replying) -> io::Result<()> {
    loop {
        let ready = r.lan.ready(Interest::READABLE | Interest::ERROR).await?;
        if ready.is_error() {
            // Linux は接続した UDP のソケットへの ICMP の拒否を EPOLLERR だけで知らせる。誤りを取り出して
            // 閉じる。誤りが無ければ (取り出し済み) 誤りの準備を消して待ちに戻る
            let taken = r.lan.try_io(Interest::ERROR, || match r.lan.take_error() {
                Ok(Some(e)) | Err(e) => Ok(e),
                Ok(None) => Err(io::ErrorKind::WouldBlock.into()),
            });
            if let Ok(e) = taken {
                return Err(e);
            }
        }
        if !ready.is_readable() {
            continue;
        }
        let mut reply = r.replies.acquire().await;
        let buf = reply.buf();
        let n = match r.lan.try_recv(buf) {
            Ok(n) => n,
            // 準備が偽だった。枠を返して待ちに戻る
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };
        r.seen.set(Instant::now());
        r.sender.send_to(&buf[..n], r.to).await?;
    }
}

/// 書き込みの誤りの文。Go の `net` の形 (`write udp <ローカル>-><宛先>: write: <理由>`) にする。
fn write_error(lan: &LanSocket, e: &io::Error) -> String {
    let text = crate::targets::dial::errno_text(e);
    match (lan.local_addr(), lan.peer_addr()) {
        (Ok(l), Ok(p)) => format!("write udp {l}->{p}: write: {text}"),
        _ => format!("write udp: {text}"),
    }
}

/// macOS では宛先へのソケットの送信バッファを 65535 byte に上げる。既定の `net.inet.udp.maxdgram`
/// (9216 byte) を超える datagram の書き込みが `EMSGSIZE` で失敗するためである。BSD のカーネルは UDP の
/// 送信バッファにデータを溜めないので、メモリは増えない。失敗は無視する (Go の `raiseUDPSendBuffer`)。
#[cfg(target_os = "macos")]
fn raise_send_buffer(s: &LanSocket) {
    let _ = socket2::SockRef::from(s).set_send_buffer_size(UDP_BUF);
}

#[cfg(not(target_os = "macos"))]
fn raise_send_buffer(_: &LanSocket) {}

/// 応答の task の future の大きさ。メモリの上界の試験が使う。
#[cfg(test)]
pub(super) fn reply_future_size() -> usize {
    fn output_size<A, F: Future>(_: impl FnOnce(A) -> F) -> usize {
        size_of::<F>()
    }
    output_size(reply_loop)
}

/// セッション 1 つが表と別の確保で持つバイト。表の容量の余裕を含む。
#[cfg(test)]
pub(super) fn session_entry_bytes() -> usize {
    // 容量は数の 4 倍までで、bucket は容量の 8/7 倍なので、項 5 つ分を数える
    5 * (size_of::<(SocketAddrV4, Conn)>() + 1)
        + size_of::<(usize, usize, LanSocket)>()
        + size_of::<(usize, usize, Cell<Instant>)>()
}
