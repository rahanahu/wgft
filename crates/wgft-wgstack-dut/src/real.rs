//! `--clock real`:qbench の engine `wgstack-rs` の形です (`docs/design/v2/test-tooling.md` の 3 節と 5 節)。
//!
//! 核は実時間の外側の層 (`wgft-netstack` の handle と、agent のデータプレーンと同じ順の駆動) の上で動きます。
//!
//! - packet:起動の時に受け取る `SOCK_SEQPACKET` の socketpair を、1 つの packet を 1 つの message として読み書き
//!   します。相手 (qbench の Go の側) はもう片方を `tun.Device` として Rig の Link につなぎます
//! - アプリケーション:`ACCEPT` で受け取った接続を、`CONN_SOCKET` が渡す Unix ソケットにつなぎ、製品の中継と同じ
//!   形で両方の向きの byte を写します
//! - 要求:標準入力の frame を別のスレッドで読み、データプレーンのスレッドが 1 つずつ答えます。答えは待ちません。
//!   受け入れる接続が無ければ `ACCEPT` は `WOULD_BLOCK` です
//!
//! 1 つのスレッドの上で、駆動の task、要求に答える task、接続ごとの中継の task が交互に核を借用します。

use std::cell::RefCell;
use std::future::poll_fn;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::UnixDatagram as StdDatagram;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{UnixDatagram, UnixStream};
use tokio::sync::{mpsc, oneshot};
use wgft_netstack::{Access, LocalNetstack, Netstack, TcpListener, TcpStream};
use wgft_tcpharness::frame::{self, Clock, ErrKind, Handle, Hello, Msg, VERSION};
use wgft_wgstack::{Budget, NoHook};

use crate::dut::{ENGINE, WgstackDut, key_values, limits_from_hello};
use crate::serve::{EXIT_PROTOCOL, read_request};

type Ns = LocalNetstack<NoHook>;

/// 1 回の起床で読む packet と作る packet の上限です。agent の既定の値と同じ桁にし、届いた packet と送る packet が
/// 互いを待たせないようにします。
const PER_WAKE: usize = 64;

/// 中継の向きごとのバッファです。製品の中継の大きいバッファ (`BULK_BUF`) と同じ大きさです。
const RELAY_BUF: usize = 32 << 10;

/// handle が指す物です。
enum Obj {
    Listener(TcpListener<Ns>),
    /// 受け入れた後、`CONN_SOCKET` の前の接続です。
    Conn(TcpStream<Ns>),
    /// 中継の task に渡した接続です。送ると中継の task が接続を RST で終えます。
    Relayed(Option<oneshot::Sender<()>>),
    /// 閉じた handle です。
    Gone,
}

/// 口の誤りです。`ERROR` を書いて終了コード 2 で終わります。
struct Broken(String);

/// `--clock real` の DUT を出し、終了コードを返します。`packets` は socketpair の DUT の側で、`input` と `output`
/// は要求と応答の流れです。ログは標準エラーに書きます。
pub fn serve_real(
    packets: StdDatagram,
    input: impl Read + Send + 'static,
    output: impl Write,
) -> u8 {
    let mut r = BufReader::new(input);
    let mut w = io::BufWriter::new(output);
    let hello = match read_request(&mut r) {
        Ok(None) => return 0,
        Ok(Some(Msg::Hello(h))) => h,
        Ok(Some(m)) => {
            return fail(
                &mut w,
                &format!("the first request is {}, not HELLO", m.kind()),
            );
        }
        Err(e) => return fail(&mut w, &e),
    };
    let ns = match build(&hello) {
        Ok(ns) => ns,
        Err(e) => return fail(&mut w, &format!("HELLO: {e}")),
    };
    if packets.set_nonblocking(true).is_err() {
        return fail(&mut w, "cannot make the packet socket non-blocking");
    }
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&mut w, &format!("cannot start the runtime: {e}")),
    };
    let ok = Msg::HelloOk {
        engine: ENGINE.to_owned(),
        version: VERSION,
    };
    if frame::write_msg(&mut w, &ok).is_err() || w.flush().is_err() {
        eprintln!("wgstack-dut: cannot write the HELLO answer");
        return EXIT_PROTOCOL;
    }
    // 標準入力の読みは待つので、データプレーンのスレッドの外で読み、channel で渡す
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        loop {
            let req = read_request(&mut r);
            let end = !matches!(req, Ok(Some(_)));
            if tx.send(req).is_err() || end {
                return;
            }
        }
    });
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let packets = match UnixDatagram::from_std(packets) {
            Ok(s) => s,
            Err(e) => return fail(&mut w, &format!("cannot register the packet socket: {e}")),
        };
        let ns = LocalNetstack::new(ns);
        let (stop_tx, stop_rx) = oneshot::channel();
        let driver = tokio::task::spawn_local(drive(ns.clone(), packets, stop_rx));
        let code = answer_requests(&ns, rx, &mut w).await;
        let _ = stop_tx.send(());
        match driver.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("wgstack-dut: the driver ended: {e}"),
            Err(e) => eprintln!("wgstack-dut: the driver task failed: {e}"),
        }
        code
    })
}

fn fail(out: &mut impl Write, msg: &str) -> u8 {
    eprintln!("wgstack-dut: {msg}");
    let _ = frame::write_msg(
        out,
        &Msg::Error {
            err: ErrKind::Other,
            msg: msg.to_owned(),
        },
    );
    let _ = out.flush();
    EXIT_PROTOCOL
}

fn build(h: &Hello) -> Result<Netstack<NoHook>, String> {
    if h.version != VERSION {
        return Err(format!("protocol version {} is not {VERSION}", h.version));
    }
    if h.clock != Clock::Real {
        return Err("wgstack-dut --clock real takes only the real clock".to_owned());
    }
    let limits = limits_from_hello(&h.limits).map_err(|e| e.0)?;
    let config = WgstackDut::config(h, limits);
    let budget = Budget::new().map_err(|e| format!("wgstack: {e}"))?;
    let now = Instant::now();
    Netstack::new(config, budget, &h.seed, NoHook, now, Instant::now)
        .map_err(|e| format!("wgstack: {e}"))
}

/// 要求に 1 つずつ答えます。標準入力が閉じたら 0 を、口の誤りでは 2 を返します。
async fn answer_requests(
    ns: &Ns,
    mut rx: mpsc::UnboundedReceiver<Result<Option<Msg>, String>>,
    w: &mut impl Write,
) -> u8 {
    let mut objs: Vec<Obj> = Vec::new();
    loop {
        let req = match rx.recv().await {
            None | Some(Ok(None)) => return 0,
            Some(Ok(Some(Msg::Hello(_)))) => return fail(w, "a second HELLO"),
            Some(Ok(Some(m))) => m,
            Some(Err(e)) => return fail(w, &e),
        };
        let resp = match answer(ns, &mut objs, &req).await {
            Ok(m) => m,
            Err(Broken(m)) => return fail(w, &m),
        };
        if frame::write_msg(w, &resp).is_err() || w.flush().is_err() {
            eprintln!("wgstack-dut: cannot write the answer to {}", req.kind());
            return EXIT_PROTOCOL;
        }
    }
}

fn engine_err(err: ErrKind, msg: impl Into<String>) -> Msg {
    Msg::Error {
        err,
        msg: msg.into(),
    }
}

fn io_kind(e: &io::Error) -> ErrKind {
    match e.kind() {
        io::ErrorKind::ConnectionReset => ErrKind::Reset,
        io::ErrorKind::BrokenPipe => ErrKind::BrokenPipe,
        io::ErrorKind::TimedOut => ErrKind::Timeout,
        io::ErrorKind::NotConnected => ErrKind::Closed,
        _ => ErrKind::Other,
    }
}

fn slot(objs: &mut [Obj], h: Handle) -> Result<&mut Obj, Broken> {
    let i = usize::try_from(h.0).unwrap_or(usize::MAX);
    if i == 0 || i > objs.len() {
        return Err(Broken(format!("unknown handle {h}")));
    }
    Ok(&mut objs[i - 1])
}

fn add(objs: &mut Vec<Obj>, o: Obj) -> Handle {
    objs.push(o);
    Handle(u32::try_from(objs.len()).unwrap_or(u32::MAX))
}

async fn answer(ns: &Ns, objs: &mut Vec<Obj>, req: &Msg) -> Result<Msg, Broken> {
    let addr = ns.with(|n| n.core().config().addr);
    Ok(match req {
        Msg::TcpListen { port } => {
            let a = std::net::SocketAddrV4::new(addr, *port);
            match TcpListener::bind(ns, a) {
                Ok(l) => Msg::Handle(add(objs, Obj::Listener(l))),
                Err(e) => engine_err(io_kind(&e), format!("listen tcp {a}: {e}")),
            }
        }
        Msg::Accept(h) => {
            let Obj::Listener(l) = slot(objs, *h)? else {
                return Err(Broken(format!("handle {h} is not a listener")));
            };
            // 答えは待たない。登録する waker は何もしない waker で、次の ACCEPT がまた問い合わせる
            let mut cx = Context::from_waker(Waker::noop());
            match l.poll_accept(&mut cx) {
                Poll::Ready(Ok((s, remote))) => Msg::Accepted {
                    h: add(objs, Obj::Conn(s)),
                    remote,
                },
                Poll::Ready(Err(e)) => engine_err(io_kind(&e), format!("accept: {e}")),
                Poll::Pending => Msg::WouldBlock,
            }
        }
        Msg::ConnSocket { h, path } => {
            let o = slot(objs, *h)?;
            if !matches!(o, Obj::Conn(_)) {
                return Err(Broken(format!(
                    "handle {h} is not a connection that is not relayed yet"
                )));
            }
            let unix = match UnixStream::connect(path).await {
                Ok(u) => u,
                Err(e) => return Ok(engine_err(io_kind(&e), format!("connect {path}: {e}"))),
            };
            let Obj::Conn(s) = std::mem::replace(o, Obj::Gone) else {
                unreachable!("checked above");
            };
            let (abort_tx, abort_rx) = oneshot::channel();
            *o = Obj::Relayed(Some(abort_tx));
            tokio::task::spawn_local(relay_conn(s, unix, abort_rx));
            Msg::Ok
        }
        Msg::Abort(h) => {
            match std::mem::replace(slot(objs, *h)?, Obj::Gone) {
                Obj::Conn(s) => s.abort(),
                Obj::Relayed(Some(tx)) => {
                    let _ = tx.send(());
                }
                Obj::Listener(_) => return Err(Broken(format!("handle {h} is a listener"))),
                Obj::Relayed(None) | Obj::Gone => {}
            }
            Msg::Ok
        }
        Msg::Close(h) => {
            let o = slot(objs, *h)?;
            match std::mem::replace(o, Obj::Gone) {
                Obj::Conn(s) => drop(s.close()),
                // 中継の task が持つ接続は、中継が終わる時に閉じる
                Obj::Relayed(tx) => *o = Obj::Relayed(tx),
                Obj::Listener(l) => drop(l),
                Obj::Gone => {}
            }
            Msg::Ok
        }
        Msg::CloseWrite(h) => match slot(objs, *h)? {
            Obj::Conn(s) => match s.close_write() {
                Ok(()) => Msg::Ok,
                Err(e) => engine_err(io_kind(&e), format!("close: {e}")),
            },
            _ => engine_err(ErrKind::Other, "the connection is relayed or closed"),
        },
        Msg::Stats => Msg::Text(ns.with(|n| key_values(&format!("{:?}", n.core().stats())))),
        Msg::Bound => Msg::Text(ns.with(|n| key_values(&format!("{:?}", n.core().bound())))),
        Msg::Held => Msg::Text(ns.with(|n| key_values(&format!("{:?}", n.core().held())))),
        // 核は RTO の経過を知らせないので、分からないと答える (qbench の判定は Linux の RTO だけを使う)
        Msg::RtoAt { h, .. } => {
            slot(objs, *h)?;
            Msg::Rto {
                known: false,
                rto: std::time::Duration::ZERO,
            }
        }
        other => engine_err(
            ErrKind::Other,
            format!(
                "{} needs --clock fake; --clock real moves packets on the socketpair and bytes on Unix sockets",
                other.kind()
            ),
        ),
    })
}

/// 接続と Unix ソケットの間を中継します。両方の向きが終われば接続を閉じ、誤りか `ABORT` で RST を送ります。
async fn relay_conn(mut tun: TcpStream<Ns>, unix: UnixStream, abort: oneshot::Receiver<()>) {
    // ABORT が中継の終わりと同時に届いたら、閉じる前に RST にする。tokio::select! は既定で枝を乱数の順に
    // 試すので、biased で ABORT の枝を先に見る
    let r = tokio::select! {
        biased;
        a = abort => {
            if a.is_ok() {
                tun.abort();
                return;
            }
            // ABORT を送る側が消えた (要求の task が終わった) ときは中継を続けない
            Err(io::ErrorKind::Interrupted.into())
        }
        r = pipe(&mut tun, unix) => r,
    };
    match r {
        Ok(()) => drop(tun.close()),
        Err(_) => tun.abort(),
    }
}

/// 両方の向きを写します。片方の向きの終わりは反対側の送る向きを閉じて伝え、誤りは両方を止めます。
/// 製品の中継 (`wgft-agent` の `relay::pipe`) と同じ規則です。
///
/// # Errors
///
/// Returns the first read or write error of either side.
pub async fn pipe<T: AsyncRead + AsyncWrite + Unpin>(
    tun: &mut T,
    unix: UnixStream,
) -> io::Result<()> {
    let tun = RefCell::new(tun);
    let (mut rd, mut wr) = unix.into_split();
    let up = async {
        let mut buf = vec![0u8; RELAY_BUF];
        loop {
            let n = poll_fn(|cx| {
                let mut rb = ReadBuf::new(&mut buf);
                let mut t = tun.borrow_mut();
                match Pin::new(&mut **t).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            if n == 0 {
                let _ = wr.shutdown().await;
                return Ok::<(), io::Error>(());
            }
            wr.write_all(&buf[..n]).await?;
        }
    };
    let down = async {
        let mut buf = vec![0u8; RELAY_BUF];
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                poll_fn(|cx| Pin::new(&mut **tun.borrow_mut()).poll_shutdown(cx)).await?;
                return Ok::<(), io::Error>(());
            }
            let mut rest = &buf[..n];
            while !rest.is_empty() {
                let k =
                    poll_fn(|cx| Pin::new(&mut **tun.borrow_mut()).poll_write(cx, rest)).await?;
                if k == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                rest = &rest[k..];
            }
        }
    };
    tokio::try_join!(up, down).map(|_| ())
}

/// 駆動の task です。1 回の起床は agent のデータプレーンと同じ順です (`docs/design/v2/wgstack-rs.md` の
/// 「1 回の起床」):packet を読んで核に渡し、時刻の来たタイマーを回し、送り出し、waker を借用の外で起こし、
/// ログの行を出し、次の期限で待ちます。packet の socket が相手に閉じられたら終わります。
async fn drive(ns: Ns, sock: UnixDatagram, mut stop: oneshot::Receiver<()>) -> io::Result<()> {
    let mtu = ns.with(|n| n.core().config().mtu);
    let mut rx = vec![0u8; usize::from(u16::MAX)];
    let mut tx = vec![0u8; mtu];
    // socket が受け付けなかった packet の長さ。tx に残し、これがある間は核から引かない
    let mut pending: Option<usize> = None;
    let mut send_errors = 0u64;
    let mut wakers = Vec::new();
    loop {
        if ns.is_poisoned() {
            return Err(io::Error::other("a panic inside the TCP/IP core"));
        }
        let now = Instant::now();
        let mut more = false;
        let mut closed = false;
        let deadline = ns.with(|n| {
            let mut read = 0;
            loop {
                if read == PER_WAKE {
                    more = true;
                    break;
                }
                match sock.try_recv(&mut rx) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(k) => n.handle_packet(now, &rx[..k]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        closed = true;
                        break;
                    }
                }
                read += 1;
            }
            if n.poll_timeout().is_some_and(|t| t <= now) {
                n.handle_timeout(now);
            }
            let mut pulled = 0;
            loop {
                if let Some(len) = pending {
                    match sock.try_send(&tx[..len]) {
                        Ok(_) => pending = None,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        // 相手が socket を閉じた。読みの側も同じ時に閉じたと分かる
                        Err(e) if gone(&e) => {
                            pending = None;
                            closed = true;
                            break;
                        }
                        Err(_) => {
                            pending = None;
                            send_errors += 1;
                        }
                    }
                }
                if pulled == PER_WAKE {
                    more = true;
                    break;
                }
                let Some(len) = n.poll_transmit(now, &mut tx) else {
                    break;
                };
                pending = Some(len);
                pulled += 1;
            }
            n.poll_wakers(&mut wakers);
            while let Some(line) = n.poll_log() {
                eprintln!("{line}");
            }
            n.poll_timeout()
        });
        for w in wakers.drain(..) {
            w.wake();
        }
        if closed {
            if send_errors > 0 {
                eprintln!("wgstack-dut: {send_errors} packets could not be sent");
            }
            return Ok(());
        }
        let blocked = pending.is_some();
        tokio::select! {
            _ = &mut stop => return Ok(()),
            r = sock.readable() => r?,
            r = sock.writable(), if blocked => r?,
            () = sleep_until(deadline) => {}
            () = ns.driver_woken() => {}
            () = tokio::task::yield_now(), if more => {}
        }
    }
}

/// 相手が packet の socket を閉じた誤りかです。
fn gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    )
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(t) => tokio::time::sleep_until(t.into()).await,
        None => std::future::pending().await,
    }
}

/// `--relay`:2 つの Unix ソケットに接続し、その間を `pipe` で中継します。qbench が中継の 1 段だけの CPU と遅れを
/// 測るための形で、核を通しません。両方の向きが終われば 0 を返します。
pub fn relay_only(first: &str, second: &str) -> u8 {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wgstack-dut: cannot start the runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async {
        let (mut one, other) =
            match tokio::try_join!(UnixStream::connect(first), UnixStream::connect(second)) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("wgstack-dut: connect: {e}");
                    return 1;
                }
            };
        match pipe(&mut one, other).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("wgstack-dut: relay: {e}");
                1
            }
        }
    })
}
