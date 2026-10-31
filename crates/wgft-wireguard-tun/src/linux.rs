//! Linux の TUN と UDP の socket で Device を回す。

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::process::Command as Process;
use tokio::sync::mpsc;
use wgft_wireguard::{Device, Event};

use crate::{Command, InboundFilter, Status, TunSettings, Verdict};

/// `IFF_TUN | IFF_NO_PI`。値は `c_short` に収まる。
#[expect(clippy::cast_possible_truncation, reason = "0x1001 fits in a c_short")]
const TUN_FLAGS: libc::c_short = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

fn open_tun(name: &str) -> io::Result<OwnedFd> {
    // カーネルは % を含む名前を番号の型として扱い、別の名前で作る。設定は渡した名前で行うので拒む
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || name
            .bytes()
            .any(|b| b == 0 || b == b'%' || b == b'/' || b.is_ascii_whitespace())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TUN name {name:?} must be 1 to 15 bytes without %, / or spaces"),
        ));
    }
    // SAFETY: open に NUL で終わる定数の path を渡す。戻り値は下で確かめる
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd は直前に開いた、ほかに持ち主のいない記述子
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ifreq は整数、配列、ポインタの union だけを持ち、すべて 0 のバイト列は正しい値である
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = libc::c_char::from_ne_bytes([src]);
    }
    req.ifr_ifru.ifru_flags = TUN_FLAGS;
    // SAFETY: req は TUNSETIFF が読み書きする struct ifreq で、呼び出しの間生きている
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &raw mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

async fn ip(args: &[&str]) -> io::Result<()> {
    let out = Process::new("ip").args(args).output().await?;
    if out.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

async fn configure(tun: &TunSettings) -> io::Result<()> {
    let addr = format!("{}/{}", tun.address, tun.prefix_len);
    let mtu = tun.mtu.to_string();
    // トンネルは IPv4 だけを運ぶ。カーネルが link up で送る IPv6 の近隣探索を TUN に流さない。
    // IPv6 の無いカーネルでは file が無い。そのときだけ無視する
    let path = format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", tun.name);
    match tokio::fs::write(&path, "1").await {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(io::Error::other(format!(
                "turn IPv6 off on {}: {e}",
                tun.name
            )));
        }
        _ => {}
    }
    ip(&["addr", "add", &addr, "dev", &tun.name]).await?;
    ip(&["link", "set", "dev", &tun.name, "mtu", &mtu, "up"]).await
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buf は書き込める長さ buf.len() の領域
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: buf は読める長さ buf.len() の領域
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

pub(crate) struct Shell {
    device: Device,
    tun: AsyncFd<OwnedFd>,
    udp: UdpSocket,
    events: mpsc::Sender<Event>,
    send_errors: u64,
    tun_write_errors: u64,
    filter: InboundFilter,
    filter_drops: u64,
    filter_replies: u64,
}

impl Shell {
    pub(crate) async fn open(
        device: Device,
        tun: &TunSettings,
        listen: SocketAddr,
        events: mpsc::Sender<Event>,
        filter: InboundFilter,
    ) -> io::Result<Self> {
        let fd = open_tun(&tun.name)?;
        configure(tun).await?;
        let udp = UdpSocket::bind(listen).await?;
        // SAFETY: OwnedFd は開いた記述子を持ち、AsyncFd が持つ間は同じ記述子を返し続ける
        let tun = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Self {
            device,
            tun,
            udp,
            events,
            send_errors: 0,
            tun_write_errors: 0,
            filter,
            filter_drops: 0,
            filter_replies: 0,
        })
    }

    fn status(&self) -> Status {
        let now = Instant::now();
        let peer = self
            .device
            .peers()
            .next()
            .and_then(|k| self.device.peer_status(&k, now));
        Status {
            peer,
            drops: *self.device.drops(),
            local: self
                .udp
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
            send_errors: self.send_errors,
            tun_write_errors: self.tun_write_errors,
            filter_drops: self.filter_drops,
            filter_replies: self.filter_replies,
        }
    }

    /// Device の出力をすべて取り出して socket と TUN と event の channel へ送る。
    async fn flush(&mut self) -> io::Result<()> {
        loop {
            while let Some(tx) = self.device.poll_transmit() {
                if self.udp.send_to(&tx.payload, tx.to).await.is_err() {
                    self.send_errors += 1;
                }
            }
            // 返事は Device に送信として入れ、送る datagram が増える。増えなくなるまで繰り返す。
            // 返事は受けた packet ごとに高々 1 つで、受けた packet は Device のキューの上限を超えない
            if !self.deliver_packets().await? {
                break;
            }
        }
        while let Some(event) = self.device.poll_event() {
            // 受け手が遅ければ捨てる。ループを event の受け手に止めさせない
            let _ = self.events.try_send(event);
        }
        Ok(())
    }

    /// 復号した packet を filter に通して TUN へ書く。返事を Device に入れたら `true` を返す。
    async fn deliver_packets(&mut self) -> io::Result<bool> {
        let mut replied = false;
        while let Some(packet) = self.device.poll_packet() {
            match (self.filter)(&packet) {
                Verdict::Deliver => {}
                Verdict::Drop => {
                    self.filter_drops += 1;
                    continue;
                }
                Verdict::Reply(reply) => {
                    self.filter_replies += 1;
                    self.device.handle_packet(Instant::now(), &reply);
                    replied = true;
                    continue;
                }
            }
            loop {
                let mut guard = self.tun.writable().await?;
                match guard.try_io(|fd| write_fd(fd.as_raw_fd(), &packet)) {
                    // 1 つの packet の書き込みの失敗でループを止めない。数えて次へ進む
                    Ok(result) => {
                        if result.is_err() {
                            self.tun_write_errors += 1;
                        }
                        break;
                    }
                    Err(_would_block) => {}
                }
            }
        }
        Ok(replied)
    }

    pub(crate) async fn run(mut self, mut commands: mpsc::Receiver<Command>) -> io::Result<()> {
        let mut udp_buf = vec![0u8; 65536];
        let mut tun_buf = vec![0u8; 65536];
        loop {
            self.flush().await?;
            let deadline = self.device.poll_timeout();
            let sleep = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                received = self.udp.recv_from(&mut udp_buf) => {
                    // 接続していない UDP の socket の誤りは一時的なものとして読み続ける
                    if let Ok((n, from)) = received {
                        self.device.handle_datagram(Instant::now(), from, &udp_buf[..n]);
                    }
                }
                ready = self.tun.readable() => {
                    let mut guard = ready?;
                    if let Ok(result) = guard.try_io(|fd| read_fd(fd.as_raw_fd(), &mut tun_buf)) {
                        let n = result?;
                        self.device.handle_packet(Instant::now(), &tun_buf[..n]);
                    }
                }
                () = sleep => self.device.handle_timeout(Instant::now()),
                command = commands.recv() => match command {
                    Some(Command::Status(reply)) => {
                        let _ = reply.send(self.status());
                    }
                    Some(Command::SetEndpoint(endpoint)) => {
                        let now = Instant::now();
                        let peer = self.device.peers().next();
                        if let Some(peer) = peer {
                            self.device.set_endpoint(now, &peer, endpoint);
                        }
                    }
                    Some(Command::Rebind(listen, reply)) => {
                        let result = match UdpSocket::bind(listen).await {
                            Ok(udp) => {
                                self.udp = udp;
                                self.udp.local_addr()
                            }
                            Err(e) => Err(e),
                        };
                        let _ = reply.send(result);
                    }
                    Some(Command::Stop) | None => return Ok(()),
                },
            }
        }
    }
}
