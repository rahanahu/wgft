//! Linux の TUN と UDP の socket で Device を回す。

use std::cell::Cell;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::process::Command as Process;
use tokio::sync::mpsc;
use wgft_wireguard::{Device, Event};

use crate::{Command, InboundFilter, Status, TunSettings, Verdict};

/// `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`。EXCL は、同じ名前の持続する TUN が既にあれば作らずに
/// 失敗させる。ほかのプロセスが作った TUN に付かないため。
#[expect(
    clippy::cast_possible_truncation,
    reason = "TUNSETIFF reads the flags as a short; 0x9001 keeps its bits"
)]
const TUN_FLAGS: libc::c_short =
    (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;

fn open_tun(name: &str) -> io::Result<OwnedFd> {
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
        let e = io::Error::last_os_error();
        return Err(io::Error::new(
            e.kind(),
            format!("create TUN {name}: {e}; a device of that name may already exist"),
        ));
    }
    Ok(fd)
}

thread_local! {
    /// filter を呼んでいる間だけ true。panic の hook が静かにする範囲を示す
    static IN_FILTER: Cell<bool> = const { Cell::new(false) };
}

/// filter の panic は数えて捨てる。既定の hook は panic ごとに stderr へ書くので、filter が
/// packet ごとに panic すると出力が溢れる。filter の中の panic だけを 1 分に 1 行に絞る hook を、
/// 元の hook の前に 1 度だけ差し込む。ほかの panic は元の hook に渡す。
fn install_panic_hook() {
    static ONCE: Once = Once::new();
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !IN_FILTER.get() {
                previous(info);
                return;
            }
            let Ok(mut last) = LAST.lock() else {
                return;
            };
            let now = Instant::now();
            if last.is_none_or(|at| now.duration_since(at) >= Duration::from_secs(60)) {
                *last = Some(now);
                eprintln!(
                    "wgft-wireguard-tun: the inbound filter panicked and its packet was dropped: {info}; further panics within a minute are only counted"
                );
            }
        }));
    });
}

pub(crate) fn bind_to_device(socket: &impl AsFd, name: &str) -> io::Result<()> {
    let fd = socket.as_fd().as_raw_fd();
    let len = libc::socklen_t::try_from(name.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"))?;
    // SAFETY: name の領域は呼び出しの間生きていて、長さ len を読める
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// iproute2 の `ip` を、root が持ち、ほかの利用者が書けないシステムの場所から探す。PATH は使わない。
fn find_ip() -> io::Result<PathBuf> {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let path = Path::new(candidate);
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.mode() & 0o111 != 0
        {
            return Ok(path.to_owned());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no root-owned ip command of iproute2 in /usr/sbin, /sbin, /usr/bin or /bin",
    ))
}

async fn ip_output(tool: &Path, args: &[&str]) -> io::Result<String> {
    let out = Process::new(tool).args(args).output().await?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    Err(io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

async fn ip(tool: &Path, args: &[&str]) -> io::Result<()> {
    let out = Process::new(tool).args(args).output().await?;
    if out.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

/// shell が足す 3 つの rule。落ちるときにも消すため、Drop で消す。
struct Rules {
    ip: PathBuf,
    /// 優先度の順の rule。どれも `ip rule add` と `ip rule del` にそのまま渡せる
    specs: Vec<Vec<String>>,
    priorities: Vec<String>,
}

impl Rules {
    fn new(ip: &Path, tun: &TunSettings) -> Self {
        let from = format!("{}/32", tun.address);
        let p = |offset: u32| (tun.rule_priority + offset).to_string();
        let words = |list: &[&str]| list.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        let table = tun.table.to_string();
        Self {
            ip: ip.to_owned(),
            specs: vec![
                // トンネルのアドレスからは、専用の表だけを引く
                words(&["from", &from, "lookup", &table, "priority", &p(0)]),
                // 表に無い宛先は main へ落とさず、到達できないとする
                words(&["from", &from, "unreachable", "priority", &p(1)]),
                // TUN から来て、このホスト宛てでないものは捨てる
                words(&["iif", &tun.name, "blackhole", "priority", &p(2)]),
            ],
            priorities: (0..3).map(p).collect(),
        }
    }

    /// 同じ rule を消せなくなるまで消す。前の実行が落ちて残したものも消える。
    fn delete_blocking(&self) {
        for rule in &self.specs {
            for _ in 0..16 {
                let deleted = std::process::Command::new(&self.ip)
                    .args(["rule", "del"])
                    .args(rule)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if !deleted {
                    break;
                }
            }
        }
    }

    /// 自分の rule を消した後も同じ優先度に rule が残っていれば、ほかのソフトのものなので止まる。
    async fn refuse_foreign(&self) -> io::Result<()> {
        for priority in &self.priorities {
            let out = ip_output(&self.ip, &["rule", "list", "priority", priority]).await?;
            if !out.trim().is_empty() {
                return Err(io::Error::other(format!(
                    "rule priority {priority} is taken by another rule: {}; choose another priority",
                    out.trim()
                )));
            }
        }
        Ok(())
    }

    async fn add(&self) -> io::Result<()> {
        for rule in &self.specs {
            let mut args: Vec<&str> = vec!["rule", "add"];
            args.extend(rule.iter().map(String::as_str));
            args.extend(["protocol", "kernel"]);
            ip(&self.ip, &args).await?;
        }
        Ok(())
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        self.delete_blocking();
    }
}

/// TUN を作り、/32 のアドレス、MTU、リンクの状態、専用の表の経路、2 つの rule を設定する。
/// main の表は変えない。失敗すると、TUN を閉じてリンクと経路を消し、rule も消す。
async fn configure(tun: &TunSettings, fd: OwnedFd) -> io::Result<(OwnedFd, Rules)> {
    let tool = find_ip()?;
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
    let addr = format!("{}/32", tun.address);
    let mtu = tun.mtu.to_string();
    let table = tun.table.to_string();
    // このホストに既にあるアドレスをトンネルに付けると、そのアドレスの通信がトンネルの rule に当たる
    let assigned = ip_output(&tool, &["-o", "-4", "addr", "show", "to", &addr]).await?;
    if !assigned.trim().is_empty() {
        return Err(io::Error::other(format!(
            "tunnel address {} is already assigned on this host",
            tun.address
        )));
    }
    // 専用の表は空でなければならない。ほかのソフトの表なら、経路を混ぜずに止まる
    let routes = ip_output(&tool, &["-4", "route", "show", "table", &table]).await?;
    if !routes.trim().is_empty() {
        return Err(io::Error::other(format!(
            "routing table {table} is not empty; choose another table"
        )));
    }
    let rules = Rules::new(&tool, tun);
    rules.delete_blocking();
    rules.refuse_foreign().await?;
    ip(&tool, &["addr", "add", &addr, "dev", &tun.name]).await?;
    ip(&tool, &["link", "set", "dev", &tun.name, "mtu", &mtu, "up"]).await?;
    for route in &tun.routes {
        let route = route.to_string();
        ip(
            &tool,
            &["route", "add", &route, "dev", &tun.name, "table", &table],
        )
        .await?;
    }
    rules.add().await?;
    Ok((fd, rules))
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
    address: Ipv4Addr,
    tun: AsyncFd<OwnedFd>,
    /// TUN より後に落とす。リンクが消えてから rule を消す
    _rules: Rules,
    udp: UdpSocket,
    events: mpsc::Sender<Event>,
    send_errors: u64,
    tun_write_errors: u64,
    filter: InboundFilter,
    filter_drops: u64,
    filter_replies: u64,
    filter_panics: u64,
    wrong_destination: u64,
}

impl Shell {
    pub(crate) async fn open(
        device: Device,
        tun: &TunSettings,
        listen: SocketAddr,
        events: mpsc::Sender<Event>,
        filter: InboundFilter,
    ) -> io::Result<Self> {
        install_panic_hook();
        let address = tun.address;
        let fd = open_tun(&tun.name)?;
        let (fd, rules) = configure(tun, fd).await?;
        let udp = UdpSocket::bind(listen).await?;
        // SAFETY: OwnedFd は開いた記述子を持ち、AsyncFd が持つ間は同じ記述子を返し続ける
        let tun = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Self {
            device,
            address,
            tun,
            _rules: rules,
            udp,
            events,
            send_errors: 0,
            tun_write_errors: 0,
            filter,
            filter_drops: 0,
            filter_replies: 0,
            filter_panics: 0,
            wrong_destination: 0,
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
            filter_panics: self.filter_panics,
            wrong_destination: self.wrong_destination,
            unix_high_water: self.device.unix_high_water(),
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
            // Device は検査済みの IPv4 だけを渡す。宛先がトンネルのアドレスでないものは、ホストの
            // ほかのアドレスや LAN を狙ったもので、server は送らない。filter の前に捨てて数える
            if packet.get(16..20) != Some(&self.address.octets()[..]) {
                self.wrong_destination += 1;
                continue;
            }
            let filter = &mut self.filter;
            IN_FILTER.set(true);
            let result = catch_unwind(AssertUnwindSafe(|| filter(&packet)));
            IN_FILTER.set(false);
            let Ok(verdict) = result else {
                self.filter_panics += 1;
                continue;
            };
            match verdict {
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
