//! ルールの中継 (試作は TCP だけ)。
//!
//! ルールのポートごとに、トンネルのアドレスに bind し、TUN の device に結び付けたカーネルの TCP の
//! ソケットで待ち受け、受けた接続をルールの宛先へ中継する。server はトンネルの中で agent のアドレスと
//! ルールのポートへ接続する。server のトンネルのアドレス以外からの接続は捨てる。
//!
//! リスナーはポートで区別し、そのリスナーの中継の接続をすべて持つ。ルールが消えるか、無効になるか、
//! 実効宛先が変わると、リスナーを閉じ、持っている接続をトンネルの側に RST を送って切る。
//!
//! 新しい接続は、フロー数の予算 ([`crate::flowpool`]) から枠を取ってから宛先へ接続する。宛先の許可一覧、
//! ブロードキャストとマルチキャストの拒否、名前の解決、接続の試し方、試し接続は [`crate::targets`] が
//! 持つ。どちらもトンネルの側の作りに依らないので、中継が wgstack に移っても同じものを使う。

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use socket2::SockRef;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use wgft_proto::{AgentRule, Proto, RuleStatus, STATUS_ERROR, STATUS_OK};

use crate::flowpool::{self, Denied, Limits, Pool};
use crate::logf;
use crate::targets::{TargetError, Targets};

/// 宛先への接続の期限。
pub const DIAL_TIMEOUT: Duration = crate::targets::DIAL_TIMEOUT;

/// 待ち受けている TCP のポートの集まり。トンネルの入口の検査 (`tunnel`) が読む。
pub type OpenPorts = Arc<RwLock<BTreeSet<u16>>>;

/// 1 分に 1 回までのログの門。
#[derive(Debug, Default)]
struct Gate(Option<Instant>);

impl Gate {
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if self.0.is_some_and(|next| now < next) {
            return false;
        }
        self.0 = Some(now + Duration::from_mins(1));
        true
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 待ち受けと、その中継の接続が分け合う状態。
#[derive(Debug, Default)]
struct Shared {
    /// 宛先の試し接続の失敗か、接続のときの宛先の拒否。待ち受けは開いているので、開き直さずに確かめ
    /// 直す。
    target_err: Mutex<Option<TargetError>>,
    /// `target_err` が今、宛先の拒否かどうか。接続ごとの判定が、状態が変わらないときに排他を取らずに
    /// 済ませるための印。
    denied: AtomicBool,
    /// 予算で拒んだログの門。
    refuse_log: Mutex<Gate>,
    /// 宛先への接続の失敗のログの門。宛先が落ちている間、接続のたびに出さない。
    dial_log: Mutex<Gate>,
}

impl Shared {
    /// 接続のときの宛先の拒否をリスナーの状態に載せる。扱うのは拒否だけで、宛先が落ちているなどの接続の
    /// 失敗はログだけにする。接続できたら、前に載せた拒否を消す (DNS が許す宛先に戻った場合)。試し接続の
    /// 失敗は消さない。
    fn note(&self, r: Result<(), &TargetError>) {
        let denied = match r {
            Err(e) if !e.denied => return,
            Err(_) => true,
            Ok(()) => false,
        };
        if denied == self.denied.load(Ordering::Acquire) {
            return;
        }
        let mut te = lock(&self.target_err);
        match r {
            Err(e) => *te = Some(e.clone()),
            Ok(()) if te.as_ref().is_some_and(|e| e.denied) => *te = None,
            Ok(()) => {}
        }
        self.denied
            .store(te.as_ref().is_some_and(|e| e.denied), Ordering::Release);
    }

    /// 試し接続の結果を書き、前の値を返す。
    fn set_probe(&self, r: Option<TargetError>) -> Option<TargetError> {
        let mut te = lock(&self.target_err);
        self.denied
            .store(r.as_ref().is_some_and(|e| e.denied), Ordering::Release);
        std::mem::replace(&mut *te, r)
    }

    fn target_err(&self) -> Option<TargetError> {
        lock(&self.target_err).clone()
    }
}

#[derive(Debug)]
struct Listener {
    rule_id: String,
    port: u16,
    target: (String, u16),
    task: Option<JoinHandle<()>>,
    /// 待ち受けを開けなかった理由。bind の失敗か、IP リテラルの宛先の拒否。[`Manager::retry`] が
    /// 開き直す。
    bind_err: Option<String>,
    /// フロー数の予算の枠。bind できるまで受け付けない。
    budget: Arc<flowpool::Listener>,
    shared: Arc<Shared>,
}

impl Listener {
    /// 受け付けのタスクを止めて、待ち受けのソケットとすべての中継の接続が閉じるまで待ち、予算の枠を
    /// 外す。
    async fn close(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
            let _ = t.await;
        }
        self.budget.close();
    }

    /// 報告する誤り。待ち受けが無いので bind の失敗が先。
    fn err(&self) -> Option<String> {
        self.bind_err
            .clone()
            .or_else(|| self.shared.target_err().map(|e| e.text))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// 中継の全体。トンネルと一緒に作り、一緒に閉じる。リスナーはポートで区別するので、数は TCP の
/// ポートの数を超えない。v1 もルールの範囲の幅に上限を置かない。フロー数の予算もトンネルごとに作るので、
/// 拒否の数はトンネルを作り直すと 0 に戻る。
#[derive(Debug)]
pub struct Manager {
    addr: Ipv4Addr,
    server: Ipv4Addr,
    device: Option<String>,
    listeners: BTreeMap<u16, Listener>,
    unsupported: BTreeMap<String, String>,
    open: OpenPorts,
    targets: Arc<Targets>,
    tcp: Pool,
    udp: Pool,
}

impl Manager {
    /// トンネルのアドレス `addr` で待ち受け、`server` からの接続だけを受ける中継を作る。`device` が
    /// あれば、待ち受けのソケットをその interface に結び付ける (Linux の `SO_BINDTODEVICE`)。待ち受けて
    /// いるポートは `open` に書き、トンネルの入口の検査と分け合う。宛先の規則は `targets`、フロー数の
    /// 上限は `limits` に従う。
    #[must_use]
    pub fn new(
        addr: Ipv4Addr,
        server: Ipv4Addr,
        device: Option<String>,
        open: OpenPorts,
        targets: Arc<Targets>,
        limits: Limits,
    ) -> Self {
        Manager {
            addr,
            server,
            device,
            listeners: BTreeMap::new(),
            unsupported: BTreeMap::new(),
            open,
            targets,
            tcp: Pool::new(limits.tcp),
            udp: Pool::new(limits.udp),
        }
    }

    /// 待ち受けている TCP のポートの集まり。
    #[must_use]
    pub fn open_ports(&self) -> OpenPorts {
        Arc::clone(&self.open)
    }

    /// TCP のフロー数の予算。
    #[must_use]
    pub fn tcp_pool(&self) -> &Pool {
        &self.tcp
    }

    /// UDP のフロー数の予算。UDP の中継が入るまで、枠を取る者はいない。
    #[must_use]
    pub fn udp_pool(&self) -> &Pool {
        &self.udp
    }

    /// 宣言に合わせる。ポートごとに実効宛先を比べ、変わったリスナーだけを閉じてから開き直す。
    /// 実効宛先が同じならルールの ID だけを置き換える。開けなかったリスナーは状態の誤りに出し、
    /// [`Manager::retry`] が開き直す。開いたリスナーの宛先へ試し接続し、その結果を待ってから戻るので、
    /// 最初の状態は適用の直後のハートビートに載る。戻り値は操作の数。
    pub async fn apply(&mut self, rules: &[AgentRule]) -> usize {
        let mut want: BTreeMap<u16, (String, (String, u16))> = BTreeMap::new();
        self.unsupported.clear();
        for r in rules.iter().filter(|r| r.enabled) {
            match &r.proto {
                Proto::Tcp => {
                    let targets: Option<Vec<_>> = r
                        .listen_port
                        .ports()
                        .map(|p| r.effective_target(p).map(|t| (p, t)))
                        .collect();
                    // 使えない宛先のルールはリスナーを 1 つも開かない
                    let Some(targets) = targets else {
                        self.unsupported.insert(
                            r.id.clone(),
                            format!(
                                "tcp/{}: target {:?} is not a usable host:port",
                                r.listen_port, r.target
                            ),
                        );
                        continue;
                    };
                    for (p, t) in targets {
                        want.insert(p, (r.id.clone(), t));
                    }
                }
                Proto::Udp => {
                    self.unsupported.insert(
                        r.id.clone(),
                        "udp rules are not supported by this prototype yet".into(),
                    );
                }
                Proto::Other(s) => {
                    self.unsupported
                        .insert(r.id.clone(), format!("unknown protocol {s:?}"));
                }
            }
        }
        let mut actions = 0;
        let stale: Vec<u16> = self
            .listeners
            .iter()
            .filter(|(p, l)| want.get(p).is_none_or(|(_, t)| *t != l.target))
            .map(|(p, _)| *p)
            .collect();
        // 入口の検査に先に知らせ、閉じるポートの packet を通さなくしてからリスナーを閉じる
        {
            let mut open = self.open.write().unwrap_or_else(PoisonError::into_inner);
            for p in &stale {
                open.remove(p);
            }
        }
        for p in stale {
            if let Some(mut l) = self.listeners.remove(&p) {
                l.close().await;
                logf!("listener tcp/{p} closed");
            }
            actions += 1;
        }
        let mut opened = Vec::new();
        for (p, (id, target)) in want {
            if let Some(l) = self.listeners.get_mut(&p) {
                l.budget.set_rule(&id);
                l.rule_id = id;
                continue;
            }
            let budget = Arc::new(self.tcp.pending_listener(&id));
            let mut l = Listener {
                rule_id: id,
                port: p,
                target,
                task: None,
                bind_err: None,
                budget,
                shared: Arc::default(),
            };
            self.open_listener(&mut l);
            self.listeners.insert(p, l);
            opened.push(p);
            actions += 1;
        }
        self.publish();
        self.probe(&opened).await;
        actions
    }

    /// 30 秒ごとの見回り。開けなかったリスナーを開き直し、開いている TCP のリスナーの宛先へ試し接続する。
    /// 宛先が戻れば誤りが消え、落ちれば付く。状態の変化はハートビートで報告される。
    pub async fn retry(&mut self) {
        let mut ls = std::mem::take(&mut self.listeners);
        for l in ls.values_mut().filter(|l| l.task.is_none()) {
            self.open_listener(l);
        }
        self.listeners = ls;
        self.publish();
        let ports: Vec<u16> = self.listeners.keys().copied().collect();
        self.probe(&ports).await;
    }

    /// 開いているリスナーのうち `ports` の宛先へ試し接続し、結果を状態に書く。到達性が変わったリスナー
    /// だけ、ログを 1 行出す。
    async fn probe(&self, ports: &[u16]) {
        let ls: Vec<&Listener> = ports
            .iter()
            .filter_map(|p| self.listeners.get(p))
            .filter(|l| l.task.is_some())
            .collect();
        if ls.is_empty() {
            return;
        }
        let list: Vec<(String, u16)> = ls.iter().map(|l| l.target.clone()).collect();
        let results = self.targets.probe_all(&list).await;
        for (l, r) in ls.into_iter().zip(results) {
            let (host, tport) = &l.target;
            let now = r.err();
            let before = l.shared.set_probe(now.clone());
            match (before, now) {
                (None, Some(e)) => logf!(
                    "listener tcp/{}: cannot connect to target {host}:{tport}: {e}",
                    l.port
                ),
                (Some(_), None) => logf!(
                    "listener tcp/{}: target {host}:{tport} is reachable again",
                    l.port
                ),
                _ => {}
            }
        }
    }

    /// すべてのリスナーと中継の接続を閉じる。
    pub async fn close(&mut self) {
        for (p, mut l) in std::mem::take(&mut self.listeners) {
            l.close().await;
            logf!("listener tcp/{p} closed");
        }
        self.publish();
    }

    fn publish(&self) {
        let ports = self
            .listeners
            .values()
            .filter(|l| l.task.is_some())
            .map(|l| l.port)
            .collect();
        *self.open.write().unwrap_or_else(PoisonError::into_inner) = ports;
    }

    /// 待ち受けを 1 つ開いて中継を始める。IP リテラルの宛先が拒まれれば bind しない。bind を先に行い、
    /// 開けてから予算の枠を受け付けにする。逆の順にすると、bind に失敗した待ち受けのルールが予算の
    /// ルールの数に入り、その間だけ他のルールの最低分が減る。
    fn open_listener(&self, l: &mut Listener) {
        let (host, tport) = l.target.clone();
        if let Some(e) = self.targets.refuse_literal(&host, tport) {
            logf!("listener tcp/{}: {e}", l.port);
            l.bind_err = Some(e.text);
            return;
        }
        let bind = SocketAddrV4::new(self.addr, l.port);
        match bind_listener(bind, self.device.as_deref()) {
            Ok(listener) => {
                l.bind_err = None;
                l.budget.accept();
                l.task = Some(tokio::spawn(accept_loop(Accepting {
                    listener,
                    server: self.server,
                    port: l.port,
                    host: host.clone(),
                    tport,
                    budget: Arc::clone(&l.budget),
                    shared: Arc::clone(&l.shared),
                    targets: Arc::clone(&self.targets),
                })));
                logf!(
                    "listener tcp/{} -> {host}:{tport} opened; rule {}",
                    l.port,
                    l.rule_id
                );
            }
            Err(e) => {
                let e = format!("bind tcp {bind}: {e}");
                logf!("listener tcp/{}: {e}", l.port);
                l.bind_err = Some(e);
            }
        }
    }

    /// 待ち受けているリスナーの数。
    #[must_use]
    pub fn listening(&self) -> usize {
        self.listeners.values().filter(|l| l.task.is_some()).count()
    }

    /// ルールごとの状態。1 つでも誤りのリスナーがあればそのルールは `error`。
    #[must_use]
    pub fn status(&self) -> Vec<RuleStatus> {
        let mut by: BTreeMap<String, RuleStatus> = BTreeMap::new();
        for l in self.listeners.values() {
            let r = by.entry(l.rule_id.clone()).or_insert_with(|| RuleStatus {
                id: l.rule_id.clone(),
                state: STATUS_OK.into(),
                reason: String::new(),
            });
            if let Some(e) = l.err()
                && r.state == STATUS_OK
            {
                r.state = STATUS_ERROR.into();
                r.reason = format!("tcp/{}: {e}", l.port);
            }
        }
        for (id, reason) in &self.unsupported {
            by.insert(
                id.clone(),
                RuleStatus {
                    id: id.clone(),
                    state: STATUS_ERROR.into(),
                    reason: reason.clone(),
                },
            );
        }
        by.into_values().collect()
    }
}

fn bind_listener(bind: SocketAddrV4, device: Option<&str>) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    if let Some(d) = device {
        s.bind_device(Some(d.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = device;
    s.bind(&bind.into())?;
    s.listen(1024)?;
    TcpListener::from_std(s.into())
}

/// 中継の接続のトンネルの側。正常に終わらずに捨てられたとき (リスナーを閉じたとき、予算と宛先の拒否) は、
/// `SO_LINGER` を 0 にして閉じ、server に RST を送る。
struct TunnelSide {
    stream: TcpStream,
    finished: bool,
}

impl Drop for TunnelSide {
    fn drop(&mut self) {
        if !self.finished {
            let _ = SockRef::from(&self.stream).set_linger(Some(Duration::ZERO));
        }
    }
}

/// 受け付けのタスクが持つもの。
struct Accepting {
    listener: TcpListener,
    server: Ipv4Addr,
    port: u16,
    host: String,
    tport: u16,
    budget: Arc<flowpool::Listener>,
    shared: Arc<Shared>,
    targets: Arc<Targets>,
}

async fn accept_loop(a: Accepting) {
    let port = a.port;
    // 中継の接続はこのタスクが持つ。タスクを止めると JoinSet が捨てられ、どの接続も止まる
    let mut flows = JoinSet::new();
    loop {
        tokio::select! {
            accepted = a.listener.accept() => {
                let (conn, from) = match accepted {
                    Ok(c) => c,
                    Err(e) => {
                        logf!("relay: tcp/{port}: accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let down = TunnelSide { stream: conn, finished: false };
                if !matches!(from, SocketAddr::V4(f) if *f.ip() == a.server) {
                    logf!("relay: tcp/{port}: refused a connection from {from}, which is not the server's tunnel address");
                    drop(down);
                    continue;
                }
                // フロー数の上限。拒んだ接続は握手の後、データを送る前に RST で閉じる。既存の接続は
                // 追い出さない
                let lease = match a.budget.take() {
                    Ok(x) => x,
                    Err(Denied::NotAccepting) => {
                        // 閉じる途中の待ち受け。予算の拒否ではないので、数にもログにも入れない
                        drop(down);
                        continue;
                    }
                    Err(Denied::Refused(r)) => {
                        drop(down);
                        if lock(&a.shared.refuse_log).allow() {
                            logf!("tcp/{port}: {r}; refusing new connections");
                        }
                        continue;
                    }
                };
                flows.spawn(relay_one(
                    down,
                    lease,
                    port,
                    a.host.clone(),
                    a.tport,
                    Arc::clone(&a.shared),
                    Arc::clone(&a.targets),
                ));
            }
            Some(_) = flows.join_next(), if !flows.is_empty() => {}
        }
    }
}

/// 1 本の接続を中継する。`lease` は中継が終わるまで持ち、落とすと予算へ返る。
async fn relay_one(
    mut down: TunnelSide,
    lease: flowpool::Lease,
    port: u16,
    host: String,
    tport: u16,
    shared: Arc<Shared>,
    targets: Arc<Targets>,
) {
    let _lease = lease;
    let dial = targets.connect_tcp(&host, tport).await;
    shared.note(dial.as_ref().map(|_| ()));
    let mut up = match dial {
        Ok(s) => s,
        Err(e) => {
            if lock(&shared.dial_log).allow() {
                logf!("tcp/{port}: dial {host}:{tport}: {e}");
            }
            // 宛先の拒否は、上限の拒否と同じく RST で終える。宛先に繋がらなければ、仕様のとおり
            // トンネルの側を FIN で閉じる
            down.finished = !e.denied;
            return;
        }
    };
    let _ = up.set_nodelay(true);
    let _ = down.stream.set_nodelay(true);
    let _ = tokio::io::copy_bidirectional(&mut down.stream, &mut up).await;
    down.finished = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn rule(id: &str, proto: Proto, port: &str, target: &str, enabled: bool) -> AgentRule {
        AgentRule {
            id: id.into(),
            proto,
            listen_port: port.parse().unwrap(),
            target: target.into(),
            enabled,
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// 接続ごとに読んだものを返す echo の宛先。
    async fn echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        a
    }

    async fn round_trip(c: &mut TcpStream, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        c.write_all(msg).await?;
        let mut got = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut got))
            .await
            .map_err(std::io::Error::other)??;
        Ok(got)
    }

    /// 試験の宛先の規則。ホストのインタフェースは読まず、名前は `names` の表で引く。
    fn targets(allow: &str, names: Vec<(&'static str, &'static str)>) -> Arc<Targets> {
        use crate::targets::resolve::Resolver;
        use crate::targets::unicast::Unicast;
        let allow = crate::config::allow_targets::parse(allow).unwrap();
        let resolver = Resolver::with_lookup(
            8,
            1,
            Arc::new(move |h: &str| {
                names
                    .iter()
                    .find(|(n, _)| *n == h)
                    .map(|(_, a)| vec![a.parse().unwrap()])
                    .ok_or_else(|| std::io::Error::other("Name or service not known"))
            }),
        );
        Arc::new(Targets::with(
            allow,
            Unicast::new(Box::new(|| Ok(Vec::new()))),
            Arc::new(resolver),
        ))
    }

    fn manager_with(targets: Arc<Targets>, limits: Limits) -> Manager {
        Manager::new(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            None,
            OpenPorts::default(),
            targets,
            limits,
        )
    }

    fn manager() -> Manager {
        manager_with(targets("", vec![]), Limits::default())
    }

    /// 接続が RST で切られたか。
    async fn was_reset(c: &mut TcpStream) -> bool {
        let mut buf = [0u8; 8];
        let r = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .unwrap();
        matches!(r, Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset)
    }

    #[tokio::test]
    async fn relays_and_cuts_the_flow_when_the_rule_is_disabled() {
        let target = echo().await;
        let port = free_port();
        let mut m = manager();
        let on = [rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &target.to_string(),
            true,
        )];
        assert_eq!(m.apply(&on).await, 1);
        assert_eq!(m.apply(&on).await, 0);
        assert!(m.open_ports().read().unwrap().contains(&port));
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(round_trip(&mut c, b"hello").await.unwrap(), b"hello");
        let off = [rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &target.to_string(),
            false,
        )];
        assert_eq!(m.apply(&off).await, 1);
        assert!(m.open_ports().read().unwrap().is_empty());
        // 開いていた接続は RST で切れている
        let mut buf = [0u8; 8];
        let r = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .unwrap();
        assert!(
            matches!(r, Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn a_target_change_rebinds_at_once() {
        let first = echo().await;
        let second = echo().await;
        let port = free_port();
        let mut m = manager();
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &first.to_string(),
            true,
        )])
        .await;
        assert_eq!(
            m.apply(&[rule(
                "r_b",
                Proto::Tcp,
                &port.to_string(),
                &second.to_string(),
                true
            )])
            .await,
            2
        );
        assert_eq!(m.listening(), 1);
        assert_eq!(
            m.status(),
            vec![RuleStatus {
                id: "r_b".into(),
                state: "ok".into(),
                reason: String::new()
            }]
        );
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
    }

    #[tokio::test]
    async fn a_new_rule_id_with_the_same_target_keeps_the_listener() {
        let target = echo().await;
        let port = free_port();
        let mut m = manager();
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &target.to_string(),
            true,
        )])
        .await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(
            m.apply(&[rule(
                "r_b",
                Proto::Tcp,
                &port.to_string(),
                &target.to_string(),
                true
            )])
            .await,
            0
        );
        assert_eq!(m.status()[0].id, "r_b");
        assert_eq!(round_trip(&mut c, b"still").await.unwrap(), b"still");
    }

    #[tokio::test]
    async fn closes_with_fin_when_the_target_refuses() {
        // 待ち受けの無い宛先
        let dead = free_port();
        let port = free_port();
        let mut m = manager();
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &format!("127.0.0.1:{dead}"),
            true,
        )])
        .await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 8];
        let r = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
            .await
            .unwrap();
        // FIN なら EOF (0 byte)、RST なら ConnectionReset
        assert!(matches!(r, Ok(0)), "{r:?}");
    }

    #[tokio::test]
    async fn refuses_peers_other_than_the_server() {
        let target = echo().await;
        let port = free_port();
        // server のアドレスを 127.0.0.2 にすると、127.0.0.1 からの接続は捨てられる
        let mut m = Manager::new(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 0, 0, 2),
            None,
            OpenPorts::default(),
            targets("", vec![]),
            Limits::default(),
        );
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &target.to_string(),
            true,
        )])
        .await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(round_trip(&mut c, b"no").await.is_err());
    }

    #[tokio::test]
    async fn reports_unsupported_unusable_and_failed_listeners() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let target = echo().await;
        let mut m = manager();
        m.apply(&[
            rule("r_u", Proto::Udp, "27015", "192.0.2.1:27015", true),
            rule(
                "r_t",
                Proto::Tcp,
                &port.to_string(),
                &target.to_string(),
                true,
            ),
            rule("r_x", Proto::Tcp, "40000-40001", "192.0.2.1:65535", true),
        ])
        .await;
        let st = m.status();
        assert_eq!(st.len(), 3);
        assert!(st.iter().all(|s| s.state == "error"), "{st:?}");
        let t = st.iter().find(|s| s.id == "r_t").unwrap();
        assert!(
            t.reason
                .starts_with(&format!("tcp/{port}: bind tcp 127.0.0.1:{port}: ")),
            "{t:?}"
        );
        assert_eq!(m.listening(), 0);
        drop(taken);
        m.retry().await;
        assert_eq!(m.listening(), 1);
        assert_eq!(m.tcp_pool().rules(), 1);
    }

    #[tokio::test]
    async fn the_flow_budget_resets_new_connections_and_keeps_existing_ones() {
        let target = echo().await;
        let port = free_port();
        // 予算 16 でルールが 1 本なら、予備の 4 を除いた 12 本まで
        let mut m = manager_with(targets("", vec![]), Limits { udp: 16, tcp: 16 });
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &target.to_string(),
            true,
        )])
        .await;
        let mut held = Vec::new();
        for _ in 0..12 {
            let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
            held.push(c);
        }
        let mut over = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(was_reset(&mut over).await);
        assert_eq!(m.tcp_pool().in_use(), 12);
        assert_eq!(
            m.tcp_pool().refusals()["r_a"][flowpool::Reason::Spare as usize],
            1
        );
        // 既存の接続は残る。1 本閉じれば新しい接続が通る
        assert_eq!(round_trip(&mut held[0], b"y").await.unwrap(), b"y");
        drop(held.pop());
        for _ in 0..50 {
            if m.tcp_pool().in_use() == 11 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(round_trip(&mut c, b"z").await.unwrap(), b"z");
        // ルールを無効にすると予算からも外れる
        m.apply(&[]).await;
        assert_eq!(m.tcp_pool().rules(), 0);
    }

    #[tokio::test]
    async fn an_ip_literal_outside_the_allowlist_is_not_opened() {
        let target = echo().await;
        let port = free_port();
        let mut m = manager_with(targets("10.0.0.0/8", vec![]), Limits::default());
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &target.to_string(),
            true,
        )])
        .await;
        assert_eq!(m.listening(), 0);
        assert_eq!(m.tcp_pool().rules(), 0);
        let st = m.status();
        assert_eq!(st[0].state, "error");
        assert_eq!(
            st[0].reason,
            format!("tcp/{port}: target {target} is not in WGFT_AGENT_ALLOW_TARGETS")
        );
        // 開き直しでも同じ判定
        m.retry().await;
        assert_eq!(m.listening(), 0);
    }

    #[tokio::test]
    async fn a_hostname_the_allowlist_refuses_is_reset_at_connect_and_reported() {
        let target = echo().await;
        let port = free_port();
        let mut m = manager_with(
            targets("10.0.0.0/8", vec![("nas.lan", "127.0.0.1")]),
            Limits::default(),
        );
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &format!("nas.lan:{}", target.port()),
            true,
        )])
        .await;
        // 待ち受けは開き、試し接続が拒否を状態に載せる
        assert_eq!(m.listening(), 1);
        let want = format!(
            "tcp/{port}: target 127.0.0.1:{} is not in WGFT_AGENT_ALLOW_TARGETS",
            target.port()
        );
        assert_eq!(m.status()[0].reason, want);
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(was_reset(&mut c).await);
        assert_eq!(m.status()[0].reason, want);
        // 拒んだ接続は枠を返す
        for _ in 0..50 {
            if m.tcp_pool().in_use() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(m.tcp_pool().in_use(), 0);
    }

    #[tokio::test]
    async fn probes_report_an_unreachable_target_and_its_recovery() {
        let dead = free_port();
        let port = free_port();
        let mut m = manager();
        m.apply(&[rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &format!("127.0.0.1:{dead}"),
            true,
        )])
        .await;
        assert_eq!(m.listening(), 1);
        let st = m.status();
        assert_eq!(st[0].state, "error");
        // Windows はループバックの拒否にも SYN を送り直すので、2 秒の期限に届くことがある
        #[cfg(not(windows))]
        assert_eq!(
            st[0].reason,
            format!("tcp/{port}: dial tcp 127.0.0.1:{dead}: connect: connection refused")
        );
        // 宛先が戻れば、次の見回りで誤りが消える
        let up = TcpListener::bind(("127.0.0.1", dead)).await.unwrap();
        m.retry().await;
        assert_eq!(m.status()[0].state, "ok");
        drop(up);
    }
}
