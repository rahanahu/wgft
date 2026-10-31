//! ルールの中継 (試作は TCP だけ)。
//!
//! ルールのポートごとに、トンネルのアドレスに bind し、TUN の device に結び付けたカーネルの TCP の
//! ソケットで待ち受け、受けた接続をルールの宛先へ中継する。server はトンネルの中で agent のアドレスと
//! ルールのポートへ接続する。server のトンネルのアドレス以外からの接続は捨てる。
//!
//! リスナーはポートで区別し、そのリスナーの中継の接続をすべて持つ。ルールが消えるか、無効になるか、
//! 実効宛先が変わると、リスナーを閉じ、持っている接続をトンネルの側に RST を送って切る。

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use socket2::SockRef;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use wgft_proto::{AgentRule, Proto, RuleStatus, STATUS_ERROR, STATUS_OK};

use crate::logf;

/// 宛先への接続の期限。
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// 待ち受けている TCP のポートの集まり。トンネルの入口の検査 (`tunnel`) が読む。
pub type OpenPorts = Arc<RwLock<BTreeSet<u16>>>;

#[derive(Debug)]
struct Listener {
    rule_id: String,
    port: u16,
    target: (String, u16),
    task: Option<JoinHandle<()>>,
    err: Option<String>,
}

impl Listener {
    /// 受け付けのタスクを止めて、待ち受けのソケットとすべての中継の接続が閉じるまで待つ。
    async fn close(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
            let _ = t.await;
        }
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
/// ポートの数を超えない。v1 もルールの範囲の幅に上限を置かない。
#[derive(Debug)]
pub struct Manager {
    addr: Ipv4Addr,
    server: Ipv4Addr,
    device: Option<String>,
    listeners: BTreeMap<u16, Listener>,
    unsupported: BTreeMap<String, String>,
    open: OpenPorts,
}

impl Manager {
    /// トンネルのアドレス `addr` で待ち受け、`server` からの接続だけを受ける中継を作る。`device` が
    /// あれば、待ち受けのソケットをその interface に結び付ける (Linux の `SO_BINDTODEVICE`)。待ち受けて
    /// いるポートは `open` に書き、トンネルの入口の検査と分け合う。
    #[must_use]
    pub fn new(addr: Ipv4Addr, server: Ipv4Addr, device: Option<String>, open: OpenPorts) -> Self {
        Manager {
            addr,
            server,
            device,
            listeners: BTreeMap::new(),
            unsupported: BTreeMap::new(),
            open,
        }
    }

    /// 待ち受けている TCP のポートの集まり。
    #[must_use]
    pub fn open_ports(&self) -> OpenPorts {
        Arc::clone(&self.open)
    }

    /// 宣言に合わせる。ポートごとに実効宛先を比べ、変わったリスナーだけを閉じてから開き直す。
    /// 実効宛先が同じならルールの ID だけを置き換える。開けなかったリスナーは状態の誤りに出し、
    /// [`Manager::retry`] が開き直す。戻り値は操作の数。
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
        for p in stale {
            if let Some(mut l) = self.listeners.remove(&p) {
                l.close().await;
            }
            actions += 1;
        }
        for (p, (id, target)) in want {
            if let Some(l) = self.listeners.get_mut(&p) {
                l.rule_id = id;
                continue;
            }
            let mut l = Listener {
                rule_id: id,
                port: p,
                target,
                task: None,
                err: None,
            };
            self.open_listener(&mut l);
            self.listeners.insert(p, l);
            actions += 1;
        }
        self.publish();
        actions
    }

    /// 開けなかったリスナーを開き直す。
    pub fn retry(&mut self) {
        let mut ls = std::mem::take(&mut self.listeners);
        for l in ls.values_mut().filter(|l| l.task.is_none()) {
            self.open_listener(l);
        }
        self.listeners = ls;
        self.publish();
    }

    /// すべてのリスナーと中継の接続を閉じる。
    pub async fn close(&mut self) {
        for (_, mut l) in std::mem::take(&mut self.listeners) {
            l.close().await;
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
        *self
            .open
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ports;
    }

    fn open_listener(&self, l: &mut Listener) {
        let bind = SocketAddrV4::new(self.addr, l.port);
        match bind_listener(bind, self.device.as_deref()) {
            Ok(listener) => {
                l.err = None;
                let (host, port) = l.target.clone();
                l.task = Some(tokio::spawn(accept_loop(
                    listener,
                    self.server,
                    l.port,
                    host,
                    port,
                )));
            }
            Err(e) => l.err = Some(format!("bind tcp {bind}: {e}")),
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
            if let Some(e) = &l.err
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

/// 中継の接続のトンネルの側。正常に終わらずに捨てられたとき (リスナーを閉じたとき) は、
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

async fn accept_loop(listener: TcpListener, server: Ipv4Addr, port: u16, host: String, tport: u16) {
    // 中継の接続はこのタスクが持つ。タスクを止めると JoinSet が捨てられ、どの接続も止まる
    let mut flows = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (conn, from) = match accepted {
                    Ok(c) => c,
                    Err(e) => {
                        logf!("relay: tcp/{port}: accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let down = TunnelSide { stream: conn, finished: false };
                if !matches!(from, SocketAddr::V4(a) if *a.ip() == server) {
                    logf!("relay: tcp/{port}: refused a connection from {from}, which is not the server's tunnel address");
                    drop(down);
                    continue;
                }
                flows.spawn(relay_one(down, from, port, host.clone(), tport));
            }
            Some(_) = flows.join_next(), if !flows.is_empty() => {}
        }
    }
}

async fn relay_one(mut down: TunnelSide, from: SocketAddr, port: u16, host: String, tport: u16) {
    let dial = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect((host.as_str(), tport))).await;
    let mut up = match dial {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            logf!("relay: tcp/{port}: from {from}: dial {host}:{tport}: {e}");
            return;
        }
        Err(_) => {
            logf!("relay: tcp/{port}: from {from}: dial {host}:{tport}: timed out");
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

    fn manager() -> Manager {
        Manager::new(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            None,
            OpenPorts::default(),
        )
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
    async fn refuses_peers_other_than_the_server() {
        let target = echo().await;
        let port = free_port();
        // server のアドレスを 127.0.0.2 にすると、127.0.0.1 からの接続は捨てられる
        let mut m = Manager::new(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 0, 0, 2),
            None,
            OpenPorts::default(),
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
        let mut m = manager();
        m.apply(&[
            rule("r_u", Proto::Udp, "27015", "192.0.2.1:27015", true),
            rule("r_t", Proto::Tcp, &port.to_string(), "192.0.2.1:1", true),
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
        m.retry();
        assert_eq!(m.listening(), 1);
    }
}
