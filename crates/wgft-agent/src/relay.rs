//! ルールの中継 (試作は TCP だけ)。
//!
//! ルールのポートごとに、トンネルのアドレスに bind したカーネルの TCP のソケットで待ち受け、受けた接続を
//! ルールの宛先へ中継する。server はトンネルの中で agent のアドレスとルールのポートへ接続する。

use crate::logf;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use wgft_proto::{AgentRule, Proto, RuleStatus, STATUS_ERROR, STATUS_OK};

/// 宛先への接続の期限。
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct Listener {
    rule: AgentRule,
    port: u16,
    task: Option<JoinHandle<()>>,
    err: Option<String>,
}

impl Listener {
    fn key(&self) -> String {
        format!("{}/{}", self.rule.proto.as_str(), self.port)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// 中継の全体。トンネルと一緒に作り、一緒に閉じる。
#[derive(Debug)]
pub struct Manager {
    addr: Ipv4Addr,
    listeners: BTreeMap<(String, u16), Listener>,
    unsupported: BTreeMap<String, String>,
}

impl Manager {
    /// トンネルのアドレス `addr` で待ち受ける中継を作る。
    #[must_use]
    pub fn new(addr: Ipv4Addr) -> Self {
        Manager {
            addr,
            listeners: BTreeMap::new(),
            unsupported: BTreeMap::new(),
        }
    }

    /// 宣言に合わせる。変わったリスナーだけを開閉する。開けなかったリスナーは状態の誤りに出し、
    /// [`Manager::retry`] が開き直す。戻り値は操作の数。
    pub fn apply(&mut self, rules: &[AgentRule]) -> usize {
        let mut want: BTreeMap<(String, u16), AgentRule> = BTreeMap::new();
        self.unsupported.clear();
        for r in rules.iter().filter(|r| r.enabled) {
            match r.proto {
                Proto::Tcp => {
                    for p in r.listen_port.ports() {
                        want.insert((r.id.clone(), p), r.clone());
                    }
                }
                Proto::Udp => {
                    self.unsupported.insert(
                        r.id.clone(),
                        "udp rules are not supported by this prototype yet".into(),
                    );
                }
                Proto::Other(ref s) => {
                    self.unsupported
                        .insert(r.id.clone(), format!("unknown protocol {s:?}"));
                }
            }
        }
        let mut actions = 0;
        let stale: Vec<_> = self
            .listeners
            .iter()
            .filter(|(k, l)| want.get(*k) != Some(&l.rule))
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.listeners.remove(&k);
            actions += 1;
        }
        for (k, rule) in want {
            if self.listeners.contains_key(&k) {
                continue;
            }
            let mut l = Listener {
                rule,
                port: k.1,
                task: None,
                err: None,
            };
            self.open(&mut l);
            self.listeners.insert(k, l);
            actions += 1;
        }
        actions
    }

    /// 開けなかったリスナーを開き直す。
    pub fn retry(&mut self) {
        let addr = self.addr;
        for l in self.listeners.values_mut().filter(|l| l.task.is_none()) {
            open_listener(addr, l);
        }
    }

    fn open(&self, l: &mut Listener) {
        open_listener(self.addr, l);
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
            let r = by.entry(l.rule.id.clone()).or_insert_with(|| RuleStatus {
                id: l.rule.id.clone(),
                state: STATUS_OK.into(),
                reason: String::new(),
            });
            if let Some(e) = &l.err
                && r.state == STATUS_OK
            {
                r.state = STATUS_ERROR.into();
                r.reason = format!("{}: {e}", l.key());
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

fn open_listener(addr: Ipv4Addr, l: &mut Listener) {
    let bind = SocketAddrV4::new(addr, l.port);
    let std_listener = match bind_listener(bind) {
        Ok(s) => s,
        Err(e) => {
            l.err = Some(format!("listen {bind}: {e}"));
            return;
        }
    };
    let listener = match TcpListener::from_std(std_listener) {
        Ok(s) => s,
        Err(e) => {
            l.err = Some(format!("listen {bind}: {e}"));
            return;
        }
    };
    l.err = None;
    let rule = l.rule.clone();
    let port = l.port;
    l.task = Some(tokio::spawn(accept_loop(listener, rule, port)));
}

fn bind_listener(bind: SocketAddrV4) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&bind.into())?;
    s.listen(1024)?;
    Ok(s.into())
}

async fn accept_loop(listener: TcpListener, rule: AgentRule, port: u16) {
    loop {
        let (conn, from) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                logf!("relay: tcp/{port}: accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some((host, tport)) = rule.effective_target(port) else {
            logf!("relay: tcp/{port}: rule {} has no usable target", rule.id);
            continue;
        };
        tokio::spawn(async move {
            let dial =
                tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect((host.as_str(), tport)))
                    .await;
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
            let mut down = conn;
            let _ = up.set_nodelay(true);
            let _ = down.set_nodelay(true);
            let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn rule(id: &str, proto: Proto, port: &str, target: &str) -> AgentRule {
        AgentRule {
            id: id.into(),
            proto,
            listen_port: port.parse().unwrap(),
            target: target.into(),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn relays_a_tcp_connection_on_loopback() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = vec![0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let mut m = Manager::new(Ipv4Addr::LOCALHOST);
        let rules = [rule(
            "r_a",
            Proto::Tcp,
            &port.to_string(),
            &target.to_string(),
        )];
        assert_eq!(m.apply(&rules), 1);
        assert_eq!(m.listening(), 1);
        assert_eq!(m.apply(&rules), 0);
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut got = vec![0u8; 5];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        assert_eq!(
            m.status(),
            vec![RuleStatus {
                id: "r_a".into(),
                state: "ok".into(),
                reason: String::new()
            }]
        );
        assert_eq!(m.apply(&[]), 1);
        assert_eq!(m.listening(), 0);
    }

    #[tokio::test]
    async fn reports_unsupported_and_failed_listeners() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let mut m = Manager::new(Ipv4Addr::LOCALHOST);
        m.apply(&[
            rule("r_u", Proto::Udp, "27015", "192.0.2.1:27015"),
            rule("r_t", Proto::Tcp, &port.to_string(), "192.0.2.1:1"),
        ]);
        let st = m.status();
        assert_eq!(st.len(), 2);
        assert!(st.iter().all(|s| s.state == "error"), "{st:?}");
        assert!(
            st[0].reason.starts_with(&format!("tcp/{port}: listen")),
            "{st:?}"
        );
        drop(taken);
        m.retry();
        assert_eq!(m.listening(), 1);
    }
}
