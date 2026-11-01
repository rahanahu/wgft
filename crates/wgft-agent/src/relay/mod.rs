//! ルールの中継。
//!
//! ルールのプロトコルとポートごとに、Rust の wgstack の核でトンネルのアドレスに待ち受け、受けた接続と
//! datagram をルールの宛先へ中継する。待ち受けと中継の接続は、データプレーンのスレッドの local の task として動き、
//! `wgft_netstack` の handle で核を呼ぶ。LAN の側はカーネルの TCP ソケットで、同じスレッドの tokio の
//! 実行環境の上で読み書きする。[`Manager`] は制御プレーンにあり、待ち受けの開閉をデータプレーンに頼む。
//! 核に届く packet の送信元は、WireGuard の device の層の AllowedIPs が server の /32 に限るので、待ち受け
//! は送信元で絞らない。
//!
//! リスナーはプロトコルとポートで区別し、そのリスナーの中継の接続と UDP のセッションをすべて持つ。ルールが消えるか、無効になるか、
//! 実効宛先が変わると、リスナーを閉じ、持っている接続をトンネルの側に RST を送って切る。
//!
//! 新しい接続は、フロー数の予算 ([`crate::flowpool`]) から枠を取ってから宛先へ接続する。宛先の許可一覧、
//! ブロードキャストとマルチキャストの拒否、名前の解決、接続の試し方、試し接続は [`crate::targets`] が
//! 持つ。中継が終わった後は、Go の agent と同じく、両側が送り残しを届け終えるまで枠を持つ。UDP の
//! 中継は [`udp`] にあり、送信元ごとのセッションを無通信の期限で閉じる。

#[cfg(test)]
mod held_tests;
mod lansock;
mod pipe;
mod replies;
#[cfg(test)]
pub(crate) mod testpeer;
#[cfg(test)]
mod tests;
mod udp;
#[cfg(test)]
mod udp_tests;

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use wgft_netstack::{Closing, LanSockets, TcpListener, TcpStream};
use wgft_proto::{AgentRule, Proto, RuleStatus, STATUS_ERROR, STATUS_OK};

use crate::dataplane::Handle;
use crate::flowpool::{self, Denied, Limits, Pool};
use crate::logf;
use crate::targets::{TargetError, Targets};
use crate::tunnel::{Net, Stack};

pub(crate) use lansock::LanConn;
pub(crate) use pipe::{BULK_BUF, BULK_KEEP};
pub(crate) use replies::{REPLY_SLOTS, UDP_BUF};
#[cfg(test)]
pub(crate) use udp::DEFAULT_UDP_IDLE;
pub(crate) use udp::udp_idle_timeout;

/// How often a finished relay checks first whether both sides delivered what they sent (Go's
/// `deliveryPollMin`). The interval doubles up to [`DELIVERY_POLL_MAX`].
pub(crate) const DELIVERY_POLL_MIN: Duration = Duration::from_millis(50);

/// The longest interval between two delivery checks (Go's `deliveryPollMax`).
pub(crate) const DELIVERY_POLL_MAX: Duration = Duration::from_secs(2);

/// A listener's protocol. TCP sorts before UDP, as Go's `Key.String` names do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Kind {
    /// A TCP listener.
    Tcp,
    /// A UDP listener.
    Udp,
}

impl Kind {
    /// `tcp` or `udp`, the protocol word of Go's `proto.Proto`.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::Tcp => "tcp",
            Kind::Udp => "udp",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A listener's protocol and port (Go's `relay.Key`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Key {
    /// The protocol.
    pub kind: Kind,
    /// The port on the tunnel address.
    pub port: u16,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.port)
    }
}

/// 試し接続の 1 周。[`Manager`] を借りずに走らせる。
#[derive(Debug)]
pub(crate) struct ProbeRound {
    targets: Arc<Targets>,
    entries: Vec<ProbeEntry>,
}

#[derive(Debug)]
struct ProbeEntry {
    key: Key,
    target: (String, u16),
    /// 試したときのリスナー。結果を書くときに、同じリスナーかを確かめる。
    shared: Arc<Shared>,
}

/// 試し接続の 1 周の結果。
#[derive(Debug)]
pub(crate) struct ProbeResults {
    entries: Vec<ProbeEntry>,
    results: Vec<Result<(), TargetError>>,
}

impl ProbeRound {
    /// 試す宛先が無いか。
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 試し接続を走らせる。同時に 32 件まで、1 件 2 秒。
    pub(crate) async fn run(self) -> ProbeResults {
        let list = self.entries.iter().map(|e| e.target.clone()).collect();
        let results = self.targets.probe_all(list).await;
        ProbeResults {
            entries: self.entries,
            results,
        }
    }
}

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
    /// 中継が持っている接続の数。トンネルの側と宛先の側を 1 本ずつ数える (Go の `Status.Sessions`)。
    sessions: AtomicUsize,
    /// 宛先への書き込みの失敗で閉じた UDP のセッションの数。試験だけが読む。
    #[cfg(test)]
    write_closes: AtomicUsize,
}

/// 中継の接続 1 本が終わるまで持つもの。落とすと、予算の枠とトンネルの側の接続の数えが同時に戻る。
struct Held {
    _lease: flowpool::Lease,
    _session: Session,
}

/// 中継が持つ接続 1 本の数え。作ると数に足し、落とすと引く。接続を持つタスクが止められても、タスクと
/// 一緒に落ちて数が戻る。
struct Session(Arc<Shared>);

impl Session {
    fn new(shared: &Arc<Shared>) -> Session {
        shared.sessions.fetch_add(1, Ordering::Relaxed);
        Session(Arc::clone(shared))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.0.sessions.fetch_sub(1, Ordering::Relaxed);
    }
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

/// データプレーンのスレッドで動く受け付けの task。
#[derive(Debug)]
struct Running {
    /// 受け付けの task に止めるよう知らせる口。送り手が落ちても止まる。
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

#[derive(Debug)]
struct Listener {
    rule_id: String,
    key: Key,
    target: (String, u16),
    /// 待ち受けを開けていれば、その受け付けの task。
    task: Option<Running>,
    /// 待ち受けを開けなかった理由。bind の失敗か、IP リテラルの宛先の拒否。[`Manager::retry`] が
    /// 開き直す。
    bind_err: Option<String>,
    /// フロー数の予算の枠。bind できるまで受け付けない。
    budget: Arc<flowpool::Listener>,
    shared: Arc<Shared>,
}

impl Listener {
    /// 受け付けの task に止めるよう知らせる。task は知らせを受けると中継の接続の task を止め、それらが
    /// 終わるまで待ってから待ち受けを閉じて終わる。止めた中継の接続は、トンネルの側に RST を送って閉じる。
    fn stop(&mut self) -> Option<JoinHandle<()>> {
        let Running { stop, task } = self.task.take()?;
        let _ = stop.send(());
        Some(task)
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
        if let Some(Running { task, .. }) = self.task.take() {
            task.abort();
        }
    }
}

/// リスナー 1 つの状態 (Go の `relay.Status`)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ListenerStat {
    /// 属するルールの ID。
    pub rule_id: String,
    /// 待ち受けのプロトコルとポート。名前は [`ListenerStat::key`]。
    pub key: Key,
    /// 待ち受けを開けているか。偽なら `err` は開けなかった理由 (bind の失敗か、IP リテラルの宛先の
    /// 拒否) で、真で `err` があれば待ち受けは開いていて宛先に届かない。
    pub listening: bool,
    /// 開けなかった理由か、開いている待ち受けの宛先の誤り。開けなかった理由が先。
    pub err: Option<String>,
    /// 中継が持っている接続の数。TCP はトンネルの側と宛先の側の両方を数えるので、フロー数の上限の対象
    /// とは一致しない。UDP はセッションの数である。
    pub sessions: usize,
    /// この待ち受けがフロー数の予算から取っている枠の数。上限の判定の対象の数である。
    pub flows: usize,
}

impl ListenerStat {
    /// `tcp/<port>` か `udp/<port>` の形の名前 (Go の `Key.String`)。
    #[cfg(test)]
    pub(crate) fn name(&self) -> String {
        self.key.to_string()
    }
}

/// Go の `Key.String` の文字列の順。プロトコルの語の順 (`tcp` が先) で、プロトコルが同じなら、ポートの
/// 10 進の文字列の順である。文字列を作らずに比べる。
fn go_key_order(a: Key, b: Key) -> std::cmp::Ordering {
    a.kind
        .cmp(&b.kind)
        .then_with(|| go_port_order(a.port, b.port))
}

fn go_port_order(a: u16, b: u16) -> std::cmp::Ordering {
    fn decimal(mut n: u16, buf: &mut [u8; 5]) -> &[u8] {
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + u8::try_from(n % 10).unwrap_or(0);
            n /= 10;
            if n == 0 {
                return &buf[i..];
            }
        }
    }
    let (mut x, mut y) = ([0u8; 5], [0u8; 5]);
    decimal(a, &mut x).cmp(decimal(b, &mut y))
}

/// 中継の全体。トンネルと一緒に作り、一緒に閉じる。リスナーはプロトコルとポートで区別するので、数は
/// TCP と UDP のポートの数を超えない。v1 もルールの範囲の幅に上限を置かない。フロー数の予算もトンネルごとに作るので、
/// 拒否の数はトンネルを作り直すと 0 に戻る。
#[derive(Debug)]
pub(crate) struct Manager {
    addr: Ipv4Addr,
    dataplane: Handle<Stack>,
    listeners: BTreeMap<Key, Listener>,
    unsupported: BTreeMap<String, String>,
    targets: Arc<Targets>,
    tcp: Pool,
    udp: Pool,
    /// UDP のセッションを閉じる無通信の期限。
    udp_idle: Duration,
    /// UDP の応答のバッファの枠。製品はプロセスで 1 つの [`replies::REPLIES`] を使う。
    replies: &'static replies::Replies,
}

impl Manager {
    /// トンネルのアドレス `addr` で待ち受ける中継を作る。待ち受けと中継の接続は `dataplane` のスレッドで
    /// 動く。宛先の規則は `targets`、フロー数の上限は `limits` に従う。UDP のセッションは `udp_idle` の
    /// 間どちらの向きにも datagram が無ければ閉じる ([`udp_idle_timeout`] が全体状態の値から作る)。
    #[must_use]
    pub(crate) fn new(
        addr: Ipv4Addr,
        dataplane: Handle<Stack>,
        targets: Arc<Targets>,
        limits: Limits,
        udp_idle: Duration,
    ) -> Self {
        Manager {
            addr,
            dataplane,
            listeners: BTreeMap::new(),
            unsupported: BTreeMap::new(),
            targets,
            tcp: Pool::new(limits.tcp),
            udp: Pool::new(limits.udp),
            udp_idle,
            replies: &replies::REPLIES,
        }
    }

    /// 宛先への書き込みの失敗で閉じた UDP のセッションの数。
    #[cfg(test)]
    pub(crate) fn write_closes(&self) -> usize {
        self.listeners
            .values()
            .map(|l| l.shared.write_closes.load(Ordering::Relaxed))
            .sum()
    }

    /// 応答のバッファの枠を替える。試験が小さい枠を渡す。
    #[cfg(test)]
    pub(crate) fn with_replies(mut self, replies: &'static replies::Replies) -> Self {
        self.replies = replies;
        self
    }

    /// TCP のフロー数の予算。
    #[must_use]
    pub(crate) fn tcp_pool(&self) -> &Pool {
        &self.tcp
    }

    /// UDP のフロー数の予算。
    #[must_use]
    pub(crate) fn udp_pool(&self) -> &Pool {
        &self.udp
    }

    /// 宣言に合わせる。ポートごとに実効宛先を比べ、変わったリスナーだけを閉じてから開き直す。
    /// 実効宛先が同じならルールの ID だけを置き換える。開けなかったリスナーは状態の誤りに出し、
    /// [`Manager::retry`] が開き直す。開いたリスナーの宛先へ試し接続し、その結果を待ってから戻るので、
    /// 最初の状態は適用の直後のハートビートに載る。戻り値は操作の数。
    pub(crate) async fn apply(&mut self, rules: &[AgentRule]) -> usize {
        let mut want: BTreeMap<Key, (String, (String, u16))> = BTreeMap::new();
        self.unsupported.clear();
        for r in rules.iter().filter(|r| r.enabled) {
            let kind = match &r.proto {
                Proto::Tcp => Kind::Tcp,
                Proto::Udp => Kind::Udp,
                Proto::Other(s) => {
                    self.unsupported
                        .insert(r.id.clone(), format!("unknown protocol {s:?}"));
                    continue;
                }
            };
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
                        "{kind}/{}: target {:?} is not a usable host:port",
                        r.listen_port, r.target
                    ),
                );
                continue;
            };
            for (port, t) in targets {
                want.insert(Key { kind, port }, (r.id.clone(), t));
            }
        }
        let mut actions = 0;
        let stale: Vec<Key> = self
            .listeners
            .iter()
            .filter(|(k, l)| want.get(k).is_none_or(|(_, t)| *t != l.target))
            .map(|(k, _)| *k)
            .collect();
        actions += stale.len();
        let closing = stale
            .into_iter()
            .filter_map(|k| self.listeners.remove(&k).map(|l| (k, l)))
            .collect();
        close_all(closing).await;
        let mut opened = Vec::new();
        for (k, (id, target)) in want {
            if let Some(l) = self.listeners.get_mut(&k) {
                l.budget.set_rule(&id);
                l.rule_id = id;
                continue;
            }
            let pool = match k.kind {
                Kind::Tcp => &self.tcp,
                Kind::Udp => &self.udp,
            };
            let budget = Arc::new(pool.pending_listener(&id));
            let l = Listener {
                rule_id: id,
                key: k,
                target,
                task: None,
                bind_err: None,
                budget,
                shared: Arc::default(),
            };
            self.listeners.insert(k, l);
            opened.push(k);
            actions += 1;
        }
        self.open_listeners(&opened).await;
        let done = self.probe_round(&opened).run().await;
        self.finish_probes(done);
        actions
    }

    /// 30 秒ごとの見回り。開けなかったリスナーを開き直し、開いている TCP のリスナーの宛先へ試し接続する。
    /// UDP は到達を確かめる手段が無いので試さない (Go と同じ)。
    /// 宛先が戻れば誤りが消え、落ちれば付く。状態の変化はハートビートで報告される。
    #[cfg(test)]
    pub(crate) async fn retry(&mut self) {
        let round = self.retry_round().await;
        let done = round.run().await;
        self.finish_probes(done);
    }

    /// 見回りのうち排他を要る前半。開けなかったリスナーを開き直し、試し接続の 1 周を返す。呼び手は
    /// agent の排他を放してから [`ProbeRound::run`] を走らせ、結果を [`Manager::finish_probes`] で書く。
    /// 試し接続の 1 周は宛先の数と応えない宛先で長くなるので、その間ハートビートと適用を止めないため。
    pub(crate) async fn retry_round(&mut self) -> ProbeRound {
        let closed: Vec<Key> = self
            .listeners
            .values()
            .filter(|l| l.task.is_none())
            .map(|l| l.key)
            .collect();
        self.open_listeners(&closed).await;
        let keys: Vec<Key> = self.listeners.keys().copied().collect();
        self.probe_round(&keys)
    }

    /// 開いている TCP のリスナーのうち `keys` の宛先への試し接続の 1 周。
    fn probe_round(&self, keys: &[Key]) -> ProbeRound {
        let entries = keys
            .iter()
            .filter(|k| k.kind == Kind::Tcp)
            .filter_map(|k| self.listeners.get(k))
            .filter(|l| l.task.is_some())
            .map(|l| ProbeEntry {
                key: l.key,
                target: l.target.clone(),
                shared: Arc::clone(&l.shared),
            })
            .collect();
        ProbeRound {
            targets: Arc::clone(&self.targets),
            entries,
        }
    }

    /// 試し接続の結果を書く。走らせている間にリスナーが閉じたか、開き直されたか、宛先が変わった場合は、
    /// その結果を捨てる (Go の `applyProbes` と同じ)。到達性が変わったリスナーだけ、ログを 1 行出す。
    pub(crate) fn finish_probes(&self, done: ProbeResults) {
        for (e, r) in done.entries.into_iter().zip(done.results) {
            let Some(l) = self.listeners.get(&e.key) else {
                continue;
            };
            if !Arc::ptr_eq(&l.shared, &e.shared) || l.target != e.target || l.task.is_none() {
                continue;
            }
            let target = crate::targets::join_host_port(&l.target.0, l.target.1);
            let now = r.err();
            let before = l.shared.set_probe(now.clone());
            match (before, now) {
                (None, Some(e)) => {
                    logf!("listener {}: cannot connect to target {target}: {e}", l.key);
                }
                (Some(_), None) => {
                    logf!("listener {}: target {target} is reachable again", l.key);
                }
                _ => {}
            }
        }
    }

    /// すべてのリスナーと中継の接続を閉じる。
    pub(crate) async fn close(&mut self) {
        close_all(std::mem::take(&mut self.listeners).into_iter().collect()).await;
    }

    /// `keys` のリスナーの待ち受けを開いて中継を始める。IP リテラルの宛先が拒まれれば開かない。開くのは
    /// データプレーンのスレッドへの 1 回の頼みでまとめて行い、範囲の広いルールでも往復は 1 回である。
    /// 待ち受けを開けてから予算の枠を受け付けにする。逆の順にすると、開けなかった待ち受けのルールが
    /// 予算のルールの数に入り、その間だけ他のルールの最低分が減る。
    async fn open_listeners(&mut self, keys: &[Key]) {
        let mut specs = Vec::new();
        for k in keys {
            let Some(l) = self.listeners.get_mut(k) else {
                continue;
            };
            let (host, tport) = l.target.clone();
            if let Some(e) = self.targets.refuse_literal(&host, tport) {
                logf!("listener {}: {e}", l.key);
                l.bind_err = Some(e.text);
                continue;
            }
            specs.push(Spec {
                key: l.key,
                addr: SocketAddrV4::new(self.addr, l.key.port),
                host,
                tport,
                budget: Arc::clone(&l.budget),
                shared: Arc::clone(&l.shared),
                targets: Arc::clone(&self.targets),
                udp_idle: self.udp_idle,
                replies: self.replies,
            });
        }
        if specs.is_empty() {
            return;
        }
        let opened: Vec<(Key, SocketAddrV4)> = specs.iter().map(|s| (s.key, s.addr)).collect();
        let results = match self
            .dataplane
            .call(move |net| specs.into_iter().map(|s| start(net, s)).collect())
            .await
        {
            Ok(r) => r,
            Err(e) => opened
                .iter()
                .map(|(k, a)| Err(format!("bind {} {a}: {e}", k.kind)))
                .collect::<Vec<_>>(),
        };
        for ((key, _), r) in opened.into_iter().zip(results) {
            let Some(l) = self.listeners.get_mut(&key) else {
                continue;
            };
            match r {
                Ok(running) => {
                    l.bind_err = None;
                    l.task = Some(running);
                    logf!(
                        "listener {} -> {} opened; rule {}",
                        l.key,
                        crate::targets::join_host_port(&l.target.0, l.target.1),
                        l.rule_id
                    );
                }
                Err(e) => {
                    logf!("listener {}: {e}", l.key);
                    l.bind_err = Some(e);
                }
            }
        }
    }

    /// 待ち受けているリスナーの数。
    #[must_use]
    pub(crate) fn listening(&self) -> usize {
        self.listeners.values().filter(|l| l.task.is_some()).count()
    }

    /// リスナーごとの状態。並びは Go の `Manager.Status` と同じく名前 (`tcp/<port>`、`udp/<port>`) の
    /// 文字列の順で、
    /// ルールの状態の理由と `agent doctor` の最初の誤りは、この順で最初のリスナーから取る。接続の数と
    /// 予算の枠の数も読む。枠の数は予算の排他を 1 回取って読む。
    #[must_use]
    pub(crate) fn listener_stats(&self) -> Vec<ListenerStat> {
        self.stats(true)
    }

    /// `counts` が偽なら、接続の数と予算の枠の数を読まずに 0 にする。ハートビートのルールの状態は
    /// それらを使わないので、30 秒ごとに予算の排他を取らない。
    fn stats(&self, counts: bool) -> Vec<ListenerStat> {
        let mut ls: Vec<&Listener> = self.listeners.values().collect();
        ls.sort_unstable_by(|a, b| go_key_order(a.key, b.key));
        let flows = if counts {
            // TCP が先に並ぶので、2 つの予算の読みをその順に繋ぐ
            let mut f = self.tcp.flows_of(
                ls.iter()
                    .filter(|l| l.key.kind == Kind::Tcp)
                    .map(|l| &*l.budget),
            );
            f.extend(
                self.udp.flows_of(
                    ls.iter()
                        .filter(|l| l.key.kind == Kind::Udp)
                        .map(|l| &*l.budget),
                ),
            );
            f
        } else {
            vec![0; ls.len()]
        };
        ls.into_iter()
            .zip(flows)
            .map(|(l, flows)| ListenerStat {
                rule_id: l.rule_id.clone(),
                key: l.key,
                listening: l.task.is_some(),
                err: l.err(),
                sessions: if counts {
                    l.shared.sessions.load(Ordering::Relaxed)
                } else {
                    0
                },
                flows,
            })
            .collect()
    }

    /// ルールごとの状態。1 つでも誤りのリスナーがあればそのルールは `error`。
    #[must_use]
    pub(crate) fn status(&self) -> Vec<RuleStatus> {
        self.status_of(&self.stats(false))
    }

    /// [`Manager::listener_stats`] の 1 回の読みからルールごとの状態を作る。ハートビートと
    /// `agent doctor` が同じ判定を使う (Go の `usermode.RuleStatuses`)。理由はリスナーの並びで最初の
    /// 誤りから取る。
    #[must_use]
    pub(crate) fn status_of(&self, stats: &[ListenerStat]) -> Vec<RuleStatus> {
        let mut by: BTreeMap<String, RuleStatus> = BTreeMap::new();
        for l in stats {
            // 範囲のルールはリスナーが多いので、ルールの ID を写すのは初めて見たときだけにする
            if !by.contains_key(&l.rule_id) {
                by.insert(
                    l.rule_id.clone(),
                    RuleStatus {
                        id: l.rule_id.clone(),
                        state: STATUS_OK.into(),
                        reason: String::new(),
                    },
                );
            }
            let Some(r) = by.get_mut(&l.rule_id) else {
                continue;
            };
            if let Some(e) = &l.err
                && r.state == STATUS_OK
            {
                r.state = STATUS_ERROR.into();
                r.reason = format!("{}: {e}", l.key);
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

/// リスナーを閉じる。先にすべてに止める知らせを送り、それから終わりを待つ。範囲の広いルールでも、
/// データプレーンのスレッドとの往復を待ち受けの数だけ重ねないためである。
async fn close_all(mut ls: Vec<(Key, Listener)>) {
    let tasks: Vec<_> = ls.iter_mut().map(|(_, l)| l.stop()).collect();
    for ((k, l), t) in ls.iter().zip(tasks) {
        if let Some(t) = t {
            let _ = t.await;
        }
        l.budget.close();
        logf!("listener {k} closed");
    }
}

/// データプレーンのスレッドで待ち受けを開くための材料。
struct Spec {
    key: Key,
    addr: SocketAddrV4,
    host: String,
    tport: u16,
    budget: Arc<flowpool::Listener>,
    shared: Arc<Shared>,
    targets: Arc<Targets>,
    /// UDP のセッションの無通信の期限。TCP では使わない。
    udp_idle: Duration,
    /// UDP の応答のバッファの枠。TCP では使わない。
    replies: &'static replies::Replies,
}

/// データプレーンのスレッドの上で、核に待ち受けを開き、受け付けの task を立てる。
fn start(net: &Net, s: Spec) -> Result<Running, String> {
    match s.key.kind {
        Kind::Tcp => start_tcp(net, s),
        Kind::Udp => udp::start(net, s),
    }
}

/// TCP の待ち受けを開く。予算の枠は開けてから受け付けにする。task が最初の接続を取る前なので、開いた
/// 直後の接続も枠を取れる。
fn start_tcp(net: &Net, s: Spec) -> Result<Running, String> {
    let listener =
        TcpListener::bind(net, s.addr).map_err(|e| format!("bind tcp {}: {e}", s.addr))?;
    s.budget.accept();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::task::spawn_local(accept_loop(Accepting {
        listener,
        stopped,
        budget: s.budget,
        flow: Flow {
            lan: crate::dataplane::stack::lan_sockets(net),
            port: s.addr.port(),
            host: s.host,
            tport: s.tport,
            shared: s.shared,
            targets: s.targets,
        },
    }));
    Ok(Running { stop, task })
}

/// 受け付けの task が持つもの。
struct Accepting {
    listener: TcpListener<Net>,
    /// 止める知らせ。送り手が落ちた場合も止める。
    stopped: oneshot::Receiver<()>,
    budget: Arc<flowpool::Listener>,
    flow: Flow,
}

/// 中継の接続 1 本が待ち受けから受け継ぐもの。
#[derive(Clone)]
struct Flow {
    /// 核の boost の hook が引く LAN の側のソケットの表。
    lan: Rc<LanSockets<LanConn>>,
    port: u16,
    host: String,
    tport: u16,
    shared: Arc<Shared>,
    targets: Arc<Targets>,
}

async fn accept_loop(mut a: Accepting) {
    let port = a.flow.port;
    // 中継の接続はこの task が持つ。止める知らせでは接続の task を止めて終わりを待つ。止めた接続の
    // トンネルの側は handle の Drop が RST で切る。task が外から abort された場合は JoinSet が捨てられ、
    // どの接続も同じく切られる
    let mut flows = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut a.stopped => {
                flows.shutdown().await;
                return;
            }
            accepted = a.listener.accept() => {
                let (conn, _from) = match accepted {
                    Ok(c) => c,
                    Err(e) => {
                        // 世代の終わり (核の中の panic) の後は、スレッドとともにこの task も落ちる
                        logf!("relay: tcp/{port}: accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // フロー数の上限。拒んだ接続は握手の後、データを送る前に RST で閉じる。既存の接続は
                // 追い出さない
                let lease = match a.budget.take() {
                    Ok(x) => x,
                    Err(Denied::NotAccepting) => {
                        // 閉じる途中の待ち受け。予算の拒否ではないので、数にもログにも入れない
                        conn.abort();
                        continue;
                    }
                    Err(Denied::Refused(r)) => {
                        conn.abort();
                        if lock(&a.flow.shared.refuse_log).allow() {
                            logf!("tcp/{port}: {r}; refusing new connections");
                        }
                        continue;
                    }
                };
                // トンネルの側の接続は、枠を取った後に中継の接続として数える (Go の `conns` への登録)
                let session = Session::new(&a.flow.shared);
                flows.spawn_local(relay_one(
                    conn,
                    Held { _lease: lease, _session: session },
                    a.flow.clone(),
                ));
            }
            Some(_) = flows.join_next(), if !flows.is_empty() => {}
        }
    }
}

/// 1 本の接続を中継する。`held` の枠と接続の数えは、中継が終わって両側が送り残しを届け終えるまで持ち、
/// 落とすと予算と数へ返る。
async fn relay_one(mut down: TcpStream<Net>, held: Held, flow: Flow) {
    let _held = held;
    let Flow {
        lan: table,
        port,
        host,
        tport,
        shared,
        targets,
    } = flow;
    let dial = targets.connect_tcp(&host, tport).await;
    shared.note(dial.as_ref().map(|_| ()));
    let up = match dial {
        Ok(s) => s,
        Err(e) => {
            if lock(&shared.dial_log).allow() {
                logf!(
                    "tcp/{port}: dial {}: {e}",
                    crate::targets::join_host_port(&host, tport)
                );
            }
            // 宛先の拒否は、上限の拒否と同じく RST で終える。宛先に繋がらなければ、仕様のとおり
            // トンネルの側を FIN で閉じ、届け終えるまで枠を持つ
            if e.denied {
                down.abort();
            } else {
                deliver(Delivering(Some(down.close())), None).await;
            }
            return;
        }
    };
    // 宛先の側の接続も、繋がった後に中継の接続として数える
    let _up_session = Session::new(&shared);
    let _ = up.set_nodelay(true);
    let lan = Rc::new(up);
    // LAN の側のソケットの受信のバッファをトンネルの側の boost の枠に合わせる (Go の `FollowBoost`)。
    // 最初に読み書きする前に組を登録し、LAN の側のソケットを閉じる前に外す
    let registration = table.register(down.id(), LanConn::new(Rc::clone(&lan)));
    let _ = pipe::pipe(&mut down, &lan).await;
    drop(registration);
    drop(table);
    // 中継の終わり:トンネルの側を閉じ、LAN の側の読み書きを止める (Go の `PipeHold`)。閉じる側を先に
    // する。止める側を先にすると、もう一方の向きが EOF を受けてトンネルの側に FIN を送りうるためである
    let closing = Delivering(Some(down.close()));
    let lan = match lansock::stop(&lan) {
        lansock::Stopped::Held => Some(lan),
        lansock::Stopped::Closing => None,
    };
    deliver(closing, lan).await;
}

/// 中継の task の future の大きさ (TCP の中継 1 本、UDP のセッションの応答 1 つ)。メモリの上界の試験が
/// 使う。
#[cfg(test)]
pub(crate) fn future_sizes() -> (usize, usize) {
    fn output_size<A, B, C, F: Future>(_: impl FnOnce(A, B, C) -> F) -> usize {
        size_of::<F>()
    }
    (output_size(relay_one), udp::reply_future_size())
}

/// UDP のセッション 1 つの表の項と確保のバイト。
#[cfg(test)]
pub(crate) fn udp_session_bytes() -> usize {
    udp::session_entry_bytes()
}

/// 届け終えるのを待つトンネルの側の接続。待ちの途中で落とすと (リスナーを閉じたとき)、RST で切る。
struct Delivering(Option<Closing<Net>>);

impl Drop for Delivering {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            c.abort();
        }
    }
}

/// 中継を終えた組が送り残しを届け終えるまで待つ。核も Linux も届け終えたことを知らせないので、間隔を
/// [`DELIVERY_POLL_MIN`] から [`DELIVERY_POLL_MAX`] まで倍に伸ばしながら見直す (Go の `AwaitDelivered`)。
/// 待ち終えたらトンネルの側の handle は何もせずに手放し、LAN の側は閉じる。
async fn deliver(mut tunnel: Delivering, lan: Option<Rc<tokio::net::TcpStream>>) {
    let mut wait = DELIVERY_POLL_MIN;
    loop {
        let tunnel_done = tunnel.0.as_ref().is_none_or(Closing::delivered);
        let lan_done = lan.as_deref().is_none_or(lansock::delivered);
        if tunnel_done && lan_done {
            break;
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(DELIVERY_POLL_MAX);
    }
    // 届け終えた接続の handle は RST を送らずに手放す
    drop(tunnel.0.take());
    drop(lan);
}
