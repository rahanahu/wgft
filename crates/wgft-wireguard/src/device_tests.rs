//! Device の試験。2 つの Device を偽の時計と手で運ぶネットワークで向かい合わせる。
//! agent の側 (A) は v1 の agent の設定、server の側 (B) は endpoint を知らないピアを 1 つ持つ。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::config::{DeviceConfig, Ipv4Prefix, Limits, PeerConfig, ProtocolTimers};
use crate::device::{Device, Event};
use crate::drops::DropReason;
use crate::ip::tests::ipv4_packet;
use crate::keys::{PrivateKey, PublicKey};

const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
const UNIX: Duration = Duration::from_hours(500_000);
const KEEPALIVE: Duration = Duration::from_secs(25);

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct Net {
    base: Instant,
    t: Duration,
    a: Device,
    b: Device,
    a_key: PrivateKey,
    b_key: PrivateKey,
    /// A の socket のアドレス。roaming の試験で変える。
    a_addr: SocketAddr,
    b_addr: SocketAddr,
    /// A と B が受け取った packet。
    a_got: Vec<Vec<u8>>,
    b_got: Vec<Vec<u8>>,
    a_events: Vec<Event>,
    b_events: Vec<Event>,
    /// false の間は B へ向かう datagram を捨てる (B が落ちている)。
    b_up: bool,
    /// 運んだ datagram の数。
    carried: usize,
}

fn agent_config(a_key: &PrivateKey, b_pub: PublicKey, b_addr: SocketAddr) -> DeviceConfig {
    DeviceConfig::agent(a_key.clone(), b_pub, Some(b_addr), SERVER_IP, KEEPALIVE)
}

fn server_config(b_key: &PrivateKey, a_pub: PublicKey) -> DeviceConfig {
    DeviceConfig {
        private_key: b_key.clone(),
        mtu: 1420,
        peers: vec![PeerConfig {
            public_key: a_pub,
            endpoint: None,
            allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
            persistent_keepalive: None,
        }],
        limits: Limits::default(),
        timers: ProtocolTimers::default(),
    }
}

impl Net {
    fn new() -> Self {
        Self::with(|_| {}, |_| {})
    }

    fn with(
        edit_a: impl FnOnce(&mut DeviceConfig),
        edit_b: impl FnOnce(&mut DeviceConfig),
    ) -> Self {
        let base = Instant::now();
        let a_key = PrivateKey::generate([0xa1; 32]);
        let b_key = PrivateKey::generate([0xb2; 32]);
        let a_addr = addr("198.51.100.2:40000");
        let b_addr = addr("203.0.113.1:51820");
        let mut ca = agent_config(&a_key, b_key.public_key(), b_addr);
        edit_a(&mut ca);
        let mut cb = server_config(&b_key, a_key.public_key());
        edit_b(&mut cb);
        Self {
            base,
            t: Duration::ZERO,
            a: Device::new(ca, [1; 32], base, UNIX).unwrap(),
            b: Device::new(cb, [2; 32], base, UNIX).unwrap(),
            a_key,
            b_key,
            a_addr,
            b_addr,
            a_got: Vec::new(),
            b_got: Vec::new(),
            a_events: Vec::new(),
            b_events: Vec::new(),
            b_up: true,
            carried: 0,
        }
    }

    fn now(&self) -> Instant {
        self.base + self.t
    }

    fn a_pub(&self) -> PublicKey {
        self.a_key.public_key()
    }

    fn b_pub(&self) -> PublicKey {
        self.b_key.public_key()
    }

    /// 両方の timer を回し、出たものを運ぶ。
    fn tick(&mut self) {
        let now = self.now();
        if self.a.poll_timeout().is_some_and(|t| t <= now) {
            self.a.handle_timeout(now);
        }
        if self.b.poll_timeout().is_some_and(|t| t <= now) {
            self.b.handle_timeout(now);
        }
        self.pump();
    }

    /// 時計を `d` だけ、`step` 刻みで進める。
    fn run(&mut self, d: Duration, step: Duration) {
        let end = self.t + d;
        while self.t < end {
            self.t += step;
            self.tick();
        }
    }

    /// 出たものが無くなるまで datagram を運ぶ。
    fn pump(&mut self) {
        let now = self.now();
        loop {
            let mut moved = false;
            while let Some(tx) = self.a.poll_transmit() {
                moved = true;
                if self.b_up && tx.to == self.b_addr {
                    self.carried += 1;
                    self.b.handle_datagram(now, self.a_addr, &tx.payload);
                }
            }
            while let Some(tx) = self.b.poll_transmit() {
                moved = true;
                if tx.to == self.a_addr {
                    self.carried += 1;
                    self.a.handle_datagram(now, self.b_addr, &tx.payload);
                }
            }
            if !moved {
                break;
            }
        }
        while let Some(p) = self.a.poll_packet() {
            self.a_got.push(p);
        }
        while let Some(p) = self.b.poll_packet() {
            self.b_got.push(p);
        }
        while let Some(e) = self.a.poll_event() {
            self.a_events.push(e);
        }
        while let Some(e) = self.b.poll_event() {
            self.b_events.push(e);
        }
    }

    fn connect(&mut self) {
        self.tick();
        assert!(
            self.a_events
                .iter()
                .any(|e| matches!(e, Event::SessionEstablished { .. })),
            "the agent established a session: {:?}",
            self.a_events
        );
    }

    fn a_sends(&mut self, payload: &[u8]) {
        let now = self.now();
        self.a
            .handle_packet(now, &ipv4_packet(AGENT_IP, SERVER_IP, payload));
        self.pump();
    }

    fn b_sends(&mut self, payload: &[u8]) {
        let now = self.now();
        self.b
            .handle_packet(now, &ipv4_packet(SERVER_IP, AGENT_IP, payload));
        self.pump();
    }

    fn count(events: &[Event], f: impl Fn(&Event) -> bool) -> usize {
        events.iter().filter(|e| f(e)).count()
    }
}

#[test]
fn agent_contacts_the_server_at_start_and_both_ways_work() {
    let mut n = Net::new();
    assert_eq!(n.a.poll_timeout(), Some(n.now()), "contact is due at start");
    n.connect();
    assert_eq!(
        n.b_events.first(),
        Some(&Event::EndpointChanged {
            peer: n.a_pub(),
            endpoint: n.a_addr
        })
    );
    n.a_sends(b"ping");
    assert_eq!(n.b_got, vec![ipv4_packet(AGENT_IP, SERVER_IP, b"ping")]);
    n.b_sends(b"pong");
    assert_eq!(n.a_got, vec![ipv4_packet(SERVER_IP, AGENT_IP, b"pong")]);
    let s = n.b.peer_status(&n.a_pub(), n.now()).unwrap();
    assert_eq!(s.endpoint, Some(n.a_addr));
    assert_eq!(s.last_handshake, Some(n.now()));
    assert!(s.rx_bytes > 0 && s.tx_bytes > 0);
    assert_eq!(n.a.drops().total(), 0);
    assert_eq!(n.b.drops().total(), 0);
}

#[test]
fn delivered_packets_lose_their_padding() {
    let mut n = Net::new();
    n.connect();
    for len in [0, 1, 15, 16, 17, 1400] {
        n.a_sends(&vec![0x5a; len]);
        let got = n.b_got.pop().unwrap();
        assert_eq!(got.len(), 20 + len, "payload of {len} bytes");
    }
}

#[test]
fn packets_from_outside_the_peers_allowed_ips_are_dropped() {
    let mut n = Net::new();
    n.connect();
    let now = n.now();
    // A は宛先で B を選ぶので、送信元が A の AllowedIPs の外でも送れる。受ける B が捨てる
    n.a.handle_packet(
        now,
        &ipv4_packet(Ipv4Addr::new(10, 200, 0, 99), SERVER_IP, b"x"),
    );
    n.pump();
    assert_eq!(n.b_got.len(), 0);
    assert_eq!(n.b.drops().get(DropReason::DisallowedSource), 1);
    // B から A へも同じ
    n.b.handle_packet(
        now,
        &ipv4_packet(Ipv4Addr::new(10, 200, 0, 7), AGENT_IP, b"x"),
    );
    n.pump();
    assert_eq!(n.a_got.len(), 0);
    assert_eq!(n.a.drops().get(DropReason::DisallowedSource), 1);
}

#[test]
fn outbound_packets_need_a_route_an_ipv4_header_and_to_fit_the_mtu() {
    let mut n = Net::new();
    n.connect();
    let now = n.now();
    n.a.handle_packet(
        now,
        &ipv4_packet(AGENT_IP, Ipv4Addr::new(10, 200, 0, 5), b"x"),
    );
    let mut v6 = ipv4_packet(AGENT_IP, SERVER_IP, b"x");
    v6[0] = 0x60;
    n.a.handle_packet(now, &v6);
    n.a.handle_packet(now, &ipv4_packet(AGENT_IP, SERVER_IP, &[0; 1401]));
    n.a.handle_packet(now, &[]);
    assert!(n.a.poll_transmit().is_none());
    assert_eq!(n.a.drops().get(DropReason::NoRoute), 1);
    assert_eq!(n.a.drops().get(DropReason::InvalidInnerPacket), 2);
    assert_eq!(n.a.drops().get(DropReason::TooBig), 1);
    // ちょうど MTU の packet は通る
    n.a_sends(&[0; 1400]);
    assert_eq!(n.b_got.len(), 1);
}

#[test]
fn inner_packets_that_are_not_ipv4_are_dropped_on_receive() {
    let mut n = Net::new();
    n.connect();
    let now = n.now();
    // B の検査を通さずに、IPv4 でない平文と、全長が詰め物の先を指す平文を暗号化して送る
    let mut bad_len = ipv4_packet(SERVER_IP, AGENT_IP, b"abc");
    bad_len[2..4].copy_from_slice(&40u16.to_be_bytes());
    for plaintext in [vec![0x60; 40], vec![0x45; 8], bad_len] {
        let datagram = n.b.proto.encapsulate(0, now, &plaintext).unwrap().unwrap();
        n.a.handle_datagram(now, n.b_addr, &datagram);
    }
    assert!(n.a.poll_packet().is_none());
    assert_eq!(n.a.drops().get(DropReason::InvalidInnerPacket), 3);
}

#[test]
fn garbage_gets_no_answer_and_does_not_move_the_endpoint() {
    let mut n = Net::new();
    n.connect();
    let now = n.now();
    let stranger = addr("192.0.2.66:9999");
    let mut data = vec![4, 0, 0, 0];
    data.extend_from_slice(&[0xee; 60]);
    let mut init = vec![1, 0, 0, 0];
    init.extend_from_slice(&[0x11; 144]);
    for d in [
        &[][..],
        &[1, 2, 3],
        &data,
        &init,
        &[2; 92],
        &[3; 64],
        &[4; 31],
    ] {
        n.b.handle_datagram(now, stranger, d);
    }
    assert!(n.b.poll_transmit().is_none(), "errors are never answered");
    let s = n.b.peer_status(&n.a_pub(), now).unwrap();
    assert_eq!(s.endpoint, Some(n.a_addr));
    assert!(n.b.drops().total() >= 7);
}

#[test]
fn a_replayed_datagram_from_elsewhere_does_not_move_the_endpoint() {
    let mut n = Net::new();
    n.connect();
    let now = n.now();
    n.a.handle_packet(now, &ipv4_packet(AGENT_IP, SERVER_IP, b"once"));
    let tx = n.a.poll_transmit().unwrap();
    n.b.handle_datagram(now, n.a_addr, &tx.payload);
    n.b.handle_datagram(now, addr("192.0.2.66:9999"), &tx.payload);
    assert_eq!(n.b.poll_packet().map(|p| p.len()), Some(24));
    assert!(n.b.poll_packet().is_none());
    assert_eq!(n.b.drops().get(DropReason::Replayed), 1);
    assert_eq!(
        n.b.peer_status(&n.a_pub(), now).unwrap().endpoint,
        Some(n.a_addr)
    );
}

#[test]
fn the_endpoint_follows_authenticated_traffic_from_a_new_address() {
    let mut n = Net::new();
    n.connect();
    n.b_events.clear();
    n.a_addr = addr("198.51.100.77:41000");
    n.a_sends(b"from the new address");
    assert_eq!(n.b_got.len(), 1);
    assert_eq!(
        n.b_events,
        vec![Event::EndpointChanged {
            peer: n.a_pub(),
            endpoint: n.a_addr
        }]
    );
    n.b_sends(b"reply reaches the new address");
    assert_eq!(n.a_got.len(), 1);
}

#[test]
fn an_initiation_from_an_unknown_key_gets_no_answer() {
    let mut n = Net::new();
    let stranger_key = PrivateKey::generate([0xcc; 32]);
    let mut c = Device::new(
        agent_config(&stranger_key, n.b_pub(), n.b_addr),
        [9; 32],
        n.base,
        UNIX,
    )
    .unwrap();
    c.handle_timeout(n.now());
    let init = c.poll_transmit().unwrap();
    n.b.handle_datagram(n.now(), addr("192.0.2.66:9999"), &init.payload);
    assert!(n.b.poll_transmit().is_none());
    assert_eq!(n.b.drops().get(DropReason::UnknownPeer), 1);
    assert_eq!(n.b.peer_status(&n.a_pub(), n.now()).unwrap().endpoint, None);
}

#[test]
fn packets_wait_for_the_handshake_within_the_bound_and_keep_their_order() {
    let mut n = Net::new();
    n.b_up = false;
    for i in 0..1000u16 {
        let now = n.now();
        n.a.handle_packet(now, &ipv4_packet(AGENT_IP, SERVER_IP, &i.to_be_bytes()));
    }
    let held = n.a.held();
    assert_eq!(held.staged_packets_max, 128);
    assert_eq!(n.a.drops().get(DropReason::StagedOverflow), 1000 - 128);
    // ハンドシェイクは進行中の 1 つだけ
    let mut initiations = 0;
    while let Some(tx) = n.a.poll_transmit() {
        assert_eq!(tx.payload.len(), 148);
        initiations += 1;
    }
    assert_eq!(initiations, 1);
    n.b_up = true;
    n.run(Duration::from_secs(6), Duration::from_secs(1));
    let got: Vec<u16> = n
        .b_got
        .iter()
        .map(|p| u16::from_be_bytes([p[20], p[21]]))
        .collect();
    assert_eq!(got, (872..1000).collect::<Vec<_>>());
}

#[test]
fn undrained_output_stays_within_the_limits() {
    let mut n = Net::new();
    n.connect();
    let now = n.now();
    for i in 0..2000u32 {
        n.b.handle_packet(now, &ipv4_packet(SERVER_IP, AGENT_IP, &i.to_be_bytes()));
    }
    let limits = n.b.limits();
    let held = n.b.held();
    assert_eq!(held.transmit_packets, limits.transmit_packets);
    assert!(held.transmit_bytes <= limits.transmit_bytes);
    assert_eq!(
        n.b.drops().get(DropReason::TransmitOverflow),
        2000 - limits.transmit_packets as u64
    );
    // A は取り出さずに受け続ける
    while let Some(tx) = n.b.poll_transmit() {
        n.a.handle_datagram(now, n.b_addr, &tx.payload);
    }
    let held = n.a.held();
    assert_eq!(held.deliver_packets, limits.deliver_packets);
    assert!(held.deliver_bytes <= limits.deliver_bytes);
}

#[test]
fn delivery_is_bounded_by_bytes_too() {
    let mut n = Net::with(
        |a| {
            a.limits.deliver_bytes = 10_000;
        },
        |_| {},
    );
    n.connect();
    let now = n.now();
    for _ in 0..20 {
        n.b.handle_packet(now, &ipv4_packet(SERVER_IP, AGENT_IP, &[0; 1000]));
        let tx = n.b.poll_transmit().unwrap();
        n.a.handle_datagram(now, n.b_addr, &tx.payload);
    }
    assert_eq!(n.a.held().deliver_packets, 9);
    assert_eq!(n.a.drops().get(DropReason::DeliverOverflow), 11);
}

#[test]
fn sessions_are_rekeyed_without_losing_packets() {
    let mut n = Net::new();
    n.connect();
    let mut sent = 0;
    for _ in 0..400 {
        n.t += Duration::from_secs(1);
        n.tick();
        n.a_sends(b"a");
        n.b_sends(b"b");
        sent += 1;
    }
    assert_eq!(n.b_got.len(), sent);
    assert_eq!(n.a_got.len(), sent);
    let accepted = Net::count(&n.a_events, |e| {
        matches!(e, Event::HandshakeAccepted { .. })
    });
    // REKEY_AFTER_TIME (120 秒) ごとに鍵を替える。最初の 1 回と合わせて 4 回ほど
    assert!(accepted >= 3, "only {accepted} handshakes in 400 s");
    assert!(
        !n.a_events
            .iter()
            .any(|e| matches!(e, Event::PeerExpired { .. }))
    );
}

#[test]
fn persistent_keepalives_flow_while_idle() {
    let mut n = Net::new();
    n.connect();
    let rx0 = n.b.peer_status(&n.a_pub(), n.now()).unwrap().rx_bytes;
    let carried0 = n.carried;
    n.run(Duration::from_secs(100), Duration::from_secs(1));
    let rx1 = n.b.peer_status(&n.a_pub(), n.now()).unwrap().rx_bytes;
    // 100 秒に 25 秒ごとの keepalive が 4 つ。鍵の寿命の前なので、ほかには何も流れない
    assert_eq!(rx1 - rx0, 4 * 32);
    assert_eq!(n.carried - carried0, 4);
}

#[test]
fn an_unanswered_peer_expires_and_is_contacted_again() {
    let mut n = Net::new();
    n.b_up = false;
    n.run(Duration::from_secs(91), Duration::from_millis(100));
    assert_eq!(
        Net::count(&n.a_events, |e| matches!(e, Event::PeerExpired { .. })),
        1
    );
    // 5 秒ごとの再送が 90 秒続く
    let tx = n.a.peer_status(&n.b_pub(), n.now()).unwrap().tx_bytes;
    assert_eq!(tx % 148, 0);
    assert!((17..=19).contains(&(tx / 148)), "{} initiations", tx / 148);
    // keepalive の間隔の後に、新しいトンネルで再び始める
    n.b_up = true;
    n.run(Duration::from_secs(26), Duration::from_millis(100));
    assert_eq!(
        Net::count(&n.a_events, |e| matches!(
            e,
            Event::SessionEstablished { .. }
        )),
        1
    );
    n.a_sends(b"back");
    assert_eq!(n.b_got.len(), 1);
}

#[test]
fn shortened_timers_apply() {
    let mut n = Net::with(
        |a| {
            a.timers.rekey_timeout = Some(Duration::from_secs(1));
            a.timers.rekey_attempt_time = Some(Duration::from_secs(4));
        },
        |_| {},
    );
    n.b_up = false;
    n.run(Duration::from_secs(5), Duration::from_millis(50));
    assert_eq!(
        Net::count(&n.a_events, |e| matches!(e, Event::PeerExpired { .. })),
        1
    );
}

#[test]
fn a_restarted_server_is_reached_again_by_traffic() {
    let mut n = Net::new();
    n.connect();
    n.a_sends(b"before");
    // B を同じ鍵で作り直す。新しい B は A の endpoint もセッションも知らない
    n.t += Duration::from_secs(3);
    n.b = Device::new(
        server_config(&n.b_key, n.a_pub()),
        [7; 32],
        n.now(),
        UNIX + n.t,
    )
    .unwrap();
    n.b_got.clear();
    // agent は keepalive の間隔ごとに ping を送る (v1 の agent の Run)。返事の無いデータの 15 秒後に
    // 新しいハンドシェイクを始める
    for _ in 0..30 {
        n.t += Duration::from_secs(1);
        n.tick();
        n.a_sends(b"again");
    }
    assert!(
        !n.b_got.is_empty(),
        "the restarted server got traffic again"
    );
    assert_eq!(
        n.b_got.last().unwrap(),
        &ipv4_packet(AGENT_IP, SERVER_IP, b"again")
    );
}

#[test]
fn a_restarted_agent_needs_a_later_wall_clock() {
    let mut n = Net::new();
    n.connect();
    n.t += Duration::from_secs(1);
    // 壁時計の戻った agent の開始は、古い開始の再送と見分けられず、捨てられる
    n.a = Device::new(
        agent_config(&n.a_key, n.b_pub(), n.b_addr),
        [5; 32],
        n.now(),
        UNIX,
    )
    .unwrap();
    n.a_events.clear();
    n.tick();
    assert_eq!(n.b.drops().get(DropReason::Replayed), 1);
    assert_eq!(n.a_events, vec![]);
    // 進んだ壁時計なら受け付ける
    n.a = Device::new(
        agent_config(&n.a_key, n.b_pub(), n.b_addr),
        [6; 32],
        n.now(),
        UNIX + n.t,
    )
    .unwrap();
    n.tick();
    assert!(
        n.a_events
            .iter()
            .any(|e| matches!(e, Event::SessionEstablished { .. }))
    );
    n.a_sends(b"after restart");
    assert_eq!(n.b_got.len(), 1);
}

#[test]
fn the_server_learns_the_endpoint_and_sends_first_after_the_agent_contacts_it() {
    let mut n = Net::new();
    let now = n.now();
    // endpoint を知らない B は送れない
    n.b.handle_packet(now, &ipv4_packet(SERVER_IP, AGENT_IP, b"early"));
    assert_eq!(n.b.drops().get(DropReason::NoEndpoint), 1);
    n.connect();
    n.b_sends(b"later");
    assert_eq!(n.a_got.len(), 1);
}

#[test]
fn set_endpoint_moves_the_peer_and_contacts_it_when_it_had_none() {
    let mut n = Net::with(
        |a| {
            a.peers[0].endpoint = None;
        },
        |_| {},
    );
    assert_eq!(n.a.poll_timeout().map(|t| t > n.now()), Some(true));
    let b_pub = n.b_pub();
    assert!(n.a.set_endpoint(n.now(), &b_pub, n.b_addr));
    assert!(!n.a.set_endpoint(n.now(), &n.a_pub(), n.b_addr));
    n.connect();
}

#[test]
fn time_going_backwards_is_ignored() {
    let mut n = Net::new();
    n.t = Duration::from_secs(10);
    n.connect();
    n.t = Duration::ZERO;
    n.a_sends(b"x");
    n.tick();
    assert_eq!(n.b_got.len(), 1);
}

#[test]
fn same_seeds_give_the_same_bytes() {
    let run = || {
        let mut n = Net::new();
        n.tick();
        let mut out = Vec::new();
        n.a.handle_packet(n.now(), &ipv4_packet(AGENT_IP, SERVER_IP, b"x"));
        while let Some(tx) = n.a.poll_transmit() {
            out.push(tx.payload);
        }
        out
    };
    assert_eq!(run(), run());
}

#[test]
fn bad_configurations_are_refused() {
    use crate::config::ConfigError;
    let key = PrivateKey::generate([1; 32]);
    let peer = PrivateKey::generate([2; 32]).public_key();
    let base = || DeviceConfig::agent(key.clone(), peer, None, SERVER_IP, KEEPALIVE);
    let now = Instant::now();
    let try_new = |c: DeviceConfig| Device::new(c, [0; 32], now, UNIX).unwrap_err();

    let mut c = base();
    c.peers.push(c.peers[0].clone());
    assert_eq!(try_new(c), ConfigError::DuplicatePeer(peer));
    let mut c = base();
    c.peers[0].public_key = key.public_key();
    assert_eq!(try_new(c), ConfigError::OwnKey);
    let mut c = base();
    let zero = PublicKey::from_bytes([0; 32]);
    c.peers[0].public_key = zero;
    assert_eq!(try_new(c), ConfigError::LowOrderKey(zero));
    let mut c = base();
    c.mtu = 67;
    assert_eq!(try_new(c), ConfigError::Mtu(67));
    let mut c = base();
    c.limits.events = 0;
    assert_eq!(try_new(c), ConfigError::ZeroLimit("events"));
}

#[test]
fn max_transmit_len_covers_a_full_packet() {
    let mut n = Net::new();
    n.connect();
    n.a.handle_packet(n.now(), &ipv4_packet(AGENT_IP, SERVER_IP, &[0; 1400]));
    let tx = n.a.poll_transmit().unwrap();
    assert_eq!(tx.payload.len(), n.a.max_transmit_len());
}
