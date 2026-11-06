//! RFC 6040 4.2 の decapsulation の試験。agent の device の層が、外側の IP の ECN の欄を見て、内側の
//! packet の ECN の欄を直すか、packet を捨てるかを確かめる。
//!
//! RFC 6040 4.2 Figure 4 (rfc-editor.org の本文のまま):
//!
//! ```text
//!             +---------+------------------------------------------------+
//!             |Arriving |            Arriving Outer Header               |
//!             |   Inner +---------+------------+------------+------------+
//!             |  Header | Not-ECT | ECT(0)     | ECT(1)     |     CE     |
//!             +---------+---------+------------+------------+------------+
//!             | Not-ECT | Not-ECT |Not-ECT(!!!)|Not-ECT(!!!)| <drop>(!!!)|
//!             |  ECT(0) |  ECT(0) | ECT(0)     | ECT(1)     |     CE     |
//!             |  ECT(1) |  ECT(1) | ECT(1) (!) | ECT(1)     |     CE     |
//!             |    CE   |      CE |     CE     |     CE(!!!)|     CE     |
//!             +---------+---------+------------+------------+------------+
//! ```
//!
//! 内側が Not-ECT なら、ほかの印を渡してはならず、外側が CE なら捨てなければならない (MUST)。それ以外は
//! 内側と外側の重い方 (CE、ECT(1)、ECT(0)、Not-ECT の順) にする (MUST)。IPv4 の header checksum も、ECN の
//! 欄を変えたら直す (4.2 の本文)。
//!
//! # 継ぎ目 (seam)
//!
//! 今の `Device::handle_datagram` は外側の ECN を受け取らない。そこで、試験は [`receive`] という 1 つの
//! 手当てだけを通して datagram を渡す。今は外側の ECN を捨てて `handle_datagram` を呼ぶ。外側の ECN を
//! 受ける口 (引数でも別の関数でもよい) を足す修正は、この関数の中身だけを差し替える。
//! 捨てた packet の数は、公開の `Device::drops()` の `total()` の増え方で見る。修正が足す専用の
//! `DropReason` の変種があれば、`drops_total` の手当てをそれに合わせて絞ってよい。
//!
//! 外側が Not-ECT の通常の通信と、送信側の compatibility mode (内側を変えない) の試験は今も通り、
//! 修正が壊さないことの関門になる。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use wgft_wireguard::{
    Device, DeviceConfig, DropReason, Ipv4Prefix, Limits, PeerConfig, PrivateKey, ProtocolTimers,
    Roaming,
};

const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// ECN の欄の 4 つの codepoint (RFC 3168)。
const NOT_ECT: u8 = 0b00;
const ECT1: u8 = 0b01;
const ECT0: u8 = 0b10;
const CE: u8 = 0b11;
/// Figure 4 の行と列の順。
const CODEPOINTS: [u8; 4] = [NOT_ECT, ECT0, ECT1, CE];

/// DSCP の EF。ECN を直しても DSCP の 6 bit は変わらないことを見るために、0 でない値を使う。
const DSCP: u8 = 0b10_1110;

fn name(ecn: u8) -> &'static str {
    match ecn {
        NOT_ECT => "Not-ECT",
        ECT0 => "ECT(0)",
        ECT1 => "ECT(1)",
        _ => "CE",
    }
}

/// Figure 4 を行 (内側)、列 (外側) の順にそのまま写した表。`None` は `<drop>`。
/// 行と列の順は Not-ECT、ECT(0)、ECT(1)、CE。
const FIGURE_4: [[Option<u8>; 4]; 4] = [
    // 内側 Not-ECT
    [Some(NOT_ECT), Some(NOT_ECT), Some(NOT_ECT), None],
    // 内側 ECT(0)
    [Some(ECT0), Some(ECT0), Some(ECT1), Some(CE)],
    // 内側 ECT(1)
    [Some(ECT1), Some(ECT1), Some(ECT1), Some(CE)],
    // 内側 CE
    [Some(CE), Some(CE), Some(CE), Some(CE)],
];

/// Figure 4 の、内側 `inner` と外側 `outer` の交点。
fn figure_4(inner: u8, outer: u8) -> Option<u8> {
    let row = CODEPOINTS.iter().position(|c| *c == inner).unwrap();
    let col = CODEPOINTS.iter().position(|c| *c == outer).unwrap();
    FIGURE_4[row][col]
}

/// 表が RFC の本文の論理 (Not-ECT は守る、CE の外側は捨てる、そのほかは重い方) と合うことの確認。
/// 表の写し間違いを、試験の側で防ぐ。
#[test]
fn the_table_in_this_file_follows_the_rfc_logic() {
    let severity = |c: u8| match c {
        CE => 3,
        ECT1 => 2,
        ECT0 => 1,
        _ => 0,
    };
    for inner in CODEPOINTS {
        for outer in CODEPOINTS {
            let want = if inner == NOT_ECT {
                if outer == CE { None } else { Some(NOT_ECT) }
            } else if severity(outer) > severity(inner) {
                Some(outer)
            } else {
                Some(inner)
            };
            assert_eq!(
                figure_4(inner, outer),
                want,
                "inner {} outer {}",
                name(inner),
                name(outer)
            );
        }
    }
}

/// 内側の IPv4 の packet。`ihl` が 5 より大きければ、NOP の option で header を伸ばす。
/// header checksum は正しい値を入れる。
fn inner_packet(src: Ipv4Addr, dst: Ipv4Addr, ecn: u8, ihl: usize, seq: u32) -> Vec<u8> {
    assert!((5..=15).contains(&ihl));
    let header = ihl * 4;
    let total = header + 8;
    let mut p = vec![0u8; total];
    p[0] = 0x40 | u8::try_from(ihl).unwrap();
    p[1] = (DSCP << 2) | ecn;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    for b in &mut p[20..header] {
        *b = 0x01; // NOP
    }
    p[header..header + 4].copy_from_slice(&seq.to_be_bytes());
    p[header + 4..].copy_from_slice(b"ecn!");
    let sum = checksum(&p[..header]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    assert!(checksum_valid(&p[..header]));
    p
}

/// 16 bit の語の 1 の補数の和を折り返したもの。
fn folded_sum(words: impl Iterator<Item = u16>) -> u16 {
    let mut sum: u32 = words.map(u32::from).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum).unwrap()
}

/// IPv4 の header checksum (checksum の欄を 0 として計算する)。
fn checksum(header: &[u8]) -> u16 {
    !folded_sum(
        header
            .chunks(2)
            .enumerate()
            .filter(|(i, _)| *i != 5)
            .map(|(_, w)| u16::from_be_bytes([w[0], w[1]])),
    )
}

/// header 全体の 16 bit の 1 の補数の和が 0xffff になるか。増分で直しても全体で直しても、有効な
/// checksum はこれを満たす。
fn checksum_valid(header: &[u8]) -> bool {
    folded_sum(header.chunks(2).map(|w| u16::from_be_bytes([w[0], w[1]]))) == 0xffff
}

/// 継ぎ目。`datagram` が外側の ECN `outer_ecn` (IP の TOS の下位 2 bit) で着いたものとして device に渡す。
/// 修正が外側の ECN を受ける口を足したら、ここで呼ぶ。今は外側の ECN を捨てる。
fn receive(
    device: &mut Device,
    now: Instant,
    from: SocketAddr,
    outer_ecn: u8,
    datagram: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    device.handle_datagram_with_ecn(now, from, outer_ecn, datagram, out)
}

/// 捨てた数の総和。「ほかに何も数えない」ことの確認に使う。
fn drops_total(device: &Device) -> u64 {
    device.drops().total()
}

/// 外側 CE と内側 Not-ECT の捨てた数。
fn ce_on_not_ect(device: &Device) -> u64 {
    device.drops().get(DropReason::CeOnNotEct)
}

struct Pair {
    /// 受ける側 (agent)。
    a: Device,
    /// 送る側 (server)。
    b: Device,
    a_addr: SocketAddr,
    b_addr: SocketAddr,
    now: Instant,
}

impl Pair {
    fn connected() -> Self {
        let a_key = PrivateKey::generate(&[0xa1; 32]);
        let b_key = PrivateKey::generate(&[0xb2; 32]);
        let a_addr: SocketAddr = "198.51.100.2:40000".parse().unwrap();
        let b_addr: SocketAddr = "203.0.113.1:51820".parse().unwrap();
        let now = Instant::now();
        let a_cfg = DeviceConfig::agent(
            a_key.clone(),
            b_key.public_key(),
            Some(b_addr),
            SERVER_IP,
            Duration::from_secs(25),
        );
        let b_cfg = DeviceConfig {
            private_key: b_key,
            mtu: 1420,
            peers: vec![PeerConfig {
                public_key: a_key.public_key(),
                endpoint: None,
                allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
                persistent_keepalive: None,
                roaming: Roaming::Any,
            }],
            limits: Limits::default(),
            timers: ProtocolTimers::default(),
        };
        let b_pub = b_cfg.private_key.public_key();
        let mut pair = Self {
            a: Device::new(a_cfg, now, Duration::ZERO).unwrap(),
            b: Device::new(b_cfg, now, Duration::ZERO).unwrap(),
            a_addr,
            b_addr,
            now,
        };
        let t = pair.a.poll_timeout().unwrap();
        pair.now = pair.now.max(t);
        pair.a.handle_timeout(pair.now);
        pair.pump();
        assert!(pair.a.has_session(&b_pub, pair.now), "handshake completed");
        pair
    }

    /// ハンドシェイクの datagram を、外側 Not-ECT で出なくなるまで運ぶ。
    fn pump(&mut self) {
        let mut plain = vec![0u8; usize::from(u16::MAX)];
        loop {
            let mut moved = false;
            while let Some(tx) = self.a.poll_transmit() {
                moved = true;
                let (now, from) = (self.now, self.a_addr);
                receive(&mut self.b, now, from, NOT_ECT, &tx.payload, &mut plain);
            }
            while let Some(tx) = self.b.poll_transmit() {
                moved = true;
                let (now, from) = (self.now, self.b_addr);
                receive(&mut self.a, now, from, NOT_ECT, &tx.payload, &mut plain);
            }
            while self.a.poll_event().is_some() || self.b.poll_event().is_some() {}
            if !moved {
                break;
            }
        }
    }

    /// 内側の packet を server から agent へ、外側の ECN `outer` で届けた結果。
    fn deliver(&mut self, packet: &[u8], outer: u8) -> Option<Vec<u8>> {
        let mut sealed = vec![0u8; self.b.max_transmit_len()];
        let o = self
            .b
            .handle_packet(self.now, packet, &mut sealed)
            .expect("the server has a session and encrypts at once");
        assert_eq!(o.to, self.a_addr);
        let mut out = vec![0u8; usize::from(u16::MAX)];
        let len = receive(
            &mut self.a,
            self.now,
            self.b_addr,
            outer,
            &sealed[..o.len],
            &mut out,
        )?;
        out.truncate(len);
        Some(out)
    }
}

/// 結果の packet が、ECN の欄と checksum 以外は元と同じで、checksum が有効なこと。
fn assert_only_ecn_changed(sent: &[u8], got: &[u8], want_ecn: u8, why: &str) {
    assert_eq!(got.len(), sent.len(), "{why}: length");
    let header = usize::from(sent[0] & 0x0f) * 4;
    assert_eq!(got[1] & 0b11, want_ecn, "{why}: ECN field");
    assert_eq!(got[1] >> 2, DSCP, "{why}: DSCP is kept");
    for i in 0..sent.len() {
        if i == 1 || i == 10 || i == 11 {
            continue;
        }
        assert_eq!(got[i], sent[i], "{why}: byte {i} changed");
    }
    assert!(
        checksum_valid(&got[..header]),
        "{why}: the IPv4 header checksum is not valid: {:02x?}",
        &got[..header]
    );
}

#[test]
fn figure_4_all_sixteen_combinations() {
    let mut pair = Pair::connected();
    let mut seq = 0;
    for inner in CODEPOINTS {
        for outer in CODEPOINTS {
            seq += 1;
            let why = format!("inner {} outer {}", name(inner), name(outer));
            let sent = inner_packet(SERVER_IP, AGENT_IP, inner, 5, seq);
            let before = (drops_total(&pair.a), ce_on_not_ect(&pair.a));
            let got = pair.deliver(&sent, outer);
            let dropped = drops_total(&pair.a) - before.0;
            let named = ce_on_not_ect(&pair.a) - before.1;
            match figure_4(inner, outer) {
                None => {
                    assert!(got.is_none(), "{why}: must be dropped, got {got:02x?}");
                    assert_eq!(dropped, 1, "{why}: the drop is counted once");
                    assert_eq!(named, 1, "{why}: and counted as CeOnNotEct");
                }
                Some(want) => {
                    let got = got.unwrap_or_else(|| panic!("{why}: must be delivered"));
                    assert_only_ecn_changed(&sent, &got, want, &why);
                    assert_eq!(dropped, 0, "{why}: nothing is counted for a delivery");
                    assert_eq!(named, 0, "{why}: CeOnNotEct is not counted");
                }
            }
        }
    }
}

#[test]
fn the_checksum_stays_valid_with_ip_options() {
    let mut pair = Pair::connected();
    // 内側 ECT(0) と外側 CE は CE に書き換わる。header は option で 24 と 60 バイト (IHL 6 と 15)
    for ihl in [6, 15] {
        let sent = inner_packet(SERVER_IP, AGENT_IP, ECT0, ihl, 7);
        let got = pair.deliver(&sent, CE).expect("delivered");
        assert_only_ecn_changed(&sent, &got, CE, &format!("IHL {ihl}"));
    }
}

#[test]
fn each_datagram_uses_its_own_outer_ecn() {
    // 同じ device に続けて渡す datagram が、前の datagram の外側の ECN を引きずらない。
    // 受信の batch (recvmmsg と UDP GRO) があっても同じであるべきことの、device の層での形
    let mut pair = Pair::connected();
    let plan = [
        // (内側, 外側)
        (ECT0, CE),
        (ECT0, NOT_ECT),
        (NOT_ECT, CE),
        (NOT_ECT, NOT_ECT),
        (ECT1, ECT0),
        (ECT0, ECT0),
        (NOT_ECT, ECT1),
        (CE, NOT_ECT),
        (NOT_ECT, CE),
        (ECT1, CE),
    ];
    let before = (drops_total(&pair.a), ce_on_not_ect(&pair.a));
    let mut want_drops = 0;
    for (i, (inner, outer)) in plan.into_iter().enumerate() {
        let sent = inner_packet(SERVER_IP, AGENT_IP, inner, 5, u32::try_from(i).unwrap());
        let got = pair.deliver(&sent, outer);
        let why = format!("#{i}: inner {} outer {}", name(inner), name(outer));
        match figure_4(inner, outer) {
            None => {
                want_drops += 1;
                assert!(got.is_none(), "{why}: must be dropped");
            }
            Some(want) => assert_only_ecn_changed(&sent, &got.expect(&why), want, &why),
        }
    }
    // 捨てる組 (内側 Not-ECT と外側 CE) は、隣り合わない 2 か所にある
    assert_eq!(want_drops, 2);
    assert_eq!(
        drops_total(&pair.a) - before.0,
        want_drops,
        "every dropped packet and nothing else is counted"
    );
    assert_eq!(
        ce_on_not_ect(&pair.a) - before.1,
        want_drops,
        "and each is counted as CeOnNotEct"
    );
}

#[test]
fn a_dropped_packet_does_not_disturb_the_session() {
    // 外側 CE と内側 Not-ECT を捨てた後も、次の packet は届く
    let mut pair = Pair::connected();
    let sent = inner_packet(SERVER_IP, AGENT_IP, NOT_ECT, 5, 1);
    assert!(pair.deliver(&sent, CE).is_none());
    let next = inner_packet(SERVER_IP, AGENT_IP, NOT_ECT, 5, 2);
    assert_eq!(pair.deliver(&next, NOT_ECT), Some(next));
}

// 以下は今も通る。外側が Not-ECT の通常の通信と、送信側の compatibility mode の関門。

#[test]
fn outer_not_ect_delivers_every_inner_packet_unchanged() {
    let mut pair = Pair::connected();
    for (i, inner) in CODEPOINTS.into_iter().enumerate() {
        let sent = inner_packet(SERVER_IP, AGENT_IP, inner, 5, u32::try_from(i).unwrap());
        let got = pair.deliver(&sent, NOT_ECT).expect("delivered");
        assert_eq!(got, sent, "inner {}", name(inner));
    }
    assert_eq!(pair.a.drops().total(), 0);
}

#[test]
fn encapsulation_leaves_the_inner_ecn_field_alone() {
    // RFC 6040 3: encapsulator は、どの mode でも内側の ECN の欄を変えない。
    // 外側の欄は device の層からは見えず、socket が決める (socket の試験は agent の dataplane 側)
    let mut pair = Pair::connected();
    for (i, inner) in CODEPOINTS.into_iter().enumerate() {
        // agent から server への向きで、内側を変えずに運ぶ
        let sent = inner_packet(AGENT_IP, SERVER_IP, inner, 5, u32::try_from(i).unwrap());
        let mut out = vec![0u8; pair.a.max_transmit_len()];
        let o = pair
            .a
            .handle_packet(pair.now, &sent, &mut out)
            .expect("encrypted at once");
        let mut plain = vec![0u8; usize::from(u16::MAX)];
        let (now, from) = (pair.now, pair.a_addr);
        let len =
            receive(&mut pair.b, now, from, NOT_ECT, &out[..o.len], &mut plain).expect("delivered");
        assert_eq!(plain[..len], sent[..], "inner {}", name(inner));
    }
}
