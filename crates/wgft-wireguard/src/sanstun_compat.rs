//! sanstun 0.1.0 の振る舞いへの手当て。
//!
//! sanstun 0.1.0 が WireGuard の論文、wireguard-go、Linux の WireGuard と違う振る舞いのうち、外から
//! 直せるものをここに集める。sanstun は改変しない。手当てはそれぞれ 1 つの const か関数か型で、
//! 頼る sanstun の振る舞いを `tests` の試験が固定する。sanstun を上げて振る舞いが直ると、その試験が
//! 落ち、消す手当てを指す。一覧と消し方は `docs/design/v2/wireguard-device.md` の「sanstun の振る舞い
//! への手当て」にある。
//!
//! この module は `protocol` の子で、sanstun を使ってよい。

use std::time::{Duration, Instant};

use sanstun::Tunnel;

/// データの message の平文を詰める単位。
pub(crate) const PADDING: usize = 16;

/// 手当て 1 (TAI64N の基準)。sanstun 0.1.0 は開始の message の印の秒を 2^62 + 37 + Unix 時刻にする。
/// Linux の WireGuard と wireguard-go は 2^62 + 10 + Unix 時刻で、印が 27 秒進む。進んだ印を覚えた
/// server は、同じ鍵の Go の agent やカーネルモードの agent に戻したとき、その開始を再送として捨てる。
/// sanstun は Unix 時刻を呼び手から受けるので、渡す時刻をこの差だけ戻す。
const TAI64N_BASE_AHEAD: Duration = Duration::from_secs(27);

/// sanstun の `Interface::new` に渡す Unix 時刻。印が標準の値になるよう、本当の Unix 時刻から
/// [`TAI64N_BASE_AHEAD`] を引く。
///
/// 消すのは、sanstun が基準を 2^62 + 10 に直した版に上げるときで、上げるのと同じ変更で消す。そうすれば
/// 印は前後で同じ値になり、server の側で印が戻らない。直った sanstun で消し忘れると印が 27 秒戻り、
/// server は前の印より古い開始を 27 秒の間捨てる。試験 `sanstun_stamps_initiations_27_seconds_ahead` が
/// 落ちて知らせる。直っていない sanstun で消すと、印は手当ての前と同じく 27 秒進む (戻りはしない)。
pub(crate) fn stamp_base(unix: Duration) -> Duration {
    unix.saturating_sub(TAI64N_BASE_AHEAD)
}

/// 手当て 2 (MTU を超える詰め物)。sanstun 0.1.0 は平文を常に 16 の倍数まで詰め、論文 (5.4.6 節) と
/// wireguard-go と Linux のように MTU で止めない。送る packet の上限を設定の MTU を 16 の倍数に
/// 切り下げた値にし、詰めた後も設定の MTU を超えないようにする。費用は packet ごとに最大 15 バイト。
///
/// 消すのは、sanstun が詰め物の上限を受ける口を持ったときで、その口に MTU を渡し、ここを
/// `usize::from(configured)` にする。
pub(crate) fn inner_mtu(configured: u16) -> usize {
    usize::from(configured) / PADDING * PADDING
}

/// 手当て 3 (passive keepalive の時刻)。
///
/// WireGuard の規則 (論文の 6.5 節、wireguard-go、Linux) では、返事をしていない最初のデータの受信から
/// `KEEPALIVE_TIMEOUT` の間なにも送らなければ keepalive を送る。sanstun 0.1.0 はデータを受けるたびに
/// この期限を受信から `KEEPALIVE_TIMEOUT` 後へ延ばすので、それより短い間隔で片向きのデータが届き続けると
/// keepalive を送らず、相手は返事の無いデータの 15 秒後にハンドシェイクを始め直す。sanstun は
/// keepalive を送る口を公開せず、空の平文の暗号化も拒む。
///
/// この型は返事をしていない最初と最後の受信の時刻を持つ。期限が来ても sanstun が送っていなければ、
/// [`PassiveKeepalive::force`] が公開の `set_keepalive_timeout` で値をその 1 回の timer の呼び出しの
/// 間だけ最後の受信からの経過に縮め、sanstun の passive keepalive の期限を今にする。
///
/// 消すときは、この型と、`protocol` の中の呼び出し (`passive` の印の付いた行と
/// `Protocol::passive_keepalive`) と、`Device::handle_timeout` の `passive_keepalive` の呼び出しを消す。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PassiveKeepalive {
    /// 最後の送信の後に受けたデータの、最初と最後の時刻。
    unanswered: Option<(Instant, Instant)>,
}

impl PassiveKeepalive {
    /// 認証したデータ (keepalive でないもの) を受けた。
    pub(crate) fn on_data(&mut self, now: Instant) {
        let (_, last) = self.unanswered.get_or_insert((now, now));
        *last = now;
    }

    /// sanstun の送信の記録 (`TimeLastPacketSent`) が進む呼び出しをした: データの暗号化、開始、
    /// 応答、keepalive。sanstun も同じ呼び出しで自分の期限を消す。
    pub(crate) fn on_send(&mut self) {
        self.unanswered = None;
    }

    /// keepalive を送るべき時刻。
    pub(crate) fn deadline(&self, keepalive_timeout: Duration) -> Option<Instant> {
        self.unanswered.map(|(first, _)| first + keepalive_timeout)
    }

    /// 期限が来ていれば、sanstun に passive keepalive を送らせる。呼んだら `true` を返し、呼び手は
    /// sanstun の event を取り出す。
    ///
    /// 呼び手は先に `Tunnel::handle_timeout` を同じ `now` で呼び、出た event を取り出してから呼ぶ。
    /// `usable` は、元の `KEEPALIVE_TIMEOUT` で送信に使えるセッションがあるか。縮めた値が sanstun 0.1.0
    /// の中で効くのは次の 4 か所で、どれも余計な送信を生まない。
    /// - passive keepalive の期限:狙いの効果
    /// - 返事の無いデータの後のハンドシェイクの期限:返事をしていない受信がある間は、sanstun の側の
    ///   「返事の無い送信」の記録が空なので期限が無い (受信がその記録を消し、送信がこちらの記録を消す)
    /// - 受信の側の鍵の更新の期限:縮めると遅くなるだけで、同じ `now` の先の呼び出しが元の値で済ませた
    /// - 送信に使うセッションの条件:縮めると緩くなるので、`usable` のときだけ呼ぶ
    ///
    /// 期限の来た記録は、送れたかに依らず消す (sanstun の passive keepalive と同じ)。
    pub(crate) fn force(
        &mut self,
        tunnel: &mut Tunnel,
        now: Instant,
        keepalive_timeout: Duration,
        usable: bool,
    ) -> bool {
        let Some((first, last)) = self.unanswered else {
            return false;
        };
        if now < first + keepalive_timeout {
            return false;
        }
        self.unanswered = None;
        if !usable {
            return false;
        }
        let shortened = now.saturating_duration_since(last).min(keepalive_timeout);
        tunnel.set_keepalive_timeout(shortened);
        tunnel.handle_timeout(now);
        tunnel.set_keepalive_timeout(keepalive_timeout);
        true
    }
}

/// 頼る sanstun の振る舞いを固定する試験。sanstun を上げてどれかが落ちたら、その振る舞いは直って
/// いるので、対応する手当てを消す (消し方は各手当ての文書)。
#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use sanstun::{
        Event, Interface, PublicKey, Received, ReceivedMessage, StaticSecret, TunnelConfig,
    };
    use zeroize::Zeroizing;

    use super::*;

    const UNIX: Duration = Duration::from_hours(500_000);

    fn src() -> SocketAddr {
        "192.0.2.2:40000".parse().unwrap()
    }

    struct Pair {
        a_if: Interface,
        b_if: Interface,
        a: Tunnel,
        b: Tunnel,
    }

    /// 手を加えない sanstun の 2 つのトンネル。A が始め、B が答える。
    fn pair(now: Instant, unix: Duration) -> Pair {
        let a_secret = StaticSecret::from(Zeroizing::new([0xa1; 32]));
        let b_secret = StaticSecret::from(Zeroizing::new([0xb2; 32]));
        let a_pub = PublicKey::from(&a_secret);
        let b_pub = PublicKey::from(&b_secret);
        let mut a_if =
            Interface::new(Zeroizing::new([1; 32]), now, unix).with_static_private(a_secret);
        let mut b_if =
            Interface::new(Zeroizing::new([2; 32]), now, unix).with_static_private(b_secret);
        let a = a_if
            .new_tunnel(b_pub, TunnelConfig::default(), now)
            .unwrap();
        let b = b_if
            .new_tunnel(a_pub, TunnelConfig::default(), now)
            .unwrap();
        Pair { a_if, b_if, a, b }
    }

    impl Pair {
        /// ハンドシェイクを済ませ、B が A の確認の keepalive を受ける。
        fn connect(&mut self, now: Instant) {
            let init = self.a.initiate_handshake(now).unwrap();
            let Received::Message(ReceivedMessage::HandshakeInitiation(init)) =
                self.b_if.receive(src(), &init, now).unwrap()
            else {
                panic!("expected an initiation");
            };
            let response = self.b.handle_handshake_initiation(init, now).unwrap();
            let Received::Message(ReceivedMessage::HandshakeResponse(response)) =
                self.a_if.receive(src(), &response, now).unwrap()
            else {
                panic!("expected a response");
            };
            let keepalive = self.a.handle_handshake_response(response, now).unwrap();
            self.b_to_receive(&keepalive, now);
        }

        fn b_to_receive(&mut self, datagram: &[u8], now: Instant) {
            let Received::Message(ReceivedMessage::TransportData(data)) =
                self.b_if.receive(src(), datagram, now).unwrap()
            else {
                panic!("expected data");
            };
            let decrypted = self
                .b
                .begin_decapsulate(data, now)
                .unwrap()
                .decrypt(datagram, vec![0; datagram.len()]);
            let _ = self.b.commit_decapsulate(decrypted, now).unwrap();
        }

        /// A から B へデータを送る。
        fn a_sends(&mut self, payload: &[u8], now: Instant) -> Vec<u8> {
            let mut out = vec![0; payload.len().next_multiple_of(PADDING) + 32];
            let len = self
                .a
                .begin_encapsulate(now)
                .unwrap()
                .encrypt(payload, &mut out)
                .unwrap()
                .len();
            out.truncate(len);
            out
        }

        /// B が送った keepalive の数。
        fn b_keepalives(&mut self, now: Instant) -> usize {
            self.b.handle_timeout(now);
            std::iter::from_fn(|| self.b.poll_event())
                .filter(|e| matches!(e, Event::SendKeepalive(_)))
                .count()
        }
    }

    #[test]
    fn sanstun_stamps_initiations_27_seconds_ahead() {
        // 手当て 1 が頼る振る舞い。落ちたら stamp_base を消す (文書の移行の注意を読む)
        let now = Instant::now();
        let mut p = pair(now, UNIX);
        let init = p.a.initiate_handshake(now).unwrap();
        let Received::Message(ReceivedMessage::HandshakeInitiation(init)) =
            p.b_if.receive(src(), &init, now).unwrap()
        else {
            panic!("expected an initiation");
        };
        assert_eq!(
            init.timestamp() >> 32,
            u128::from((1u64 << 62) + 37 + UNIX.as_secs())
        );
        // 手当てを通すと標準の 2^62 + 10
        assert_eq!(
            stamp_base(UNIX) + Duration::from_secs(37),
            UNIX + Duration::from_secs(10)
        );
    }

    #[test]
    fn sanstun_pads_past_the_mtu() {
        // 手当て 2 が頼る振る舞い。sanstun は MTU を知らず、1420 バイトの packet を 1424 まで詰める
        let now = Instant::now();
        let mut p = pair(now, UNIX);
        p.connect(now);
        assert_eq!(p.a_sends(&[0x45; 1420], now).len(), 1424 + 32);
        assert_eq!(inner_mtu(1420), 1408);
        assert_eq!(inner_mtu(1408), 1408);
    }

    #[test]
    fn sanstun_postpones_the_passive_keepalive_on_every_receipt() {
        // 手当て 3 が頼る振る舞い。B は 0 秒と 5 秒にデータを受け、何も送らない。規則では 10 秒に
        // keepalive を送るが、sanstun 0.1.0 は最後の受信から 10 秒の 15 秒まで送らない
        let start = Instant::now();
        let mut p = pair(start, UNIX);
        p.connect(start);
        for at in [0, 5] {
            let now = start + Duration::from_secs(at);
            let d = p.a_sends(b"data", now);
            p.b_to_receive(&d, now);
        }
        assert_eq!(p.b_keepalives(start + Duration::from_secs(10)), 0);
        assert_eq!(p.b_keepalives(start + Duration::from_secs(15)), 1);
    }

    #[test]
    fn force_sends_the_passive_keepalive_at_the_rule_s_time() {
        let start = Instant::now();
        let mut p = pair(start, UNIX);
        p.connect(start);
        let mut passive = PassiveKeepalive::default();
        let k = Duration::from_secs(10);
        for at in [0, 5] {
            let now = start + Duration::from_secs(at);
            let d = p.a_sends(b"data", now);
            p.b_to_receive(&d, now);
            passive.on_data(now);
        }
        assert_eq!(passive.deadline(k), Some(start + k));
        let now = start + k;
        assert_eq!(p.b_keepalives(now), 0);
        assert!(passive.force(&mut p.b, now, k, true));
        let sent = std::iter::from_fn(|| p.b.poll_event())
            .filter(|e| matches!(e, Event::SendKeepalive(_)))
            .count();
        assert_eq!(sent, 1);
        assert_eq!(passive.deadline(k), None);
        // 元の値に戻っている: 次の受信の 10 秒前には送らない
        let now = start + Duration::from_secs(12);
        let d = p.a_sends(b"data", now);
        p.b_to_receive(&d, now);
        assert_eq!(p.b_keepalives(now + Duration::from_secs(9)), 0);
        assert_eq!(p.b_keepalives(now + k), 1);
    }

    #[test]
    fn force_does_nothing_without_a_usable_session_but_clears_the_deadline() {
        // 縮めた値は送信に使うセッションの条件も緩めるので、元の値で使えないときは縮めない
        let start = Instant::now();
        let mut p = pair(start, UNIX);
        p.connect(start);
        let mut passive = PassiveKeepalive::default();
        let k = Duration::from_secs(10);
        for at in [0, 5] {
            let now = start + Duration::from_secs(at);
            let d = p.a_sends(b"data", now);
            p.b_to_receive(&d, now);
            passive.on_data(now);
        }
        assert!(!passive.force(&mut p.b, start + k, k, false));
        assert_eq!(passive.deadline(k), None);
        let sent = std::iter::from_fn(|| p.b.poll_event())
            .filter(|e| matches!(e, Event::SendKeepalive(_)))
            .count();
        assert_eq!(sent, 0);
    }
}
