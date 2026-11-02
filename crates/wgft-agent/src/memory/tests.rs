use super::*;
use crate::batching::Batching;

#[test]
fn the_line_has_the_lab_s_form_and_grows_with_the_caps() {
    let small = MemoryBound::for_limits(caps(4096, 1024), Batching::derived(caps(4096, 1024)));
    let big = MemoryBound::for_limits(flowpool::Limits::default(), Batching::default());
    assert!(small.line().starts_with("memory bound: "));
    assert!(
        small
            .line()
            .contains(&format!("{} MiB, derived from the flow caps", small.mib()))
    );
    assert!(big.total > small.total);
    assert_eq!(
        small.total,
        small.terms().iter().map(|(_, b)| b).sum::<usize>(),
        "the terms line names every term of the sum"
    );
    let open = small.with_listeners(3, 2);
    assert_eq!(
        open.total,
        small.total + 3 * LISTENER_TCP + 2 * LISTENER_UDP
    );
    assert_eq!(open.with_listeners(0, 0), small);
    // lab/lifecycle.sh の check 5b が読む項の名前
    let line = small.terms_line();
    for name in [
        "core fixed",
        "core arrays",
        "tables",
        "driver",
        "device",
        "batch",
        "tcp relay",
        "udp relay",
    ] {
        assert!(
            line.contains(&format!(" {name} ")),
            "{name} is missing: {line}"
        );
    }
}

fn caps(udp: usize, tcp: usize) -> flowpool::Limits {
    flowpool::Limits { udp, tcp }
}

/// データプレーンが device に渡すバッチの枠は、最大の MTU の device が求める長さで数える。
#[test]
fn the_batch_term_counts_slots_the_device_fills() {
    use wgft_wireguard::{DATA_OVERHEAD, DEFAULT_KEEPALIVE, Device, DeviceConfig, PrivateKey};
    let key = PrivateKey::generate(&[1; 32]);
    let peer = PrivateKey::generate(&[2; 32]).public_key();
    let mut config = DeviceConfig::agent(
        key,
        peer,
        None,
        std::net::Ipv4Addr::new(10, 200, 0, 1),
        DEFAULT_KEEPALIVE,
    );
    config.mtu = u16::try_from(MAX_MTU).unwrap();
    let device = Device::new(config, std::time::Instant::now(), std::time::Duration::ZERO).unwrap();
    assert_eq!(device.mtu(), MAX_MTU);
    assert_eq!(device.max_transmit_len(), MAX_MTU + DATA_OVERHEAD);
    // 枠を持たない device の項は、バッチが無くても変わらない
    let on = MemoryBound::for_limits(caps(4096, 1024), Batching::default());
    let off = MemoryBound::for_limits(caps(4096, 1024), Batching::OFF);
    assert_eq!(on.device, off.device);
    assert_eq!(on.device, device_bytes());
    let one_slot = 2 * UDP_BUF + device.mtu() + device.max_transmit_len();
    assert!(
        off.batch >= one_slot && off.batch < one_slot + 256,
        "{}",
        off.batch
    );
    assert_eq!(on.batch, Batching::default().bytes());
}

#[test]
fn the_per_flow_terms_cover_their_types() {
    let (tcp, udp) = crate::relay::future_sizes();
    assert!(tcp <= tcp_relay_future() && tcp_relay_future() < tcp + 64);
    assert!(udp <= udp_reply_future() && udp_reply_future() < udp + 64);
    let entry = crate::relay::udp_session_bytes();
    assert!(entry <= udp_session_entry() && udp_session_entry() < entry + 64);
}

/// 上界の表の生成です。中継の future と表の項の大きさは target で変わるので、表は Linux の x86_64 の値で、ほかの
/// target では比べません。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod table {
    use std::fmt::Write as _;

    use super::*;

    /// 生成する表の上限の組 (UDP、TCP) です。既定の上限、ラボの check 5 の上限、ラボのメモリの測定の上限、受け付ける
    /// 最小の上限です。
    const TABLE_LIMITS: [(usize, usize); 4] = [(8192, 2048), (4096, 1024), (256, 256), (16, 16)];

    const BEGIN: &str = "<!-- BEGIN GENERATED TABLE -->\n";
    const END: &str = "<!-- END GENERATED TABLE -->\n";

    fn mib(x: usize) -> String {
        let tenths = (x * 10 + (1 << 19)) >> 20;
        format!("{}.{}", tenths / 10, tenths % 10)
    }

    /// 生成する表です。行の名前は項の行の名前で、説明は文書の手で書いた部分が持ちます。
    fn table() -> String {
        let bounds = TABLE_LIMITS.map(|(udp, tcp)| {
            let limits = flowpool::Limits { udp, tcp };
            let core = Bound::for_limits(&CoreLimits::with_max_flows(tcp), MAX_MTU);
            (
                MemoryBound::for_limits(limits, Batching::derived(limits)),
                core,
            )
        });
        let mut w = String::new();
        w.push_str("| term |");
        for (udp, tcp) in TABLE_LIMITS {
            write!(w, " K = {tcp}, U = {udp} |").unwrap();
        }
        w.push_str("\n| --- |");
        for _ in TABLE_LIMITS {
            w.push_str(" ---: |");
        }
        w.push('\n');
        let row = |w: &mut String, name: &str, f: &dyn Fn(usize) -> usize| {
            write!(w, "| {name} |").unwrap();
            for i in 0..TABLE_LIMITS.len() {
                write!(w, " {} ({}) |", f(i), mib(f(i))).unwrap();
            }
            w.push('\n');
        };
        let to = |x: u64| usize::try_from(x).unwrap();
        for (n, (name, _)) in bounds[0].0.terms().iter().enumerate() {
            row(&mut w, &format!("`{name}`"), &|i| bounds[i].0.terms()[n].1);
            if *name == "core flows" {
                row(&mut w, "`core flows`: the floors", &|i| {
                    to(bounds[i].1.floor_conn - bounds[i].1.floor_arrays)
                });
                row(&mut w, "`core flows`: `boost`", &|i| to(bounds[i].1.boost));
                row(&mut w, "`core flows`: the rest", &|i| {
                    to(bounds[i].1.frag
                        + bounds[i].1.udp_rx
                        + bounds[i].1.udp_tx
                        + bounds[i].1.ping)
                });
            }
        }
        row(&mut w, "`total`", &|i| bounds[i].0.total);
        row(&mut w, "one TCP listener", &|_| LISTENER_TCP);
        row(&mut w, "one UDP listener", &|_| LISTENER_UDP);
        w
    }

    /// 上界の表は `MemoryBound` の計算から生成し、生成し直しの差分で検査します。`WGFT_UPDATE_GOLDEN=1` を付けた
    /// ときだけファイルを書き直し、付けないときは差があれば失敗します。中継の future と表の項の大きさは target で
    /// 変わるので、表は Linux の x86_64 の値で、ほかの target では比べません。
    #[test]
    fn bound_table_is_up_to_date() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/design/v2/agent-bound.md");
        let doc = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        let (head, rest) = doc.split_once(BEGIN).expect("the begin marker");
        let (old, tail) = rest.split_once(END).expect("the end marker");
        let want = table();
        if std::env::var_os("WGFT_UPDATE_GOLDEN").is_some_and(|v| v == "1") {
            std::fs::write(&path, format!("{head}{BEGIN}{want}{END}{tail}")).unwrap();
            return;
        }
        assert!(
            old == want,
            "{} is out of date; run WGFT_UPDATE_GOLDEN=1 cargo nextest run -p wgft-agent bound_table",
            path.display()
        );
    }
}
