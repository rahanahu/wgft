# wgstack の Rust 版の上界の表

この文書は、[wgstack の Rust 版](wgstack-rs.md)の上界の式の値を、代表の K の値で示します。
表は `crates/wgft-wgstack` の試験 `bound::tests::bound_table_is_up_to_date` が生成し、印の間だけを書き直します。
手で直さず、`WGFT_UPDATE_GOLDEN=1 cargo nextest run -p wgft-wgstack bound_table` で作り直します。
印を付けずに流すと、試験は表が計算と違うときに失敗します。

値は byte で、括弧の中は MiB です。
MTU は 1420 で、K のほかの表の大きさは既定の値です。
型の大きさは rustc の版で変わりうるので、toolchain を上げる PR は表を作り直し、差分を PR に書きます。

行の名前は `crates/wgft-wgstack/src/bound.rs` の欄の名前で、中身は次のとおりです。

- `stack`:核の値
- `conn_slots`:接続の枠と空きの list
- `conn_index`:接続の 4 つ組の hash の表と世代
- `syn`:握手の途中の表とその hash の表と空きの list
- `tw`:TIME_WAIT の表とその hash の表と空きの list、元の接続の枠ごとの list
- `listeners`:待ち受けのポートごとの行と、開いている印の bit の集合
- `udp_endpoints`:UDP の endpoint のポートごとの行と、開いている印の bit の集合
- `wheel`:タイマーの輪と、期限の来た節の list
- `output`:出力の 2 つの list (節の印は 1 節 1 bit) と制御の輪
- `events`:知らせの印と順番の list (節の印は 1 節 1 bit)。対象は接続の枠、ポート、ping の endpoint です
- `chunk_pool`:chunk の置き場に残す chunk とその管理
- `fix`:上の項の和で、M_fix です
- `floor_conn`:N_c × (f_s + f_r + r_f + h_f) です
- `boost`:B × (d_s + d_r + d_rec + d_h) と `Budget` の枠の管理です
- `frag`:再組み立ての表の保持 byte の上限で、M_frag です
- `udp_rx`:UDP の受信の byte の予算、受信の datagram の管理の配列、chunk の管理の配列の半分で、M_udp_rx です
- `udp_tx`:UDP の送信の byte の予算、送信の datagram の管理の配列、chunk の管理の配列の残りの半分で、M_udp_tx です
- `ping`:ping の endpoint の行と応答の置き場で、N_ping × c_ping です
- `total`:`fix`、`floor_conn`、`boost`、`frag`、`udp_rx`、`udp_tx`、`ping` の和です
- `transient`:段を変える間の一時の保持で、式に含めない項です

<!-- BEGIN GENERATED TABLE -->
| term | K = 256 | K = 2048 | K = 8192 |
| --- | ---: | ---: | ---: |
| `stack` | 3704 (0.0) | 3704 (0.0) | 3704 (0.0) |
| `conn_slots` | 3956736 (3.8) | 13189120 (12.6) | 44843008 (42.8) |
| `conn_index` | 57344 (0.1) | 229376 (0.2) | 917504 (0.9) |
| `syn` | 118784 (0.1) | 118784 (0.1) | 118784 (0.1) |
| `tw` | 7605248 (7.3) | 7612416 (7.3) | 7636992 (7.3) |
| `listeners` | 1056768 (1.0) | 1056768 (1.0) | 1056768 (1.0) |
| `udp_endpoints` | 2105344 (2.0) | 2105344 (2.0) | 2105344 (2.0) |
| `wheel` | 67584 (0.1) | 225280 (0.2) | 765952 (0.7) |
| `output` | 911072 (0.9) | 925632 (0.9) | 975552 (0.9) |
| `events` | 605176 (0.6) | 621528 (0.6) | 677592 (0.6) |
| `chunk_pool` | 1049088 (1.0) | 1049088 (1.0) | 1049088 (1.0) |
| `fix` | 17536848 (16.7) | 27137040 (25.9) | 60150288 (57.4) |
| `floor_conn` | 419328000 (399.9) | 1397760000 (1333.0) | 4752384000 (4532.2) |
| `boost` | 131382144 (125.3) | 131382144 (125.3) | 131382144 (125.3) |
| `frag` | 4194304 (4.0) | 4194304 (4.0) | 4194304 (4.0) |
| `udp_rx` | 4370944 (4.2) | 4370944 (4.2) | 4370944 (4.2) |
| `udp_tx` | 4241920 (4.0) | 4241920 (4.0) | 4241920 (4.0) |
| `ping` | 23104 (0.0) | 23104 (0.0) | 23104 (0.0) |
| `total` | 581077264 (554.2) | 1569109456 (1496.4) | 4956746704 (4727.1) |
| `transient` | 8388608 (8.0) | 8388608 (8.0) | 8388608 (8.0) |
<!-- END GENERATED TABLE -->

[wgstack の Rust 版](wgstack-rs.md)
