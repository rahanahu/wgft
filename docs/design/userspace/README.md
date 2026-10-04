# ユーザー空間の転送と資源

ユーザー空間の転送は WireGuard と netstack のトンネル、TCP と UDP の中継を組み合わせます。
動作条件、予算、上界に含めない保持点をそれぞれ定めます。

- [フロー数とメモリのソフト上限](flow-limits.md)
- [リスナーの収束とフローの帰属](listeners.md)
- [エージェントとホストのメモリの条件](memory-agent-host.md)
- [上界に含めない保持点と測定の限界](memory-limits.md)
- [server のメモリの上界](memory-server.md)
- [送信元の制限とモードの選択](mode-selection.md)
- [IPv4 の断片と ICMP の検査](packet-validation.md)
- [WireGuard のソケットの動作条件](socket-buffers.md)
- [WireGuard のハンドシェイクの送信元の保持](wireguard-sources.ja.md) · [English](wireguard-sources.md)
- [待ち受けの失敗と宛先の許可](targets.md)
- [netstack の TCP バッファ](tcp-buffers.md)
- [netstack の依存の固定](netstack-dependency.ja.md) · [English](netstack-dependency.md)
- [中継のカーネル TCP ソケット](tcp-host-sockets.md)
- [TCP の中継と終了](tcp-relay.md)
- [TIME_WAIT と中継後の netstack の保持](tcp-retention.md)
- [トンネルの回復と作り直し](tunnel-recovery.md)
- [UDP の受信と出力の会計](udp-accounting.md)
- [UDP の中継と応答のバッファ](udp-relay.md)
