# netstack の依存の固定

[English](netstack-dependency.md) · [ユーザー空間の仕様](README.md)

wgft は公式の gVisor module を `v0.0.0-20261004063249-f57b8fc79db4` に固定します。
この公式 go branch のコミットは、週次の `release-20260928.0` tag より後の修正を含みます。
wgft は netstack の fork やローカルの依存パッチを持ちません。

選んだソースは、TIME_WAIT の再利用で到着した SYN をキューに入れられないときに、segment の参照を返します。
また、`Buffer.GrowTo` が追加の byte を公開して 0 にするときに、clone 元のバッファの内容を保ちます。
これらの修正は参照の解放と copy-on-write の正しさを改善しますが、TCP の endpoint や空の TCP segment の件数を制限しません。

通常の close は、依存が持つ TIME_WAIT の挙動を保ちます。
RACK の損失検出を有効なまま保ち、wgft は引き続き SACK を有効にします。
送信、受信と RACK のソースは、前の固定版から変わりません。
そのため、今回の更新で既知の[短い障害の後の回復の遅さ](../vps/userspace.md#63-ユーザー空間モード)は直りません。
依存は、payload が 0 の TCP segment を受信のメモリのしきい値とは別に受け入れます。
待ち受けが segment を新しい endpoint に渡すとき、依存の `segment.setOwner` は前の持ち主の受信のメモリの会計から、その segment の分を引きません。
SYN cookie の経路では、待ち受けの会計が受信のバッファを超えることがあり、その後の待ち受けは payload を持つ segment を拒み続けます。
この経路に入る条件は[エージェントの accept の待ち行列の制限](memory-agent-host.md#syn-cookie-の経路の受信のメモリの会計)に書きます。
待ち受けの backlog を 256(待ち受け 1 つあたりの受信の floor で約 64 MiB)に下げるには、前の持ち主の会計を返す版の gVisor が要ります。
gVisor を更新するときに、この点を確かめ直します。
特定の payload を持つ handshake 形式の受付も、別の制限として残ります。
閉じた後の TCP の endpoint は、Device 全体の固定の表で抑えます([閉じた後の接続の表](tcp-retention.md#閉じた後の接続の表))。
この版の固定だけでは、保持メモリ全体やプロセスの RSS の上界を示しません。

TCP バッファの adapter は、非公開の受信メモリの atomic field の実際の型を確かめてから読みます。
配置が合わなければ、位置を仮定せず、対応する回収を止めます。
依存の更新をマージする前に、対象の版で各 OS の実動作と全体の結合を確認します。
