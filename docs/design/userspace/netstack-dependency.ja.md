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
受信のメモリの会計に残る値と、特定の payload を持つ handshake 形式の受付は、別の制限として残ります。
共有の post-close の所有表、キューの受付と内部処理の会計は、別に実装する課題です。
この版の固定だけでは、保持メモリ全体やプロセスの RSS の上界を示しません。

TCP バッファの adapter は、非公開の受信メモリの atomic field の実際の型を確かめてから読みます。
配置が合わなければ、位置を仮定せず、対応する回収を止めます。
依存の更新をマージする前に、対象の版で各 OS の実動作と全体の結合を確認します。
