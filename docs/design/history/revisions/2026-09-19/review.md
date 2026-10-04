<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 48, 57, 58, 60, 65, 66 です。

# 2026-09-19: review

- 読み込みの確認ページも、変わっていない行に検査を掛け直さないようにしました(2026-09-19、レビューの指摘):プロキシモードの範囲を拒否した変更で、バッチは変わっていない古い行を検査から外すようになりましたが、Web UI の確認ページだけは全件に `Rule.Validate` を掛けていました。
  そのため、古い範囲ルールが 1 件あるだけで、別のルールの note を変えただけの読み込みでも適用ボタンが出ず、CLI の `rule import` では通るという経路の差がありました。
  確認ページもバッチと同じ判定(`proto.UnchangedIDs`)を使うようにし、5.4 節と 10.1 節を改訂しました。
  この判定は空の接続元リストの `nil` と空の配列を同じとみなします

- 運用のログ(2026-09-19):10.4 節を新設し、journald のログだけで起動、エージェントの接続と切断、ルールの変更、世代の配信、転送の失敗の箇所を追えるようにした。
  それまではルールの変更がログに残らず、`vpsd` の起動の行に版もモードも無かった。
  バッチ操作の要求に記録用の `op` を加え、CLI と Web UI が操作名を渡す。
  中継先への接続の失敗は接続ごとに 1 行出ていたので、フローの上限での拒否と同じく待ち受けごとに 1 分に 1 回までにした。
  エージェントが 30 秒ごとに出していた状態の行は、内容が変わったときだけ出す

- 拒んだ TCP 接続を RST で閉じるよう修正(2026-09-19、GitHub issue #25 の原因の確認):エージェントの netstack(`internal/agent/tunnel`)と、同じ中継コード(`internal/agent/relay`)を使う `vpsd` のユーザー空間モードは、同時フロー数の上限を超えた TCP 接続を accept の直後に通常の `Close` で閉じていた。
  gVisor のソース(`pkg/tcpip/transport/tcp/endpoint.go` の `closeLocked`)を読むと、これは graceful shutdown(FIN)を経て `tcp.DefaultTCPTimeWaitTimeout`(既定 60 秒)の TIME_WAIT にエンドポイントを残すことが分かる。
  原因の確認は、Go の生きているヒープ(一時的な pprof フックで GC を強制して読む。
  RSS は GC 後も OS に返らない分を含み参考にならない)を、カーネルモードのラボ(VPS が DNAT と kernel WireGuard でエージェントの netstack へ直接転送するため、ユーザー空間モードより実効レートが高く出る)で、修正前後のバイナリを同条件で比べる形で行った。
  修正前は、上限を超える接続のフラッドの間、生きているヒープが受け付けた接続数にほぼ比例して増え、フラッドを止めてからおよそ 1 分(TIME_WAIT の既定と符合する)で元の水準に戻った。
  拒否を RST で即座に終える形(`internal/nettun.TCPConn.Abort`)に変えると、同じフラッドでヒープは終始ほぼ変化しなかった。
  実効レートはラボ(2 vCPU)の制約で issue の報告(毎秒約 4000)には届かず毎秒 1300 台にとどまったが、原因と対策の効果は確認できたと判断する。
  wireguard-go の `tun/netstack`(`netstack.Net`)は stack を公開せず `Abort` に要る `tcpip.Endpoint` へ届かないため、エージェントも `vpsd`(6.3 節)と同じく netstack と TUN の接続部分を自前で持つ必要があり、この部分を両者で共有する内部パッケージ(`internal/nettun`)に切り出した。
  `vpsd` のユーザー空間モードのうち、`vps_mode = kernel` 相当のルール(6.3 節)は公開側の accept をホストの実ソケットで行う(`internal/agent/relay` を `hostNetwork` 越しに使う)ため、この TIME_WAIT の対象ではないと判断し、同じ考え方で実ソケットの拒否も `SetLinger(0)` の RST に変えたが、実ソケットの accept-refuse だけを単独で確かめてはいない。
  プロキシモードの中継(`internal/vpsd/proxyrelay`)は元から実ソケットで、この修正の対象に含めていない。
  7 節と 6.3 節を改訂し、13 節の該当の未決事項は解消として削除した。
  未確認:実機に近い接続レート(毎秒約 4000)での効果、`vpsd` の実ソケットの accept-refuse を単独で確かめること

- カーネルモードに接続元 IP ごとの同時フロー数の上限を追加(2026-09-19、13 節の未決事項の解消):カーネルモードの VPS には、1 つの IP がエージェントのルールごとの上限を埋めて他の利用者を締め出すことへの備えが無かった。
  6.1 節に、7 節と同じ値(UDP 256、TCP 128)を、プロトコルごとに全ルールで共有する動的 set と `ct count over` で数える行を加えた。
  meter と同じく `ct state new` にだけ効かせ、集約上限より前に置く。
  落とした数は既存の drop カウンタと同じ経路で累積する。
  ラボ(`lab/connlimit.sh`、カーネルモード)で、1 つの送信元が TCP 128 本と UDP 256 フローで止まり、上限の前に張った接続が生き残り、上限に達した送信元がいる間も別の送信元が通り、フローが消えると set の要素も消えることを確かめた。
  テーブルの差し替えの後は既存のフローが数に入らず、上限を超えて開けることも確かめ、6.1 節に許容する理由を書いた。
  timeout を持つ set と `ct count` の組み合わせは、カーネルが `Operation not supported` で拒むことも確かめた

- 版の範囲と Commit の戻れない地点(2026-09-19、レビュー反映):7a.6 節の版の交渉を、agent が対応する版の範囲(`protocol_min`、`protocol_max`)を送り、server が共通部分の最大を選ぶ形に改めた。
  agent が 1 つの版しか送らない形では、旧い server と共通に対応できる版を server が計算できないためである。
  版の番号は 1 から始め、版のフィールドを持たない今の実装は legacy v0 として、番号の付いた版の履歴とは別に v1.0.x の間だけ支える。
  7a.2 節に、Runtime の手順の戻れない地点を定めた。
  失敗しうる処理はすべて `Prepare` に置き、dataplane の `Commit` の成功を戻れない地点とし、frontend の `Commit` は失敗せず何度呼んでも同じ結果になるものに限る。
  戻れない地点の直後のクラッシュは、再起動時の収束で直す。
  対応表の `internal/flowcap` の行を、Admission Policy と Resource Guard の両方を持つ今の実態に合わせた

- 版と機能の交渉を実装(2026-09-19、7a.6 節の実装):5.2 節に、`pubkey`/`state` メッセージへのフィールド追加(`protocol_min`/`protocol_max`/`capabilities`、`server_protocol_version`/`server_capabilities`)と、legacy v0 の扱い、共通部分が無い場合と advertisement が壊れている場合の拒否を追記した。
  版の範囲は `proto.SupportedProtocol` の 1 か所に持たせ、選ぶ処理は `proto.SelectProtocolVersion` の 1 関数に集約したので、v2 を加える変更はこの 2 か所の値を広げるだけで済む形にした。
  空配列と不在の区別は、`capabilities`/`server_capabilities`/`server_protocol_version` を `*[]string`/`*int` のポインタで持たせることで表した(`encoding/json` の `omitempty` は空スライスも省いてしまうため)。
  レビューで、`protocol_min`/`protocol_max` の片方だけがある宣言と、範囲そのものが無効な宣言(`protocol_min` が 1 未満、または `protocol_min` が `protocol_max` を超える)を、共通部分が無い場合と同じ扱いにしていた(片方が無ければ legacy v0 と誤認し、無効な範囲は素朴な区間交差の計算で版 0 のような無効な版を選びかねなかった)ことの指摘を受け、`ProtocolRange.Valid()` を設け、`SelectProtocolVersion` は local・remote のどちらかが無効なら選ばずに拒む形にした。
  `vpsd` はこの 2 つの誤りを malformed な advertisement として、共通部分が無い場合(`CloseProtocolMismatch`)とは別の理由コード(`CloseProtocolMalformed`)で区別して閉じ、理由文字列に何が悪かったかを含める。
  前者は相手の実装の不具合、後者は版を上げれば直る正常な状態という違いによる。
  agent 側も、`server_protocol_version` が 1 未満なら範囲外とは別に「版として無効」と検査する。
  `vpsd` の stream hub は、選んだ版と agent の宣言した範囲を接続ごとに記録し、管理用 API のエージェント一覧に加算的なフィールド(`protocol_version`、`agent_protocol_legacy`、`agent_protocol_min`/`max`)として出す。
  `agent ls` の表の列は変えていない。
  選んだ版は接続ごとに 1 回だけ両側のログに出す。
  ラボ(Incus VM、カーネルモード)で、新しい `wgft` と、公開前の直近コミットから別途ビルドした旧い `wgft`(版のフィールドを持たない)を組み合わせ、新 server と旧 agent、旧 server と新 agent、新旧同士の 3 通りで、登録・TCP・UDP の転送が通ることと、新しい側のログに 1 回だけ「protocol legacy v0」または「protocol v1」が出ることを確認し、レビュー対応後に新 server と旧 agent の組み合わせを再確認した。
  共通部分が無い場合と malformed な advertisement の拒否(理由コードと理由文字列)は、実機バイナリの版の範囲や advertisement の形を通常の設定では変えられないため、ラボでは作れず、`proto.SelectProtocolVersion`、`ProtocolRange.Valid()`、stream hub の交渉処理(`negotiateVersion`)のユニットテスト(該当する組み合わせをすべて網羅した表形式)だけで確かめた。
  既存の `lab/e2e.sh` と `lab/lifecycle.sh` はカーネル・ユーザー空間の両モードで通した(このラボ VM は直前に `lan` host を加えたトポロジ変更が未反映だったため、`lab/lab up` でトポロジを作り直してから流した)。
  未確認:v2 を実際に追加する変更が、設計どおり範囲を広げるだけで済むこと(コードレビューでの確認にとどまる)
