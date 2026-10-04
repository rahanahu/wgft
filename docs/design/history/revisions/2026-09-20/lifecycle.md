<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 73, 78, 108 です。

# 2026-09-20: lifecycle

- トランザクショナルな収束を実装(2026-09-20、7a.8 節の Phase 4):`internal/reconcile` に `Reconciler` を加え、`Runtime` を動かして `Active`、ルールごとの公開の世代、`Retiring` の値、`desired_generation`/`active_generation` を制御プレーンに持たせた。
  失敗は範囲で分けた。
  bind の失敗はそのルールだけを `not_active` にし、dataplane へ渡す `Plan` から外して(fail-closed)、他のルールの公開と世代の前進を妨げない。
  WireGuard のピアの変更と nftables のトランザクションの失敗は backend 全体の失敗とし、何も公開せず、`Prepare` したものを戻し、世代を進めない。
  userspace backend の bind を `Commit` から `Prepare` へ移し、範囲のルールの一部のポートだけが開く状態を無くした。
  ピアの変更、drop カウンタの読み出し、公開の後の収束を 1 つのトランザクションに入れ、差し替えが失敗したときに drop カウンタを二重に累積しないようにした。
  `Relay` の frontend に `StopAccepting` と `Retire` を加え、fail-closed にしたルールの成立済みの接続のうち新しい宣言が許すものを残すようにした。
  削除と無効化は従来どおり成立済みの接続を切る。
  7a.2 節と 7a.3 節に細部を追記し、`not active` の表記を API の値 `not_active` に揃えた。
  単体テストで、失敗の範囲の分類、fail-closed の `Plan` と nftables のテーブル、世代の扱い、backend 全体の失敗での `Rollback`、drop カウンタの二重計上の防止、`StopAccepting` と `Retire` を確かめた。
  未確認:ラボでの既存の結合テストと lifecycle テスト、7a.8 節の Phase 4 の完了条件を確かめる新しい lifecycle テスト、agent 側(agent は従来どおり部分的な適用と 30 秒ごとの再試行のまま)

- wgft の外で変えられたカーネルの状態へ収束させる(2026-09-20、7a.3 節):ラボで、kernel モードの server が転送している最中に `nft flush ruleset` を実行すると、`table inet wgft` が消えたまま次の管理者の変更まで戻らず、ログにも何も出なかった。
  30 秒ごとの再試行は `Desired` がすべて `Active` のときは何もせず、カーネルの実際の状態を読む経路が無かったためである。
  多くの VPS の `/etc/nftables.conf` は `flush ruleset` で始まるので、`systemctl reload nftables` でも同じことが起きる。
  宣言が変わったときだけ適用する方式から、`Desired` と実際の状態が食い違えばいつでも収束させる方式に改めた。
  契機は nftables、リンク、IPv4 アドレスの変更の通知で、通知のたびに `Observe` でテーブルの指紋と wg インタフェースの鍵、ポート、アドレス、up の状態、ピアを直前の `Commit` と比べ、食い違えば `Plan` の全体を 1 回だけ公開し直す。
  通知の取りこぼしに備えて 5 分ごとにも `Observe` する。
  ラボで分かったことは次のとおりである。
  `wg set` によるピアと待ち受けポートの変更は netlink の通知を生まないので、安全網が拾う。
  `flags owner` でテーブルを保持したプロセスが終わってテーブルが消えても nftables の通知は届かないので、backend 全体の失敗は 30 秒ごとの再試行の対象に残した。
  backend 全体の失敗で配られなかった世代は、試し直しで公開したときにエージェントへ配ることにした。
  単体テストで、食い違いがあれば 1 回だけ公開し直すこと、食い違いが無ければ何も commit しないこと、自身の `Commit` の直後の `Observe` が食い違いを報告しないこと、他人のインタフェースに触れないこと、userspace backend が通知を購読せず食い違いを報告しないこと、通知のまとめ、安全網、購読の張り直しを確かめた。
  ラボで、`nft flush ruleset`、`nft delete table inet wgft`、行の削除の後に 1 秒以内に転送が戻ること、`ip link del wgft0` の後にインタフェースが作り直され、エージェントの次のハンドシェイクで転送が戻ること、食い違いの無いあいだルールのハンドルが変わらないこと、他のテーブルの変更で公開し直さないこと、保持の解放の後に `pending` の世代が公開されることを確かめた。
  未確認:受信バッファの溢れと購読の張り直しのラボでの再現、Linux 6.1 より新しいカーネルでの通知の有無

- nf_conntrack が未ロードのホストでカーネルモードの起動が失敗する不具合の修正(2026-09-20):他のファイアウォールを一切使わない、素の Debian 12 の VM(モジュールの状態は再起動のたびに失われる)で `wgft server run --mode kernel` を試したところ、conntrack の UDP タイムアウトの sysctl(4 節)を読む処理が `table inet wgft` を適用するより前にあり、nf_conntrack が未ロードのため読めずに終了コード 1 で終わり、同梱の `server.service` の `RestartPreventExitStatus=3` はこの終了コードを含まないため、systemd がその VM で 2 秒おきに再起動を繰り返すことを確かめた(観測は約 3 分で 83 回)。
  9 節に、この読み取りを `table inet wgft` の適用の後へ動かすこと(適用の netlink 書き込みが `ct` 式を含むテーブルを書くため、`nft` コマンドで同じテーブルを書いたときと同じくカーネルに nf_conntrack を自動ロードさせる)を追記し、適用後もなお読めない場合はカーネルの WireGuard モジュールが無い場合と同じ理由(モジュールの自動ロードでは直らない環境の欠如)で終了コード 3 の中止として扱うことにして、11a 節の一覧にも加えた。
  読み取りの結果(UDP タイムアウト 2 値)を起動のこの時点より前に使う処理は無く、admin API 向けの参照(admin_backend.go)は admin API が待ち受けを始めるさらに後なので、Phase 4 の収束順序と戻れない地点の保証は変えていない。
  `wgft server check` はテーブルを何も適用しないためこの値を起動前には読めないので、その旨をラベル付きの Finding にして、カーネルモードでは無害である(起動時に自動ロードされる)と明記した。
  ホストの単体テストで、適用の後に読む順序であること(順序を入れ替えると失敗することを実際に確かめてから戻した)、適用そのものの失敗は読み取りへ進まずそのまま返ること、適用後の読み取りの失敗が `*wg.StartupRefusal` になり `cmd/wgft` の `exitCode` で終了コード 3 に写ること、`server check` の新しい Finding の文言を確かめた。
  ラボの使い捨て VM で、nf_conntrack を未ロードにした状態(`rmmod` 後)で旧いバイナリ(このコミットの前)が同じ失敗で起動できないこと、直したバイナリは modprobe なしで起動し `lsmod` で nf_conntrack のロードを確認し、転送が動くことを確認した。
  未確認:`table inet wgft` の適用後もなお conntrack の sysctl が読めない実機の環境(単体テストのフェイクでしか確かめていない)
