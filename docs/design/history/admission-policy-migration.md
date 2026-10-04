<!-- docs-status: historical -->

#### Phase 5 の移行の手順

各段は、7a.8 節の共通の完了条件を満たしてから次へ進む。
6.1、6.2、6.3 節と 5.3 節の記述は、挙動を変える段のコミットで合わせて改める。

1. `internal/policy` に評価の定数、段と drop の種類の対応、CIDR の正規化を置く。
   `conntrack` と `proxyrelay` の `sourceAllowed` を `RulePolicy.SourceAllowed` に置き換える。
   挙動は変えない
2. `internal/policy/nftables` と解釈器と fixture を置き、`internal/dataplane/linuxkernel/nft` の `emit` の送信元制限とレートの部分を置き換える。
   完了条件は、`testdata/basic.nft` とゴールデンテストが変わらず、今の kernel の挙動を書いた fixture がすべて通ることである。
   この段では kernel の挙動を変えないので、`Relay` のポートは `src_flow` の行だけを持ち、TCP のルールも `packet` の行を持つ。
   この 2 点の fixture は `interim_until_step` を付けた暫定のもので、手順 4 と 5 で書き直す(`Relay` の分は手順 4 で書き直した)
3. `internal/policy/goengine` を置き、`srcpolicy` と中継の中の判定の呼び出しを置き換える。
   前項の userspace の食い違いのうち最初の 2 つを直し、同じ fixture を通す。
   送信元ごとの同時フロー数は評価器が数え、`flowcap.Counter` はプロセス全体の数だけを数える。
   評価器は IPv4 でない送信元を拒み、userspace と `Relay` の listener を IPv4 だけで開く。
   `Relay` の listener は両モードで同じ `proxyrelay` の待ち受けなので、kernel モードの `Relay` の listener もこの段で IPv4 だけになる。
   kernel の Admission Policy のすべての行に `meta nfproto ipv4` を付ける(送信元の set を使わない集約のレートの行を含む)。
   nftables の出力が変わるので、`testdata/basic.nft` とゴールデンテストを同じコミットで改め、解釈器にも `meta nfproto` の照合を加える
4. `Relay` に Admission Policy のすべての段を適用する。
   kernel モードでは待ち受けを開けている `Relay` のポートに全段の行を付け、`Relay` のポートも set の連番を進める。
   userspace モードでは `proxyrelay` の受け付けで `AdmitFlow` を呼び、手順 3 の入口(`AdmitSourceFlow`)を取り除く。
   kernel モードの `proxyrelay` に残るのは deny と allow の状態を持たない確認だけで、その拒否は drop に数えない
5. TCP のルールの `packet_rate` の扱いを仕上げる。
   kernel の nftables コンパイラから TCP のルールの `packet` の行をやめ、`srcpolicy` を削除する。
   CLI(`rule rate packet`、`rule import`、`rule ls`)と Web UI(ルール詳細ページのレート区画)に、TCP のルールでは `packet_rate` を保存しても効かない旨を示す。
   `rule add` は `packet_rate` を設定するフラグを持たないので対象に含まない。
   入力欄は無効にせず、他の欄の保存で既存の値を消さない。
   この段で Phase 5 のすべての手順が終わる

#### 利用者から見て変わらないものと変わるもの

CLI のコマンドとフラグ、`WGFT_*`、機械向けの CLI 出力、ルールの書き出しと読み込みの形式、admin API v1、join string と agent/server の通信は変わらない(7a.6 節)。
Admission Policy は server の中だけで評価し、エージェントには配らない(5.3 節)ので、全体状態も変わらない。
drop の種類の文字列、SQLite への累積、`Transparent` の UDP のルールの nftables の行も変わらない。

次の挙動は、IR の意味に揃える修正として変わる。

- userspace モードの UDP で、deny と allow で拒む送信元のデータグラムが、`packet_rate` のトークンを使わなくなる
- userspace モードで、送信元ごとの同時フロー数の上限が `new_flow_rate` より先に判定され、`src_flow` の drop として数えられる
- userspace モードで、`Relay` のルールの接続を送信元ごとの同時フロー数の上限で拒んだとき、`src_flow` の drop として数えられる(手順 3。
  kernel モードは既に数えている)
- `Relay` のルールに `per_source_rate` と `new_flow_rate` が効き、deny と allow を含めて drop カウンタに数えられる(手順 4)。
  既にレートを書いた `Relay` のルールでは、更新の後に初めて制限が効き始める
- kernel モードの `Relay` のルールでレートと送信元ごとの同時フロー数が拒む接続は、accept の後に閉じられる代わりに、nftables で黙って捨てられる(手順 4)
- `Relay` のルールを含む設定では、kernel モードの set の連番が `Relay` のポートでも進むので、`wgft server nft` が示す set の番号が変わる(手順 4)
- kernel モードで、TCP のルールの `packet_rate` が効かなくなる(手順 5)
- CLI(`rule rate packet`、`rule import`、`rule ls`)と Web UI が、TCP のルールに `packet_rate` が保存されているとき、効かない旨を新しく示す(手順 5)
- userspace と `Relay` の listener が IPv6 で待ち受けなくなり、IPv6 の送信元は届かなくなる

#### Phase 6 との境界

Phase 5 が扱うのは、IR の 6 つの段だけである。
Resource Guard(プロセス全体の予算、ルールごとの隔離、メモリのソフト上限、kernel の conntrack の保護)は、Admission Policy がフローを通した後にだけ判定する。
その拒否は Admission Policy の drop の種類に数えず、fixture にも含めない。
kernel でも、conntrack の表が溢れてフローが落ちるのは prerouting の判定の後なので、この順序は両モードで同じである。
Phase 5 は、送信元ごとの同時フロー数を数える場所を `flowcap.Counter` から評価器へ移すだけで、`flowcap.Limits` の型の分割、`internal/flowcap` の改称、ルールごとの隔離の方式は Phase 6 に残す。

`frontend` の package の分け方(7a.7 節)は、分けないことで決着した。
詳細は 7a.7 節を見よ。
