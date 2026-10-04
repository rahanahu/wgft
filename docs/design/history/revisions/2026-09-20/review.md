<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 74, 76, 77, 79, 90, 92, 94, 95, 103, 104, 110, 111, 112 です。

# 2026-09-20: review

- fail-closed で残るフローの範囲を明記(2026-09-20、7a.3 節):ラボの lifecycle テストで、`listen_port` を bind できないポートへ変えると、server は旧いポートの接続を `Retiring` として残すが、エージェントが旧いポートのリスナーを閉じ直すため接続は切れることを確かめた。
  これはエージェントの従来の挙動(7 節)どおりで、`Retiring` で残せるのはエージェントに配る宣言が変わらない置き換えに限ると 7a.3 節に書いた

- 適用の再試行を追加(2026-09-20、7a.3 節):bind に失敗したルールが、次の変更か再起動まで `not_active` のまま残っていた。
  `Desired` がすべて `Active` になっていないあいだ(ルールの `Prepare` の失敗、または backend 全体の失敗)、30 秒ごとに適用し直すことにした。
  2 つの失敗を 1 つの再試行の仕組みで扱い、backend 全体の失敗もこの間隔より速くは試さない。
  前回と同じものを公開するだけの再試行は commit せず、nftables のテーブルを差し替えないので、meter と `ct count` の状態は保たれる。
  単体テストで、変化の無い再試行が commit しないこと、ポートが空いた後の再試行が公開すること、backend 全体の失敗の後の再試行が公開することを確かめた。
  既知の制限:userspace モードの TCP のルールをポート A から bind できないポート B へ移し、A へ戻すと、A で `Retiring` だった成立済みの接続は、ルールが A で `Active` に戻った時点で閉じる(UDP のセッションは引き継ぐ)

- 再試行のログを絞る(2026-09-20、7a.3 節):失敗し続けるルールが 30 秒ごとの再試行のたびに bind の失敗をログに出し、1 つのポートで 1 日あたり約 2,900 行になっていた。
  ルール単位の失敗は、始まったときと理由が変わったときに 1 行、回復したときに 1 行だけ出すことにした。
  単体テストで、同じ失敗を繰り返しても 1 行だけ出ることと、回復の行を確かめた

- 戻れない地点の後の失敗を試し直す(2026-09-20、7a.3 節、レビュー反映):kernel backend の `Commit` は、nftables の差し替えの後の conntrack の収束、ピアの削除、指紋の読み直しの失敗をログに出すだけで、`Reconciler` はそのトランザクションを完全な成功として扱っていた。
  ルールを削除した直後に conntrack の収束が失敗すると、新しいフローは止まるが、成立済みのフローは旧い DNAT のまま流れ続け、conntrack は `Observe` の比較の対象ではなく、再試行も走らないので、無関係な次の変更まで直らなかった。
  指紋の読み直しが失敗すると、それ以降テーブルの食い違いを検出できなかった。
  これらを修復として `Committed` に明示し、`Reconciler` に「公開済みで修復が残っている」状態を加え、`NeedsRetry` と `apply_error` で示すことにした。
  修復の再試行は、公開が同じでもテーブルを差し替えずに修復の手順だけを走らせる。
  指紋の読み直しの失敗は食い違いとして扱い、公開し直す。
  drop カウンタの読み出しの失敗は修復にしない。
  単体テストで、3 つの修復の失敗がそれぞれ再試行を求め、同じ公開の再試行が修復を走らせてから状態を戻すこと、修復の無い同じ公開の再試行が何も commit しないことを確かめた。
  未確認:ラボでの conntrack の収束の失敗の再現

- userspace と `Relay` の listener を IPv4 だけで開く(2026-09-20、7a.9 節の移行の手順 3):userspace backend の中継のホストの待ち受けを `udp4`、`tcp4` に、`proxyrelay` の待ち受けを `tcp4` に変えた。
  `proxyrelay` は kernel モードでも同じ待ち受けを使うので、kernel モードの `Relay` のルールも IPv6 で待ち受けなくなる。
  これまでは VPS が IPv6 を持つと、IPv6 の送信元が IPv4 の CIDR だけを並べた deny に一致せずに届いた。
  単体テストで、IPv6 のループバックから待ち受けに届かないことを確かめた

- 分割と統合で新しいフローを拒まない(2026-09-20、7a.9 節の移行の手順 3、レビュー反映):userspace の中継を Go の評価器に切り替えた変更では、評価器の更新を中継の待ち受けの更新より先に行うので、所属ルール ID を付け替える待ち受け(分割と統合)とルールを消す待ち受けが、その間に届いた新しいフローを IR に無いルール ID として拒んでいた。
  `srcpolicy` は未知のルール ID を通していたので、分割と統合で新しいフローを拒むことは無く、これは後退だった。
  評価器は、直前の宣言にあって新しい宣言に無いルールを、次の `Update` まで旧い方針で判定するようにした。
  userspace モードの `Relay` の待ち受けは frontend の `Commit` で付け替わるので、評価器と中継の間で付け替えの前後の組を合わせる方法(両方を同じロックの下で更新するなど)では足りず、1 世代の猶予を評価器に持たせた。
  一度も宣言に無かったルール ID は今までどおり拒む。
  単体テストで、1 つのポートの所属ルール ID を 300 回付け替えるあいだ新しい TCP 接続を開き続け、1 つも拒まれないことを確かめた。
  猶予を外すと、同じテストで数十の接続が拒まれた

- TCP の packet_rate を仕上げる(2026-09-20、7a.9 節の移行の手順 5):手順 5 を、依存しない 2 つの部分(CLI と Web UI の旨の表示、kernel の `packet` の行の削除)に分ける案を検討したが、両方とも 1 つのコミットで揃えられたので、7a.9 節の記述は分けずに 1 つの手順のままにした。
  `internal/policy/nftables.Compile` は、TCP のルールでは `packet_rate` が設定されていても `StepAggregatePacketRate` の行を作らないようにした(UDP のルールは変えない)。
  CLI(`rule rate packet`、`rule import`、`rule ls`)は、TCP のルールに有効な `packet_rate` があるとき `packet_rate is stored but has no effect on TCP rules` を stderr に 1 度出す。
  `rule add` は `packet_rate` を設定するフラグを持たないので対象に含まない。
  Web UI は、TCP のルールに `packet_rate` が保存されているときだけ、レート区画に同じ旨を添え、入力欄は無効にしない。
  値そのものは書き出しと読み込みの互換のため今までどおり受け付けて保存する。
  共有 fixture の `tcp_packet_rate_until_step5.json`(kernel の暫定の挙動)と `tcp_packet_rate_userspace_until_step5.json`(userspace の最終の挙動)は、後者を `tcp_packet_rate.json` に改めて両方の評価器に照らす 1 本にまとめ、前者は削除した。
  どの fixture も評価器を限らなくなったので、`admissiontest.Fixture` の `interim_until_step`/`engines` フィールドと `AppliesTo` を取り除いた。
  ゴールデンテスト(`internal/dataplane/linuxkernel/nft`)の `testdata/basic.json` の TCP のルール(`r_tcp`)に `packet_rate` を加え、`testdata/basic.nft` は行が増えないことで、その値がテーブルに現れないことを実カーネルで確かめる。
  単体テスト(`internal/policy/nftables` の `TestCompileRows`)も、`packet_rate` を持つ TCP のルールが `packet` の行を持たないことを確かめる。
  `internal/dataplane/userspace/srcpolicy`(手順 3 から未使用で `Deprecated` の印を付けていた)の削除は別のコミットに残した

- `internal/dataplane/userspace/srcpolicy` を削除する(2026-09-20、7a.9 節の移行の手順 5):Phase 5 の移行の手順 3 から使われなくなり `Deprecated` の印を付けていた package を削除し、Phase 5(共通の Admission Policy)の移行の手順をすべて終えた。
  参照していたコメント(`internal/policy/policy.go`、`internal/policy/policy_test.go`、`internal/dataplane/deps_test.go`)と、`docs/development/testing.md` の `admission` 契機の対象パスの一覧を、削除に合わせて書き直した

- エージェント側の宛先の許可一覧(2026-09-20、所有者の決定):エージェントは `vpsd` が配る `target` へ無条件に接続していたため、VPS を奪った攻撃者はルールの `target` を書き換えるだけで、エージェントを自宅の LAN 全体への踏み台にできた。
  7 節に `WGFT_AGENT_ALLOW_TARGETS` による宛先の許可一覧を加え、11a 節に設定の形を、11 節に脅威と一覧の限界を書いた。
  判定は中継が宛先へ接続する 1 か所に置き、ホスト名の `target` は名前解決の後の実際のアドレスで判定する。
  IP リテラルの `target` は適用のときにも判定し、一覧の外にあれば待ち受けを開かず、5.2 節のルールの `error` として理由を報告する。
  `vpsd` は一覧を知らないので、server 側の変更と wire protocol の変更は無い。
  ラボでは、許可した宛先のルールが転送し、許可しない LAN のアドレスのルールが転送せず理由付きの `error` になることを `lab/e2e.sh` で確かめた。
  未確認の点は、実機の LAN の IPv6 の宛先と、Windows と macOS のエージェントでの動作である

- エージェント用 API の証明書の入れ替えを v1 では持たない(2026-09-20、所有者の決定):証明書ローテーションは 13 節の未決事項のままだが、秘密鍵が漏れた場合の対処を決めていなかった。
  5.1 節に、稼働中の入れ替えを行わないことと、対処が `teardown --purge` と全エージェントの再登録であることを書いた。
  再登録で配る接続文字列が新しいピンを運ぶので、既にあるピンの不一致からの復帰経路をそのまま使える。
  13 節にも同じ判断を書き、SECURITY.md に利用者向けの説明を置いた。
  コードの変更は無い

- 切断したエージェントの表示を履歴として描く(2026-09-20、5.2・10.1 節):stream が切れると `vpsd` は `Connected` を false にするだけで、最後に記録したトンネルとルールの状態、stream の接続元 IP を残す(診断のため。
  5.2 節にもとから書いてある)。
  ところが Web UI(`internal/vpsd/admin/webui.go` の `agentToView`)と CLI(`cmd/wgft agent ls`)はどちらも `Connected` を見ずにこれらの値を今の状態として描いていたため、3 日前に切断したエージェントが緑の「OK」の付いたトンネルと、両方とも履歴である IP の食い違いの比較結果のまま出ていた。
  ハートビートの古さの警告色は `Connected` が true のときだけ働いており、72 時間前の時刻が通常の色で出る逆転も起きていた。
  ルールごとの適用状態は元から `Connected` を最優先で見ており(`webui_state.go`)、直していない。
  Web UI のトンネルの表示と IP の比較は `Connected` が true のときだけ今の状態として出し(切断中は muted の「最終報告(切断中)」、IP の比較は出さない)、ハートビートの古さの警告色は `Connected` を見ずに常に働くよう直した。
  CLI の TUNNEL・RULES 列は切断中の値に `last:` を接頭辞で付け、履歴であることを示す(`cmd/wgft/helptext.go` の `agent ls` の説明も追随し、実装と食い違っていた RULES の説明も合わせて直した)。
  管理 API の JSON は `connected` フィールドが既にあり、他のフィールドも変えていない。
  5.2 節に、切断時に残る値を UI・CLI が今の状態として描いてはならないことを追記し、10.1 節のエージェント一覧の記述を追随させた。
  `tools/uidemo` の既存の切断済みサンプル(`office`)にトンネルの最終状態(`ok`)を足し、`scripts/screenshot-ui.sh` で撮り直して office の行が両言語で「最終報告」に変わり IP の比較が消えたことを確認した。
  ホストの単体テストで、Web UI の一覧(ja/en 両方)と CLI の出力それぞれについて、直す前は失敗する形で確かめた。
  未確認:実機かラボで実際に 1 台のエージェントを切断して見えを確かめてはいない(コードを読んで組み立てた表示である)

- ラボの一式を隔てる単位を VM から Sandbox に変更(2026-09-20、ラボでの実測を受けた所有者の決定):ラボの一式を並列に流す単位を、使い捨ての VM から、1 台の Lab Host VM の中に並べる Sandbox に変えた。
  Sandbox は 6 つの network namespace(`wgft-<id>-client`、`-vps`、`-router`、`-home`、`-lan`、確認の shell 自身が動く `-runner`)、`/tmp/wgft-lab/<id>/` の作業ディレクトリ、自分が起こしたプロセスをひとまとまりに持つ。
  network namespace がすでに隔てるインタフェース名、アドレス、待ち受けポート、`127.0.0.1:8686`、WireGuard のポート、`table inet wgft`、conntrack のテーブルは Sandbox ごとに分けず、作業ディレクトリとプロセスの所有だけを分けた。
  後片付けに VM 全体への `pkill` を使わず、`ip netns pids` で自分の namespace の中のプロセスだけを止める。
  `tools/labhost` が Sandbox の発行、トポロジの構築、並列実行、後片付け、結果の集約を担い、`lab/suite.txt` が確認ごとに parallel、exclusive-heavy、exclusive-timing、exclusive-global の分類を持つ。
  確認は `lab/sandbox.sh` から自分の Sandbox の値を受け取り、`WGFT_LAB_*` が未設定なら従来どおり共有の namespace と `/tmp` を使うので、1 確認 1 VM の流し方も残っている。
  ラボで確かめたこと:同じコミットを 1 確認 1 VM の一式と `labhost run all` の両方で流し、確認が出す PASS、FAIL、SKIP の行数が確認ごとにも合計でも一致した。
  4 つの Sandbox が同時に同じ待ち受けポートと `table inet wgft` と conntrack のテーブルを持てた。
  2 vCPU / 2 GiB の VM で Sandbox 32 個まで並列に流せ、Sandbox 1 つあたりメモリが約 47 MiB 増えた。
  SIGINT では harness 自身が、SIGKILL のあとでは `labhost gc` が、その Sandbox の namespace、プロセス、作業ディレクトリだけを片付け、流れている別の Sandbox には触らなかった。
  分類は測定で決めた。
  `connlimit.sh` は隣に 8 つの Sandbox があっても測定値が 1 つも動かないので並列に流し、`rates.sh` と check 5、5b、5e は読む値がメモリと到達頻度の測定値そのものなので単独で流し、check 5c と 5d は根拠がルールごとの受け付けの判定なので並列に流す。
  check 9 は単独で 20 回中 20 回成功する一方、8 並列のプールでは 20 回中 17 回しか成功しないので単独で流す。
  `version-skew.sh` を Sandbox で流した結果は、この記録の時点では未確認だったが、2026-10-03 に Sandbox で流し、FAIL が無く、Sandbox の後片付けの後に残骸が無いことを確かめた。
  未確認:8 を超える並列数での一式の実行、`exclusive-global` の分類に入る確認(該当は今は無い)、実行中の Incus VM への `limits.cpu` と `limits.memory` の変更がゲストに届かないことへの対処

- SQLite を開く接続の busy_timeout の順序の修正(2026-09-20):`internal/vpsd/store.Open` は `PRAGMA journal_mode=WAL`、`PRAGMA foreign_keys=ON`、`PRAGMA busy_timeout=5000` の順に 3 つの文を送っており、最初の文は busy_timeout が効く前に実行されていた。
  再起動やバイナリの入れ替え、`wgft server teardown`、CLI の一操作など、他のプロセスが数ミリ秒だけファイルを保持している瞬間にこの最初の文がぶつかると、待たずに `SQLITE_BUSY`(`database is locked`)で失敗していた。
  まず `modernc.org/sqlite` の DSN パラメータ(`_busy_timeout`、`_journal_mode`、`_foreign_keys`)に切り替え、3 つを別々の文として送る代わりに 1 回の接続確立に含めることを試したが、手を動かして確かめたところ、journal_mode を初めて WAL に切り替えるこの 1 手だけは、busy_timeout を先に効かせても SQLite 自身がリトライせず、`SQLITE_BUSY` を即座に返すことが分かった(sqlite.org の journal_mode の説明にある、この遷移だけの特別な扱い)。
  DSN パラメータへの切り替えは、確立した後の通常の文(migrate が送る他の文、以後のすべてのクエリ)を短いロックから守る効果はそのまま残したうえで、この 1 手(接続の確立、`Open` の最初の `migrate` 呼び出し全体)だけは `*sqlite.Error` の `Code()` が `SQLITE_BUSY`(5)であることを見て、最大 5 秒(busy_timeout と同じ長さ)まで 20 ミリ秒間隔で自前で待ち直すことにした。
  9 節に経緯と対処を追記した。
  ホストの単体テストで、この特別な扱い自体(busy_timeout を先に設定してもなお即座に失敗すること)、新規のまっさらなファイルを 300 ミリ秒だけ別の接続が保持している間に `Open` を呼んでも待って成功すること(境界は保持時間の半分から 10 倍 + 2 秒の緩い範囲)、`-race` を確かめた。
  この 2 つ目の確認は、リトライを外した(順序の修正だけを残した)状態に一度戻すと、1 ミリ秒未満で `SQLITE_BUSY` のまま失敗することを確かめてから戻した。
  未確認:実機での再起動時の実際の頻度(ホストの単体テストで人為的に作った競合でしか確かめていない)
