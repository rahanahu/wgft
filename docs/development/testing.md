# テストの分類と実行の契機

wgft のテストは、実行の費用、所要時間、必要な機材、再現性によって A から F の 6 類に分かれます。
どの類に置くかは、そのテストだけが捉えられる失敗と、そのテストの費用との釣り合いで決めます。
「大事なテストなので毎回流す」という理由では類を決めません。
ただし、ラボの一式は費用が小さいので、コードを変える PR ではマージの前にすべてを流します (次節)。

## 類の定義

- A 類 (すべての PR):数分で終わり、結果の再現性が高く、日常の退行を捉えるテストです。
  CI の検査はすべての PR で、ラボの一式はコードを変える PR のマージの前に流します
- B 類 (関係する変更の関門):ラボの一式に含まれず、特定の領域を変えた PR とリリースの候補でだけ流すテストです。
  どの変更がどのテストを流すかは、後述の「変更の契機と対象のパス」の表で決まります
- C 類 (段階の完了の関門):関係する実装の段階を終えるときに流すテストです。
  悪い条件のネットワーク、クラッシュからの回復、別のディストリビューションでのラボの一式、長時間の通信、小さいメモリの環境を含みます。
関係する変更を含む段階の完了時に流し直す項目は、この類に置きます
- D 類 (リリース候補の関門):リリースの候補の版ごとに流すテストです。
  Windows と macOS のエージェント、旧版からの更新、リリースの成果物を確かめます
- E 類 (手作業と実機の関門):実 VPS、実回線の自宅ルータ、Windows と Mac の実機、実アプリケーションでの長時間の利用のように、再現用の環境では作れない条件を人が確かめる関門です
- F 類 (調査だけの実験):回帰テストに含めない実験です。
  仕様の根拠 (測定値や挙動の確認) を得たら、必要な範囲だけを小さな回帰テストに置き換え、高価な実験そのものは繰り返しません

リリース候補で繰り返す条件と、関係する変更の後に繰り返す条件は、各類の表の頻度に従います。

「新設」と記した項目は、実装されるまではマージの関門に含めません。
実装された時点から、表の契機を適用します。
v1.0 はリリース済みですが、その事実だけで新設項目の実装や実施が完了したとは判断しません。
未確認と未実装の範囲は[追加テストの台帳](testing-catalog.md)に記録します。
存在しないテストを関門にすると、どの PR も関門を満たせなくなるためです。

## 壁時計で測る区間を使うテストの規範

テストは「N 秒待てば足りる」という想定だけでは書きません。
まず状態が届き収束したことを確認してから、観察の区間に入ります。
何も起きないことを主張する否定の主張は区間そのものを必要とするので、この規範は区間を禁じません。
求めるのは、区間に入る前に収束を確認することです。
待ちの上限 (budget) は残します。
上限は待ちすぎを防ぐ道具であり、主張の根拠ではないからです。

収束を確認しないまま区間に入ると、直前の操作の収束がまだ終わっておらず、その残りが区間の途中で観測されて無関係な失敗に見えます。

## マージの前に流すテスト

コードを変える PR は、マージの前にラボの一式 (A9) を両モードで流します。
ラボの一式は、ラボの一式の内訳 (L 番号) のうち実装済みの確認の集まりで、今は L1 から L18 です。
流し方は、1 台の Lab Host VM の中で `labhost run -parallel 8 all` を実行することです。
この 1 コマンドが、両モードの確認と、分類に従った並列と単独の振り分けを含みます。
文書だけを変える PR は、ラボを流しません。
CI の検査のうち A8 は、どちらの PR でも流します。
A1 から A7 は、Markdown の文書と `docs/images/` の画像だけを変える PR では流しません。

コードは、実行時の挙動かテストの結果を変えうるすべての変更を指します。
Go のコード (`go.mod`、`go.sum` を含む)、`deploy/`、`lab/` 自身、設定と dotenv の扱い、`scripts/`、`.goreleaser.yaml`、`.github/workflows/` がこれに当たります。
変更がコードに当たらないのは、Markdown とテキストの文書 (README、`docs/` の文書とその画像) だけです。
`docs/cli.md` はヘルプから生成するので、ヘルプを変えた PR は Go のコードを変える PR です。

ラボの一式は自動で実行できるため、コードを変えたらすべてを流します。
一式の費用が大きく伸びた場合は、この規則を見直します。
所要時間と資源の費用は、実行時の結果を PR に記載します。

B 類の契機は、ラボの一式に含まれないテスト (B 類の一覧のうち実装済みのもの) を選ぶためと、開発の途中でラボの確認を流し直すときに、変えた領域の確認だけを選ぶために使います。
開発の途中の選び方は、後述の「ラボの一式の内訳」の表の契機の列にあります。

## 変更の契機と対象のパス

次の表の契機に当たるパスを PR が変えたときは、B 類の列のテストのうち実装済みのものを流します。
新設の B 類は、実装されるまで契機に当たっても流しません。
1 つのパスが複数の契機に当たる場合は、当たる契機のテストをすべて流します。
ラボの一式の列は、開発の途中で流し直す確認を選ぶための目安で、マージの前にはラボの一式のすべてを流します。

| 契機 | 対象のパス | B 類 | ラボの一式のうち開発の途中で選ぶ確認 |
|---|---|---|---|
| `nft-emit` | `internal/policy/nftables/**`、`internal/dataplane/linuxkernel/nft/**`、`internal/policy/*.go`、`internal/planner/**` | B1 | L2、L3 (kernel モード) |
| `kernel` | `internal/dataplane/linuxkernel/**`、`internal/platform/linux/**`、`internal/vpsd/teardown/**`、`lab/netns.sh`、`lab/lab` | B1、B2 | L2、L4、L5、L7、L10 (kernel モード) |
| `admission` | `internal/policy/**`、`proto/rate.go`、`proto/source.go` | B1 | L2、L3、L13 |
| `resource` | `internal/resource/**`、`internal/lograte/**`、`internal/dataplane/userspace/**`、`internal/netpipe/**`、`internal/nettun/**`、`cmd/wgft/limits.go` | B11 (C5 と C6 は次の段階の完了時に流し直す) | L8 (両モード) |
| `reconcile` | `internal/reconcile/**`、`internal/planner/**`、`internal/model/**`、`internal/dataplane/*.go`、`internal/vpsd/apply.go`、`internal/vpsd/watch.go`、`internal/vpsd/dataplane*.go` | 無し (C2 は次の段階の完了時に流し直す) | L4、L5、L6、L9、L10、L15 (両モード) |
| `relay` | `internal/vpsd/proxyrelay/**` | B3 | L1、L3、L6、L9、L13 |
| `userspace` | `internal/dataplane/userspace/**`、`internal/nettun/**`、`internal/netpipe/**`、`internal/agent/**` | B11 | L1、L3、L4、L8、L18 (userspace モード) |
| `rule-ops` | `internal/vpsd/admin/**`、`internal/vpsd/agent_disable.go`、`proto/rule.go`、`proto/splitmerge.go`、`proto/importdiff.go`、`cmd/wgft/rule.go` | 無し | L5、L11、L12、L14、L15 (両モード) |
| `protocol` | `proto/stream.go`、`proto/state.go`、`proto/version.go`、`internal/vpsd/stream/**`、`internal/vpsd/agentapi/**`、`internal/agent/**` | B7 | L1、L4、L14、L15 |
| `agent-platform` | `internal/agent/**`、`internal/flock/**`、`internal/dataplane/userspace/relay/**`、`internal/dataplane/userspace/tunnel/**`、`cmd/wgft/**`、`*_windows.go`、`*_darwin.go` | B4、B8 | L1、L14、L16、L17、L18 |
| `deploy` | `deploy/*.service`、`deploy/*.conf`、`deploy/*.plist`、`deploy/server.env.example`、`cmd/wgft/config.go`、`cmd/wgft/server.go`、`cmd/wgft/agent.go` (設定の読み込みと終了コード) | B2、B9 | L7 |
| `build` | `.goreleaser.yaml`、`scripts/build-release.sh`、`scripts/goreleaser-checksum.sh`、`scripts/third-party-licenses.sh`、`scripts/check-release-assets.sh`、`scripts/docker-smoke.sh`、`deploy/Dockerfile.*`、`deploy/*.compose.yaml`、`go.mod`、`go.sum`、`.github/workflows/**` | B5、B6、B10 | 無し |
| `dataplane-net` | `internal/dataplane/**`、`internal/nettun/**`、`internal/netpipe/**`、`internal/agent/**` の転送の経路 | 無し (C1 と C5 は次の段階の完了時に流し直す) | L1 |
| `phase` | 関係する実装の段階の完了 | C 類 | すべて |
| `rc` | リリースの候補の版 | 「リリース候補ごと」の項目 | すべて |
| `manual-release` | 過去に 1 回の確認を求めた項目を関係する変更の後に流し直すとき | E 類の該当する項目 | 無し |

表の対象のパスは、実装の移動 (7a.7 節の package 配置) に合わせて改めます。

## CI とラボの関係

CI (`.github/workflows/ci.yml`) は、ホストで完結する A1 から A8 と、B 類のうち GitHub の runner で動くものを、変更の内容に応じて流します。
ラボの結合テストは Incus の VM を必要とするので、CI では流しません ([CLAUDE.md](../../CLAUDE.md#開発環境とテスト))。
ラボの一式 (A9) と、ラボを使う B 類は、PR を出す開発者がラボで流し、その結果を PR の本文に書きます。

ラボの実行手順は[lab/README.md](../../lab/README.md)にあります。
`labhost run all` は `lab/suite.txt` の分類に従い、並列の確認の後に単独の確認を流します。
複数の VM に分けてフラッドの確認を流す場合は、`lifecycle.sh` の check 5、5b、5c、5d、5e と `rates.sh` に他の VM と CPU を取り合わない VM を使います。

開発の途中でラボの確認を流し直すときは、`lab/lifecycle.sh` に確認の番号を指定して、その確認だけを流せます (`lab/lab exec vm bash /wgft/lab/lifecycle.sh kernel 3 3b`)。

CI は、`build-test` (A1 から A7)、B4 (`windows-test`)、B5 (`release-snapshot`)、B6 (`govulncheck`)、B8 (`macos-test`) を、変更の内容に応じてだけ流します。
振り分けは `.github/workflows/ci.yml` の `changes` という 1 つのジョブが担い、`dorny/paths-filter` で変更されたパスを調べます。
振り分けはワークフロー全体の `paths:` ではなく、ジョブごとの `if:` で行います。
ワークフローの `paths:` で絞ると、当たらない PR ではジョブそのものが実行されず、GitHub の checks の一覧に現れません。
ブランチ保護がこれらを必須の check にした場合、現れない check はいつまでも待ち続け、マージを永久に塞ぎます。
ジョブごとの `if:` であれば、当たらない PR でもジョブは実行され、内容を飛ばして skipped で終わります。
GitHub は skipped のジョブを必須の check の合格として扱うため、マージを塞ぎません。

`build-test` の絞り方は、他のジョブと向きが逆です。
他のジョブは流す条件をパスの一覧で数え上げますが、`build-test` は skip する条件を数え上げます。
A1 から A7 の検査が見るのは Go のソース、`go.mod`、`go.sum`、および Go のテストが読むファイルだけなので、Markdown の文書と `docs/images/` の画像だけを変えた PR では結果が変わりません。
`changes` ジョブは変更されたパスの一覧を受け取り、一覧のすべてが Markdown の文書か `docs/images/` の画像であるときにだけ `build-test` を skip します。
当てはまらないパスが 1 つでも混じれば流します。
`docs/cli.md` は Markdown ですが、`cmd/wgft/helptext.go` から生成して `TestCLIDocUpToDate` が照合するので、文書としては扱いません。

向きを逆にした理由は、A2 の `go test ./...` が Go 以外のファイルも読むことにあります。
読み取りの対象は `docs/cli.md`、`internal/vpsd/admin` が `go:embed` で取り込む Web UI のテンプレートと静的ファイル、`tools/labhost` の `suite_test.go` が読む `lab/suite.txt`、`internal/policy` と `internal/dataplane/linuxkernel/nft` の `testdata` です。
流す条件を数え上げる書き方では、後から加わった読み取り先が漏れて、検査が静かに skip されます。
skip する条件を数え上げる書き方では、一覧に無いパスはすべて流す側に倒れます。

B4 と B8 は、前節の表の `agent-platform` の契機どおりには絞りません。
`agent-platform` の契機は、CI では再現できない実機の確認 (D1、D2、E4、E5) の定義としてそのまま残しますが、`windows-test` と `macos-test` は、Go のソースファイル (`*.go`) 1 つでも、`go.mod`、`go.sum` のどちらかでも変えた PR で流します。
理由は、この 2 つのジョブが実行する `cmd/wgft` と `internal/agent` などのテストの一式が、実際のサーバのデータベースや admin backend を組み立てるためです。
組み立てに使う依存は `internal/vpsd/store`、`internal/vpsd/admin`、`proto`、`internal/model`、`internal/policy`、`internal/resource`、`internal/nettun` など広い範囲に及び、パスの一覧として手で追いかけると保守のたびに漏れが生じます。
加えて、特定の OS でだけ壊れる変更は、`*_windows.go` のようなプラットフォーム固有のファイルの外に置かれることもあります。
共有パッケージの中でファイルパスや `file:` の URI をスラッシュ区切りで組み立てるコードは、その一例です。
Linux と macOS では動いても Windows では壊れ、これを捉えられるのは実際に Windows で流すジョブだけです。
この理由から、`windows-test` と `macos-test` は Go のコードと `go.mod`、`go.sum` のどれも変えない PR (文書、`lab/` のスクリプト、`deploy/` の設定ファイル、画像だけの変更) でだけ skip します。
`scripts/portable-test-packages.sh` も同じ契機に入れています。
このスクリプトが 2 つのジョブの対象そのものを決めるためです。

B4 と B8 が `go test` に渡す package は、スクリプトが数え上げます。
対象は、その `GOOS` でビルドできる package のうち、その環境での失敗が既に分かっているものを除いた全部です。
`go list ./...` は `//go:build linux` の付いたファイルだけからなるディレクトリを外すので、`internal/vpsd`、`internal/dataplane/linuxkernel`、`internal/platform/linux` は自然に対象から外れます。
除く package とその理由はスクリプトの中にあります。
2026-09-23 までは ci.yml が package のパスを 2 か所に直書きしており、新しい package を加えたときに一覧に入れ忘れた分が Windows と macOS で一度も走らない状態になりました。
`go test ./...` をこの 2 つのジョブで流さない理由は変えていません。
`internal/dataplane/userspace`、`internal/vpsd/store`、`tools/labhost` には、この変更より前から native Windows で落ちるテストがあり、issue #109 が記録しています。
`internal/dataplane/userspace` では `TestPrepareBindFailureIsFailClosed` が落ちます。
`internal/vpsd/store` では `TestOpenTightensExistingModesTo0600` と `TestNarrowModeKeepsOwnerBits` が落ちます。
どちらも Windows の分岐を持たずにファイルのモードを `0o600` と `0o400` に照合しており、Windows は POSIX のパーミッションのビットを保持しません。
`tools/labhost` では `TestRunLockNamesItsHolder` が落ちます。
ロックの持ち主の名前を `/proc/<pid>/comm` から読むので、POSIX ではなく Linux を前提にしており、`/proc` の無い macOS でも落ちる見込みです。
macOS で除くのは `tools/labhost` だけです。
`internal/vpsd/store` と `internal/dataplane/userspace` は、issue #109 が挙げる 3 つのテストを含めて macOS の runner で通ることを確かめました。

B5 は、前節の表の `build` の契機 (`.goreleaser.yaml`、GoReleaser のフックのスクリプト、`deploy/Dockerfile.*`、`deploy/*.compose.yaml`、`go.mod`、`go.sum`、`.github/workflows/**`) どおりに絞ります。
B5 が捉えるのは GoReleaser の設定とフック、成果物の名前の食い違いであり、通常の Go のソースの変更はここに触れません。
コードがビルドできることは `build-test` のビルドとクロスビルドの手順がすべての PR で確かめるので、`build` の契機を広げていません。

B6 は `build` の契機に加えて、Go のソースファイルの変更でも流します。
`govulncheck` は既知の脆弱性への到達可能性をコード全体の呼び出しグラフから判定するため、`go.mod` や `go.sum` を変えない Go のソースの変更だけでも、既存の脆弱な依存関係への呼び出しの経路が新しく生まれることがあります。
これは前節の表の `build` だけに絞った記述より広い判定です。

パスによる判定ができない、または信用できないときは、契機を問わずすべてを流す側に倒します。
`changes` ジョブの `paths-filter` の実行が失敗したとき、比較対象の直前のコミットが無いとき (ブランチの最初の push、force push)、`workflow_dispatch` による手動実行のとき、`.github/workflows/**` 自身を変更したとき (振り分けの仕組み自身の変更を、その仕組みに判定させないため) は、`build-test`、B4、B5、B6、B8 のすべてを流します。
B6 はこれに加えて、週に 1 回の定期実行と `workflow_dispatch` でも流します。
定期実行はコードを変えていない PR にも起きるため、この場合の失敗は外部の脆弱性の情報の変化によるものであり、コードの不具合とは限りません。
定期実行が失敗すると、GitHub はリポジトリの所有者に既定でメールを送ります。
追加の通知の仕組みや issue を起票する bot は用意していません。

netns のトポロジを組む `lab/netns.sh` は Incus に依存しないので、GitHub の runner の上で root としてラボの一式を流す案があります。
ただし、runner のカーネルの版と、runner で動く Docker が有効にする `br_netfilter` の影響が結果に混ざるので、ラボを VM に切り分けた理由 ([CLAUDE.md](../../CLAUDE.md#開発環境とテスト)) と両立するかは未確認です。
現在は採用していません。

## ラボの一式を隔てる単位

ラボの一式は、2 つの単位で隔てて流せます。
1 つは VM です。
使い捨ての VM を複数立て、確認ごとに
別の VM を割り当てます。
もう 1 つは Sandbox です。
1 台の VM を OS とカーネルを与える Lab Host
とし、その中に使い捨ての Sandbox を並べます。
Sandbox は、6 つの network namespace
(`wgft-<id>-client`、`-vps`、`-router`、`-home`、`-lan`、確認の shell 自身が動く `-runner`)、
`/tmp/wgft-lab/<id>/` の作業ディレクトリ、自分が起こしたプロセスをひとまとまりに持ちます。

network namespace は、インタフェース名、アドレス、待ち受けポート、`127.0.0.1:8686`、WireGuard
のポート、`table inet wgft`、conntrack のテーブルをすでに隔てています。
Sandbox が分けるのは、
network namespace が隔てない部分、つまり作業ディレクトリとプロセスの所有だけです。
Sandbox の
発行と後片付けは [tools/labhost](../../tools/labhost) が担い、使い方は [lab/README.md](../../lab/README.md)
にあります。

[lab/suite.txt](../../lab/suite.txt) は、確認ごとに次の 4 つの分類のどれかを持ちます。

| 分類 | 意味 |
|---|---|
| `parallel` | 他の Sandbox と同時に流せます。触るものが自分の namespace と自分の作業ディレクトリの中に閉じます |
| `exclusive-heavy` | Lab Host VM の中で単独で流します。RSS か到達頻度の測定値を主張の根拠にするため、他の確認と資源を取り合うと結果が変わります |
| `exclusive-timing` | Lab Host VM の中で単独で流します。壁時計で測る区間の中で何が起きないかを主張するため、VM を分け合うと前の段の収束が区間に食い込みます |
| `exclusive-global` | Lab Host VM の中で単独で流します。`nf_conntrack_max` のように network namespace が隔てない値を変えるため、VM の中に 1 つしかありません |

`labhost run all` は、`parallel` の確認をプールで並列に流し、そのあと `exclusive-*` の確認を
1 つずつ流します。
確認ごとの並列可否は、この文書の表に個別に書く代わりに
[lab/suite.txt](../../lab/suite.txt) の 1 か所にまとめてあります。

プールへ渡す順は [lab/suite.txt](../../lab/suite.txt) の行の順です。
suite.txt は `parallel` の確認を
所要時間の長い順に並べます。
長い確認が短い確認の後に始まると、一式の終わりがその 1 つの確認の
終わりまで延びるためです。
新しい確認は、所要時間に応じた位置に加えます。
`exclusive-*` の確認は、
並べた位置にかかわらずプールの後に流れます。

## テストの一覧

一覧の列は次の内容を示します。

- リスク:そのテストだけが捉えられる失敗を書きます
- 環境:テストを流すのに必要な機材と場所を書きます
- 契機:前節の表の契機を書きます
- 頻度:契機に当たったときに流す回数の目安を書きます
- 自動化:「自動」は判定まで機械が行い、「半自動」は実行を機械が行って結果を人が読み、「手作業」は人が操作して確かめます

「新設」の印の付いた項目は、まだ存在しないか自動化されていないテストです。
現在の実装状態と未確認の範囲は[追加テストの台帳](testing-catalog.md)にあります。

### A 類 (すべての PR)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 自動化 |
|---|---|---|---|---|---|---|
| A1 | `gofmt -l`、`go mod tidy` の差分、`go vet`、`go build ./...` | 書式の崩れ、`go.mod` の不整合、ビルドの失敗 | CI (Linux) | コードを変える PR | PR の更新ごと | 自動 |
| A2 | `go test ./...` | 単体で確かめられる退行全般 (`docs/cli.md` とヘルプの食い違いを捉える `TestCLIDocUpToDate` を含めて) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 自動 |
| A3 | Admission Policy の共有 fixture (`internal/policy/admissiontest`、`internal/policy/testdata/admission`) | nftables のコンパイラと Go の評価器の判定、drop の種類、カウンタの食い違い (7a.9 節) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 自動 |
| A4 | 計画と収束の故障注入 (`internal/planner`、`internal/reconcile` の retry、repair、drift のテスト、`internal/dataplane` の fail-closed のテスト) | Prepare、Commit の失敗の扱い、世代の前進、再試行の誤り (7a.3 節) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 自動 |
| A5 | nftables の行の生成 (`internal/dataplane/linuxkernel/nft` と `internal/policy/nftables` の単体テスト) | 行の順序、行の抜け、ルールごとの fail-closed の誤り (カーネルを使わない照合) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 自動 |
| A6 | `staticcheck` | 静的解析で分かる誤り | CI (Linux) | コードを変える PR | PR の更新ごと | 自動 |
| A7 | Windows と macOS へのクロスビルドと `go vet` | 共有のパッケージの変更で Windows、macOS のビルドが壊れること | CI (Linux) | コードを変える PR | PR の更新ごと | 自動 |
| A8 | 出力と公開ファイルの検査 (`scripts/check-japanese`、`scripts/check-ascii-punct.sh`、`scripts/check-log-tokens.sh`、`scripts/check-docs.py` とその fixture) | ツールの出力への日本語の混入、全角記号、ログへのトークンの値の出力、リンク切れ、日英の対の欠け、旧参照先の喪失 | CI (Linux) | すべての PR | PR の更新ごと | 自動 |
| A9 | ラボの一式 (L 番号のうち実装済みの確認。今は L1 から L18。モードを持つ確認は両モードで) | 領域をまたぐ変更の見落としを含む、結合したときの退行全般。関係する実装の段階の共通の完了条件 | ラボ (1 台の Lab Host VM の中で Sandbox を並列に。使い捨て VM で 1 確認 1 台の並列、1 台で順に、も残ります) | コードを変える PR、`phase`、`rc` | マージの前に 1 回 | 自動 (開発者が起動) |

### ラボの一式の内訳

| 番号 | テスト | リスク | 環境 | 開発の途中で選ぶ契機 | 頻度 | 自動化 |
|---|---|---|---|---|---|---|
| L1 | `lab/e2e.sh` (kernel と userspace) | 登録、TCP と UDP の転送、3000 バイトの UDP、PROXY protocol、deny による切断、撤去の退行 | ラボ | `relay`、`userspace`、`protocol`、`agent-platform`、`dataplane-net` | A9 として | 自動 |
| L2 | `lab/connlimit.sh` | 送信元ごとの同時フロー数の上限 (`ct count`) が実際のパケットで守られないこと、既存のフローの追い出し | ラボ | `admission`、`kernel`、`nft-emit` | A9 として | 自動 |
| L3 | `lab/rates.sh` (kernel と userspace) | 3 つのレートと `Relay` のルールのレートの実際の通過数が両モードで食い違うこと、拒否した段が後の段のトークンを使うこと、TCP のルールに `packet_rate` が効くこと | ラボ | `admission`、`nft-emit`、`relay`、`userspace` | A9 として | 自動 |
| L4 | `lab/lifecycle.sh` check 1 | server の再起動の間に kernel モードの転送と conntrack が途切れること | ラボ | `reconcile`、`kernel`、`userspace`、`protocol` | A9 として | 自動 |
| L5 | `lab/lifecycle.sh` check 2 | 無関係なルールの追加、変更、削除で既存のフローが切れること、成立済みの TCP のセッションを切ったルールが 10 秒以内に転送に戻らないこと | ラボ | `reconcile`、`rule-ops`、`kernel` | A9 として | 自動 |
| L6 | `lab/lifecycle.sh` check 3、3b | Relay の bind の失敗が nftables に漏れること、テーブルの差し替えの失敗で待ち受けが戻らないこと | ラボ | `relay`、`reconcile` | A9 として | 自動 |
| L7 | `lab/lifecycle.sh` check 4 | `server teardown` が wgft の物以外を削除すること | ラボ | `kernel`、`deploy` | A9 として | 自動 |
| L8 | `lab/lifecycle.sh` check 5、5b、5c、5d、5e、5f、5g | 上限までのフラッドでメモリがソフト上限と余裕の和を超えること (check 5 は半分の予算、5b は既定の予算)、1 本のルールへのフラッドが他のルールの最低分までの新しいフローを止めること (5c は 2 本、5d は 3 本のルール)、既定より小さい予算で隔離が崩れること (5e)、拒否の理由 `rule_cap`、`budget`、`floor`、`reserve` が実際の接続で出ないこと (5f)、分割元に残ったポートが分割元の置き換えの後も新しい接続を通せないこと (5g) | ラボ (CPU を占有できる VM) | `resource`、`userspace` | A9 として | 自動 |
| L9 | `lab/lifecycle.sh` check 6、7、8 | ルール単位の失敗が fail-closed にならないこと、backend 全体の失敗で世代が進むこと、再試行で回復しないこと | ラボ | `reconcile`、`relay` | A9 として | 自動 |
| L10 | `lab/lifecycle.sh` check 9 | 外から削除された nftables のテーブルが戻らないこと | ラボ | `kernel`、`reconcile` | A9 として | 自動 |
| L11 | `lab/split-merge.sh` (kernel と userspace) | Web UI の分割と統合で流れている UDP のセッションが切れること | ラボ | `rule-ops` | A9 として | 自動 |
| L12 | `lab/import-export.sh` (kernel と userspace) | Web UI の書き出しと読み込みの形式の食い違い、確認後の変更の見落とし | ラボ | `rule-ops` | A9 として | 自動 |
| L13 | `lab/ipv6.sh` (kernel と userspace) | IPv6 の送信元が deny をすり抜けること、IPv6 のフラッドが集約のレートのトークンを使うこと | ラボ (IPv6 を加えた netns) | `admission`、`relay` | A9 として | 自動 |
| L14 | `lab/lifecycle.sh` check 10 (kernel と userspace) | エージェントの停止後も、`agent ls` と Web UI の一覧が最後のハートビートを生きた状態のまま示すこと ([設計文書の 5.2 節](../design/overview.md#52-全体状態の配信とハートビート)) | ラボ | `rule-ops`、`protocol`、`agent-platform` | A9 として | 自動 |
| L15 | `lab/lifecycle.sh` check 11 (kernel と userspace) | エージェントの無効化がそのエージェントのルールの転送を止めないこと、他のエージェントのルールまで止めること、有効化で各ルールが自分の `enabled` に戻らないこと、有効化が bind 中のポートを拒まないこと、公開に失敗した無効化がエージェントに届かないこと ([設計文書の 5.1 節](../design/overview.md#51-登録))、無効なエージェントのルールで `server doctor` と `status` が失敗を報告すること、削除したエージェントに残ったルールの `server doctor` と `status` の結果が変わること (設計文書の [10.2a 節](../design/server-doctor.md)と[10.2b 節](../design/status.md)) | ラボ | `reconcile`、`rule-ops`、`protocol` | A9 として | 自動 |
| L16 | `lab/agentkernel.sh` check 16、17、18、19、22、24、25、resolve、drift、notify、session、route、pin、reconnect、stale、teardown (kernel と userspace) | カーネルモードのエージェントの基本の転送とルール状態の到達、停止と再起動をまたぐ成立済みフローの継続、無関係な変更や再対象化や削除でのフローの扱い、許可一覧とループバックの拒否、自ホストと他のテーブルからの隔離、MSS clamp、無効化による DNAT の撤去、名前解決の失敗時の直前アドレスへの転送継続、外部からの変更への収束と変更の通知による早期の収束、ポリシールーティングの変化の検出、サーバの乗っ取りに対する帯とアドレスの拒否、サーバの再起動をまたぐ再接続とトンネルの陳腐化への対応、`wgft agent teardown` の挙動 (設計文書の [7b 節](../design/agent-kernel.md)、[9 節](../design/state.md#9-状態の保存と再起動)、[10.3 節](../design/interface.md#103-運用の流れ)) | ラボ | `agent-platform` | A9 として | 自動 |
| L17 | `lab/agentdoctor.sh` (kernel と userspace) | `wgft agent doctor` の判定が、稼働中と停止中の切り分け、テーブルの行の欠けや変更や差し替えの見分け、`ip_forward` と wgft0 の状態、経路、無効化、呼び出し元の権限の有無による結果の違いで、カーネルモードのエージェントの実際の状態と食い違うこと ([設計文書の 10.2c 節](../design/agent-doctor.md#102c-エージェント側の診断-wgft-agent-doctor)) | ラボ | `agent-platform` | A9 として | 自動 |
| L18 | `lab/lifecycle.sh` check 12 (kernel と userspace) | ユーザー空間モードの WireGuard のソケットのバッファの条件 ([設計文書の 7 節](../design/agent-dataplane.md#7-データプレーン自宅側)) を、`agent doctor` とログが実際のソケットの値で示さないこと、条件に届かないときに `agent doctor` の終了コードが 0 でなくなること、セットアップの文書の `/etc/sysctl.d` の手順で条件を満たせないこと、`rotate-key` で開き直したソケットを測らないこと | ラボ (VM 全体の sysctl を変えるので単独で) | `userspace`、`agent-platform` | A9 として | 自動 |

L15 は server の 30 秒ごとの再試行を待つ場合に、確認の待ち時間として 40 秒を許します。
通知による早期の公開は、必ず起きる条件として扱いません。

### B 類 (関係する変更の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 自動化 |
|---|---|---|---|---|---|---|
| B1 | build tag `lab` の nftables のテスト (`lab/lab test internal/dataplane/linuxkernel/nft`。server の `table inet wgft` とエージェントの `table inet wgft_agent` のゴールデンテスト、他のテーブルを触らないこと、wg からの転送の遮断、google/nftables での読み戻し、エージェントの表の全幅までの範囲の読み込みと、network namespace の間で他のテーブルの DNAT に wgft0 から届かないこと) | 生成した式が実際のカーネルで同じ `nft list` にならないこと。エージェントの表では `nft --debug=netlink list` の式の列も比べる。大きな範囲の map の要素が欠けること。wgft0 から公開していないポートに届くこと | ラボ | `nft-emit`、`kernel`、`admission` | 契機に当たる PR ごとに 1 回 | 自動 (開発者が起動) |
| B2 | build tag `lab` の WireGuard、ホストの検査、teardown のテスト (`internal/dataplane/linuxkernel/wg`、`internal/platform/linux`、`internal/vpsd/teardown`) | 他の wg インタフェースの乗っ取り、所有の判定の誤り、他のテーブルの削除 | ラボ | `kernel`、`deploy` | 契機に当たる PR ごとに 1 回 | 自動 (開発者が起動) |
| B3 | 実際の Caddy での HTTPS の経路 ([lab/caddy/README.md](../../lab/caddy/README.md)) | PROXY protocol のヘッダを実際のリバースプロキシが読めないこと | ラボ | `relay` | 契機に当たる PR ごとに 1 回 | 手作業 |
| B4 | CI の `windows-test` (`internal/dataplane/userspace/utun` の `TestAgentServerInProcessForwarding` を含む。後述の「実機の確認を小さな回帰テストに置き換えた範囲」) | Windows でだけ通る経路 (認証情報の ACL、`LockFileEx`、UDP の待ち方) の退行と、エージェントのトンネル・中継の転送そのものの退行 (D1 の一部の置き換え) | CI (Windows の runner) | `agent-platform` | 契機に当たる PR の更新ごと | 自動 |
| B5 | CI の `release-snapshot` | GoReleaser の設定、フック、成果物の名前の食い違い | CI (Linux) | `build`、`rc` | 契機に当たる PR の更新ごと | 自動 |
| B6 | CI の `govulncheck` | 依存するモジュールの既知の脆弱性 | CI (Linux) | `build`、`rc`、週に 1 回の定期実行 | 契機に当たる PR の更新ごと。定期実行は週に 1 回 | 自動 |
| B7 | `lab/version-skew.sh` | 旧 agent と新 server、新 agent と旧 server、legacy v0 の agent と新 server の組で、登録、全体状態の配信、転送、再接続が壊れること。旧い側には、直前のリリースと、agent の無効化より前の最後のリリースである v1.1.3 の 2 つを使う。旧い側が表せない機能のルールを理由付きの `not_active` にすること (7a.6 節) は、該当する capability がまだ無いため確認を SKIP する。新しい server と旧い agent の組では、agent の無効化で転送が止まらないこと、有効化で転送が戻らないこと、無効化が VPS 側だけにとどまり旧い agent 自身に届かないこと、`agent ls`、`status`、`server doctor` が無効を示さないこと、無効化の間に旧い agent が落ちたり再接続を繰り返したりすること (5.1 節)。v1.1.3 の agent との組は、無効化を知らない agent が `enabled:false` の写しで止まらないことを検出する。直前のリリースの server と新しい agent の組でも、その server の CLI で無効化と有効化をしたときの同じ失敗を検出する。v1.1.3 の server は無効化を持たないので、この組では無効化の確認を SKIP する | ラボ (直前のリリース、v1.1.3、legacy v0 のバイナリを GitHub の Releases から取得してキャッシュする。ラボの VM から GitHub への経路が無い場合は、バイナリを事前に置く。直前のリリースの版はスクリプトの定数を既定とし、環境変数 `WGFT_SKEW_OLD_VERSION` で上書きできる。定数が直前のリリースより古いまま流すときは、この変数で直前のリリースを明示する) | `protocol`、`rc` | 契機に当たる PR ごとと、リリース候補ごとに 1 回 | 自動 (開発者が起動) |
| B8 | CI の `macos-test` (`internal/dataplane/userspace/utun` の `TestAgentServerInProcessForwarding` を含む) | macOS でだけ通る経路 (UDP の送信バッファの既定 9216 バイトを超えるデータグラムの書き込み) の退行 (D2 の一部の置き換え。後述の「実機の確認を小さな回帰テストに置き換えた範囲」) | CI (macOS の runner) | `agent-platform`、`rc` | 契機に当たる PR の更新ごと | 自動 |
| B9 | 配布物の VM 試験 (`scripts/dist-vm.sh`) | 同梱の unit で起動しないこと、VM の再起動の後に転送が戻らないこと、設定の誤りで再起動を繰り返すこと | 2 台の VM (server と agent) | `deploy`、`rc` | 契機に当たる PR ごとに 1 つのディストリビューションで、リリース候補ごとに 3 つのディストリビューションで | 自動 (開発者が起動) |
| B10 | Docker のイメージの疎通 (`scripts/docker-smoke.sh`) | `deploy/Dockerfile.*` から作ったイメージで server と agent が動かないこと | Docker か Podman のある Linux (ホスト、CI の runner、ラボの VM のどれでも可) | `build`、`rc` | 契機に当たる PR ごとと、リリース候補ごとに 1 回 | 自動 (開発者が起動) |
| B11 | `lab/rcvwin.sh` | ユーザー空間モードの中継で、`vpsd` の公開側のカーネルの TCP ソケットが、穴の後ろの順序外のデータとして floor を超える受信のメモリを持ったまま boost の枠を返すこと。穴が埋まった後に、その枠が別の接続へ戻らないこと ([設計文書の 7 節](../design/agent-dataplane.md#7-データプレーン自宅側)) | ラボ | `resource`、`userspace` | 契機に当たる PR ごとに 1 回 | 自動 (開発者が起動) |
| B12 | `lab/lab test internal/nettun vps -test.run='^(TestRelayHold|TestSetupFailure)OutOfOrderKernelData$'` | 中継終了時と中継開始前の通常の失敗で、カーネル TCP ソケットの順序外の受信メモリが、フローと送信元ごとの枠を返した後にも残ること | 使い捨て VM の隔離した network namespace | `resource`、`userspace` | 契機に当たる PR ごとに 1 回 | 自動 (開発者が起動) |

B9 は、リリース候補ごとに Debian 12、Ubuntu 24.04、Fedora 44 の 3 つで実行します。
`deploy/agent.kernel.conf` を変える PR は、B9 を `scripts/dist-vm.sh --agent-kernel` で実行します。
この追加の経路は過去に Debian 12 で確認しましたが、Ubuntu 24.04 と Fedora 44 では未確認です。

### C 類 (段階の完了の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 自動化 |
|---|---|---|---|---|---|---|
| C1 | 悪い条件のネットワーク (新設) | 損失、遅延、小さい経路 MTU と ICMP の遮断、自宅側のアドレスの変化で、トンネルと転送が回復しないこと | ラボ (netns に `tc netem` と経路の変更を加える) | `phase`、`dataplane-net` | 関係する変更 (network dataplane) を含む段階の完了時 | 自動 (新設) |
| C2 | クラッシュと強制停止からの収束 (新設) | Prepare と Commit の間での強制終了や VM の強制停止の後に、宣言した状態へ収束しないこと | ラボ | `phase`、`reconcile` | 関係する変更 (収束の仕組み) を含む段階の完了時 | 自動 (新設) |
| C3 | 規模の試験 | ルール数とエージェント数が多いときの適用時間、テーブルの差し替え、全体状態の大きさの問題 | ラボ | `phase` | 段階の完了ごとに 1 回 | 自動 (開発者が起動) |
| C4 | ラボの一式を別のディストリビューションで | カーネルと nftables の版の違いによる挙動の違い (通知、`ct count`、式の表記) | ラボ (`WGFT_LAB_IMAGE` で別のイメージの VM) | `phase`、`kernel` | 関係する変更 (kernel 側の経路) を含む段階の完了時 | 自動 (開発者が起動。Fedora の SELinux enforcing と firewalld 有効の条件は未確認) |
| C5 | 長時間の TCP と UDP (新設) | 通常の WireGuard のセッションの鍵の更新、ハートビート、conntrack の期限をまたいで長いセッションが切れること。`agent rotate-key` の後に新しい通信が戻らないこと | ラボ | `phase`、`resource`、`dataplane-net` | 関係する変更 (Resource Guard、network dataplane) を含む段階の完了時 | 自動 (新設) |
| C6 | 小さいメモリの環境 (新設) | 上限を下げた設定と 256 MiB に制限したメモリで、フラッドの下で server が OOM で落ちること | ラボ (メモリを制限した cgroup) | `phase`、`resource`、`dataplane-net` | 関係する変更 (Resource Guard、network dataplane) を含む段階の完了時 | 自動 (新設) |

### D 類 (リリース候補の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 自動化 |
|---|---|---|---|---|---|---|
| D1 | Windows のエージェントの smoke (手作業) | リリースのバイナリが Windows で登録、転送、再接続、状態の保持に失敗すること | Windows の VM か Windows の実機 | `rc` | リリース候補ごとに 1 回 | 手作業。自動化は未実装 |
| D2 | macOS のエージェントの smoke (手作業) | リリースのバイナリが Apple シリコンの Mac で登録、転送、再接続、launchd での起動に失敗すること | Mac の実機 | `rc` | リリース候補ごとに 1 回 | 手作業 |
| D3 | リリースの成果物と署名の検証 | 成果物の欠け、`wgft version` の表記の誤り、`gh attestation verify` の失敗、GHCR のイメージの欠け | リリースの後の GitHub と GHCR | `rc` (タグの後) | リリースごとに 1 回 | 半自動 (成果物の名前は B5 が確かめる) |
| D4 | `lab/upgrade.sh`、`scripts/dist-vm.sh --upgrade` | 選んだ旧版のデータベースと認証情報を現在のビルドが読めないこと、更新の間にルール・鍵・認証情報が変わること、片側だけを先に更新した組み合わせで転送が止まること、docs/manual/setup.md の手順で導入した VM でバイナリだけを入れ替え、同梱の unit を再起動し、VM も再起動する経路で転送が戻らないこと。`lab/upgrade.sh` の既定の v1.1.3 のデータは agent の無効化 (5.1 節) より前のものなので、更新した直後に既存の agent が無効として扱われて転送が止まること、更新の後に無効化した状態が server の再起動で失われること | ラボ (選んだ旧版のバイナリを GitHub の Releases から取得してキャッシュする) と、2 台の使い捨て VM (`scripts/dist-vm.sh` 自身の環境。直前のリリースのバイナリはホストで取得し、VM には push するだけです) | `rc` | リリース候補ごとに 1 回 | 自動 (開発者が起動) |

### E 類 (手作業と実機の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 自動化 |
|---|---|---|---|---|---|---|
| E1 | 実 VPS での導入、再起動、撤去 | 実際のクラウドのイメージ (最小構成、ホストのファイアウォール、`flush ruleset` で始まる設定) で手順どおりに動かないこと | 試験用の実 VPS と自宅の Linux のエージェント | `manual-release`、`deploy`、`kernel` | 契機に当たるとき | 手作業 |
| E2 | 実回線の自宅ルータと NAT | CGNAT や IPv4 over IPv6 の回線、経路 MTU の小さい回線で登録とトンネルが成り立たないこと | 実回線と実際の自宅ルータ | `manual-release`、`dataplane-net` | 契機に当たるとき | 手作業 |
| E3 | 実回線での WAN のアドレスの変化 | 回線の再接続でアドレスが変わった後に、エージェントが戻らないこと、窃取の検知が誤って働くこと | 実回線 | `manual-release`、`protocol` | 契機に当たるとき | 手作業 |
| E4 | Windows の実機での利用 | スリープと復帰、ネットワークアダプタの無効と有効、Wi-Fi の再接続の後に戻らないこと | Windows の実機 | `manual-release`、`agent-platform` | 契機に当たるとき | 手作業 |
| E5 | Mac の実機での利用 | スリープと復帰、Wi-Fi やインタフェースの変化、再起動の後に戻らないこと | Mac の実機 | `manual-release`、`agent-platform` | 契機に当たるとき | 手作業 |
| E6 | 実アプリケーションでの長時間の利用 | 実際の利用者の通信で数日単位に現れる切断、メモリの増加、ログの異常 | 実 VPS と実アプリケーション | `manual-release`、`dataplane-net`、`resource` | 契機に当たるとき | 手作業 (外からの疎通の確認は機械でもできる) |

### F 類 (調査だけの実験)

| 番号 | 実験 | 得たい根拠 | 環境 | 契機 | 頻度 | 置き換え先の回帰テスト |
|---|---|---|---|---|---|---|
| F1 | conntrack のメモリの費用の実測 (実施済み) | 65536 という推奨値が小さいメモリの環境でも非現実的でないことの設計の根拠 (7a.10 節) | ラボ | 対応するカーネルの範囲の変更 | 対応するカーネルの範囲の変更時 | 診断の文言にメモリの値が含まれないことの単体テスト (未実装) |
| F2 | 毎秒 4000 接続以上の負荷 | 拒否の経路の費用が高い接続の頻度でも一定であること | ラボ (CPU を占有できる VM) | 根拠が要るとき | 1 回 | L8 (到達できる頻度でのフラッド) |
| F3 | netlink の ENOBUFS の強制 | 通知の取りこぼしの後に購読を張り直して Observe すること | ラボ | 根拠が要るとき | 1 回 | 購読の失敗を模した単体テスト (未実装) と L10 |
| F4 | カーネルの版による通知の違い | 版ごとに nftables と rtnetlink の通知の出方が違うかどうか | 版の違う VM | 根拠が要るとき | 1 回 | C4 での L10 |
| F5 | メモリと CPU のプロファイル | フロー 1 本の費用、拒否した接続が残すメモリ | ラボ、実機 | 根拠が要るとき | 1 回 | L8 とメモリのソフト上限の計算式の単体テスト |
| F6 | パケットキャプチャによる調査 | 不具合の原因の特定 | ラボ、実機 | 不具合の調査 | 必要なとき | 不具合を再現するラボの確認 |
| F7 | スループットの測定 | 転送の速さの目安 | ラボ、実機 | 性能の報告を受けたとき | 必要なとき | 無し (性能の約束を文書に書いていないため) |
| F8 | トークンバケットの補充の境界と meter の期限 | 7a.9 節の許容差のうち未確認の点 | ラボ | 根拠が要るとき | 1 回 | A3 の fixture (補充の時刻から 10% 以上離して出来事を置く) |


## 更新と戻しの約束

更新の経路は保証します。
旧版への戻しは互換性の保証に含めず、各版で観測した挙動だけを記録します。
戻す必要があるときは、更新の前に取ったデータの置き場のバックアップから戻します。
戻しを約束すると、サーバのデータベースのスキーマ、migration、知らないフィールドの保存、状態ファイル、wire protocol の変更を、旧い版が読める形に永久に縛るためです ([設計文書](../design/internals.md#7a6-維持する外部仕様と互換性) 7a.6 節)。
D4 はこの約束に従い、更新を確かめ、戻しについては挙動を記録するだけにします。


## 高価な実験を小さな回帰テストへ置き換える規則

F 類の実験と、C 類から E 類の高価な確認は、次の規則で小さな回帰テストに置き換えます。

1. 実験の目的は仕様の根拠を得ることなので、根拠を得たら実験を終えます。
結果の要約、設計への影響、未確認の点は PR に記載し、現在の仕様に必要な理由と制約は該当する設計に反映します ([文書の更新手順](documentation.ja.md#更新の時点))。
2. 根拠のうち、今後のコードの変更で崩れうるものだけを回帰テストにします。
コードの変更で崩れない性質 (カーネルの定数、特定の機器の性能) は回帰テストにしません
3. 回帰テストは、崩れうる性質を確かめられる最も安い環境に置きます。
安い順に、ホストの単体テスト (A1 から A8)、ラボの一式の 1 つの確認 (L 番号)、ラボの一式の外の確認 (B 類)、複数の VM や実機の確認 (C 類から E 類) です
4. 回帰テストは、実験の測定値そのものではなく、測定値から決めた上限や判定を確かめます。
中継のフロー 1 本のメモリの費用を調べるプロファイル (F5) を例に取ると、回帰テストは測定のやり直しではなく、上限までのフラッドで RSS がソフト上限と余裕の和の内側にあることの確認 (L8) です
5. 同じ実験をやり直すのは、根拠の前提 (カーネルの版、依存するライブラリ、設計の決定) が変わったときだけです

各実験の置き換え先は、F 類の表の「置き換え先の回帰テスト」の列にあります。
E 類の実機の確認で見つかった不具合も同じ規則に従い、再現できる範囲を A 類か B 類のテストにします。
macOS の UDP の送信バッファの不具合を relay の単体テストで扱い、そのテストを B8 で macOS の runner に流すのがこの規則の例です。

## 旧見出しの参照先

移動した節への旧リンクは維持します。

<a id="v1-の項目と繰り返しの頻度"></a>
[v1 の項目と繰り返しの頻度](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/testing.md#v1-の項目と繰り返しの頻度)

<a id="新設と自動化が未了の項目"></a>
[新設と自動化が未了の項目](testing-catalog.md#実装状態と確認範囲)

<a id="b7-の-not_active-の確認"></a>
[B7 の not_active の確認](testing-catalog.md#b7-の-not_active-の確認)

<a id="c1-悪い条件のネットワーク"></a>
[C1 悪い条件のネットワーク](testing-catalog.md#c1-悪い条件のネットワーク)

<a id="c2-クラッシュと強制停止からの収束"></a>
[C2 クラッシュと強制停止からの収束](testing-catalog.md#c2-クラッシュと強制停止からの収束)

<a id="c3-規模の試験"></a>
[C3 規模の試験](testing-catalog.md#c3-規模の試験)

<a id="c4-ラボの一式を別のディストリビューションで"></a>
[C4 ラボの一式を別のディストリビューションで](testing-catalog.md#c4-ラボの一式を別のディストリビューションで)

<a id="c5-長時間の-tcp-と-udp"></a>
[C5 長時間の TCP と UDP](testing-catalog.md#c5-長時間の-tcp-と-udp)

<a id="c6-小さいメモリの環境"></a>
[C6 小さいメモリの環境](testing-catalog.md#c6-小さいメモリの環境)

<a id="d1-と-d2windows-と-macos-のエージェントの-smoke"></a>
[D1 と D2:Windows と macOS のエージェントの smoke](testing-catalog.md#d1-と-d2windows-と-macos-のエージェントの-smoke)

<a id="d4-の残りの項目-実装済み"></a>
[D4 の残りの項目 (実装済み)](testing-catalog.md#d4-旧版からの更新)

<a id="f1-conntrack-のメモリの費用の実測"></a>
[F1 conntrack のメモリの費用の実測](testing-catalog.md#f1-conntrack-のメモリの費用の実測)

<a id="e-類の手作業の確認"></a>
[E 類の手作業の確認](testing-catalog.md#e-類の手作業の確認)

<a id="windows-と-macos-のエージェント"></a>
[Windows と macOS のエージェント](testing-platforms.md#windows-と-macos-のエージェント)

<a id="windows-のエージェントの-smoke-の内容"></a>
[Windows のエージェントの smoke の内容](testing-platforms.md#windows-のエージェントの-smoke-の内容)

<a id="macos-のエージェントの-smoke-の内容"></a>
[macOS のエージェントの smoke の内容](testing-platforms.md#macos-のエージェントの-smoke-の内容)

<a id="実機の確認を小さな回帰テストに置き換えた範囲"></a>
[実機の確認を小さな回帰テストに置き換えた範囲](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/testing.md#実機の確認を小さな回帰テストに置き換えた範囲)
