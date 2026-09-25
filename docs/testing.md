# テストの分類と実行の契機

wgft のテストは、実行の費用、所要時間、必要な機材、再現性によって A から F の 6 類に分かれます。どの類に置くかは、そのテストだけが捉えられる失敗と、そのテストの費用との釣り合いで決めます。「大事なテストなので毎回流す」という理由では類を決めません。ただし、ラボの一式は費用が小さいので、コードを変える PR ではマージの前にすべてを流します (次節)。

## 類の定義

- A 類 (すべての PR):数分で終わり、結果の再現性が高く、日常の退行を捉えるテストです。CI の検査はすべての PR で、ラボの一式はコードを変える PR のマージの前に流します
- B 類 (関係する変更の関門):ラボの一式に含まれず、特定の領域を変えた PR とリリースの候補でだけ流すテストです。どの変更がどのテストを流すかは、後述の「変更の契機と対象のパス」の表で決まります
- C 類 (段階の完了の関門):[設計文書](design.md) 7a.8 節の段階 (Phase 5、6、7 など) を終えるときに流すテストです。悪い条件のネットワーク、クラッシュからの回復、別のディストリビューションでのラボの一式、長時間の通信、小さいメモリの環境を含みます。v1 の前に一度流し、以後は関係する変更を含む段階の完了時に流し直す項目は、この類に置きます
- D 類 (リリース候補の関門):リリースの候補の版ごとに流すテストです。Windows と macOS のエージェント、旧版からの更新、リリースの成果物を確かめます
- E 類 (手作業と実機の関門):実 VPS、実回線の自宅ルータ、Windows と Mac の実機、実アプリケーションでの長時間の利用のように、再現用の環境では作れない条件を人が確かめる関門です
- F 類 (調査だけの実験):回帰テストに含めない実験です。仕様の根拠 (測定値や挙動の確認) を得たら、必要な範囲だけを小さな回帰テストに置き換え、高価な実験そのものは繰り返しません

v1 に必須の項目には、繰り返しの頻度として「リリース候補ごと」か「v1 の前に 1 回、以後は関係する変更で」のどちらかを付けます (後述の「v1 の項目と繰り返しの頻度」)。

「新設」と記した項目は、実装されるまではマージの関門に含めません。実装された時点から、表の契機を適用します。ただし、v1 に必須の新設の項目は、v1.0 のリリース候補を作る前までに実装か実施を完了します。存在しないテストを関門にすると、どの PR も関門を満たせなくなるためです。

## 壁時計で測る区間を使うテストの規範

テストは「N 秒待てば足りる」という想定だけでは書きません。まず状態が届き収束したことを確認してから、観察の区間に入ります。何も起きないことを主張する否定の主張は区間そのものを必要とするので、この規範は区間を禁じません。求めるのは、区間に入る前に収束を確認することです。待ちの上限 (budget) は残します。上限は待ちすぎを防ぐ道具であり、主張の根拠ではないからです。

収束を確認しないまま区間に入ると、直前の操作の収束がまだ終わっておらず、その残りが区間の途中で観測されて無関係な失敗に見えます。

## マージの前に流すテスト

コードを変える PR は、マージの前にラボの一式 (A9) を両モードで流します。ラボの一式は、ラボの一式の内訳 (L 番号) のうち実装済みの確認の集まりで、今は L1 から L17 です。流し方は、1 台の Lab Host VM の中で `labhost run -parallel 8 all` を実行することです。この 1 コマンドが、両モードの確認と、分類に従った並列と単独の振り分けを含みます。文書だけを変える PR は、ラボを流しません。CI の検査のうち A8 は、どちらの PR でも流します。A1 から A7 は、Markdown の文書と `docs/images/` の画像だけを変える PR では流しません。

コードは、実行時の挙動かテストの結果を変えうるすべての変更を指します。Go のコード (`go.mod`、`go.sum` を含む)、`deploy/`、`lab/` 自身、設定と dotenv の扱い、`scripts/`、`.goreleaser.yaml`、`.github/workflows/` がこれに当たります。変更がコードに当たらないのは、Markdown とテキストの文書 (README、`docs/` の文書とその画像) だけです。`docs/cli.md` はヘルプから生成するので、ヘルプを変えた PR は Go のコードを変える PR です。

変更の領域ごとに流すテストを選ぶ仕組みを持たずに、コードを変えたらすべてを流す規則にする理由は、ラボの一式が安いためです。1 台の Lab Host VM の中で Sandbox を並列に流すと、ラボの一式は 約 10 分以内 (既定の 2 vCPU / 2 GiB の Lab Host VM で並列数 8 のときの実測は、L15 を加える前で 338 秒、L16 と L17 を加えた後で 600 秒。加わった `lab/agentkernel.sh` の一部の組が、他の確認より長い 3 分から 5 分近くかかるため)で終わり、人の操作を要しません。この費用であれば、変更の領域とテストの対応を保守して選ぶよりも、すべてを流す規則のほうが単純で、対応の漏れによる見落としもありません。ラボの一式の所要時間が大きく伸びた場合は、この規則を見直します。

B 類の契機は、ラボの一式に含まれないテスト (B 類の一覧のうち実装済みのもの) を選ぶためと、開発の途中でラボの確認を流し直すときに、変えた領域の確認だけを選ぶために使います。開発の途中の選び方は、後述の「ラボの一式の内訳」の表の契機の列にあります。

## 変更の契機と対象のパス

次の表の契機に当たるパスを PR が変えたときは、B 類の列のテストのうち実装済みのものを流します。新設の B 類は、実装されるまで契機に当たっても流しません。1 つのパスが複数の契機に当たる場合は、当たる契機のテストをすべて流します。ラボの一式の列は、開発の途中で流し直す確認を選ぶための目安で、マージの前にはラボの一式のすべてを流します。

| 契機 | 対象のパス | B 類 | ラボの一式のうち開発の途中で選ぶ確認 |
|---|---|---|---|
| `nft-emit` | `internal/policy/nftables/**`、`internal/dataplane/linuxkernel/nft/**`、`internal/policy/*.go`、`internal/planner/**` | B1 | L2、L3 (kernel モード) |
| `kernel` | `internal/dataplane/linuxkernel/**`、`internal/platform/linux/**`、`internal/vpsd/teardown.go`、`lab/netns.sh`、`lab/lab` | B1、B2 | L2、L4、L5、L7、L10 (kernel モード) |
| `admission` | `internal/policy/**`、`proto/rate.go`、`proto/source.go` | B1 | L2、L3、L13 |
| `resource` | `internal/resource/**`、`internal/lograte/**`、`internal/dataplane/userspace/**`、`internal/netpipe/**`、`internal/nettun/**`、`cmd/wgft/limits.go` | 無し (C5 と C6 は次の段階の完了時に流し直す) | L8 (両モード) |
| `reconcile` | `internal/reconcile/**`、`internal/planner/**`、`internal/model/**`、`internal/dataplane/*.go`、`internal/vpsd/apply.go`、`internal/vpsd/watch.go`、`internal/vpsd/dataplane*.go` | 無し (C2 は次の段階の完了時に流し直す) | L4、L5、L6、L9、L10、L15 (両モード) |
| `relay` | `internal/vpsd/proxyrelay/**` | B3 | L1、L3、L6、L9、L13 |
| `userspace` | `internal/dataplane/userspace/**`、`internal/nettun/**`、`internal/netpipe/**`、`internal/agent/**` | 無し | L1、L3、L4、L8 (userspace モード) |
| `rule-ops` | `internal/vpsd/admin/**`、`internal/vpsd/agent_disable.go`、`proto/rule.go`、`proto/splitmerge.go`、`proto/importdiff.go`、`cmd/wgft/rule.go` | 無し | L5、L11、L12、L14、L15 (両モード) |
| `protocol` | `proto/stream.go`、`proto/state.go`、`proto/version.go`、`internal/vpsd/stream/**`、`internal/vpsd/agentapi/**`、`internal/agent/**` | B7 | L1、L4、L14、L15 |
| `agent-platform` | `internal/agent/**`、`internal/flock/**`、`internal/dataplane/userspace/relay/**`、`internal/dataplane/userspace/tunnel/**`、`cmd/wgft/**`、`*_windows.go`、`*_darwin.go` | B4、B8 | L1、L14、L16、L17 |
| `deploy` | `deploy/*.service`、`deploy/*.conf`、`deploy/*.plist`、`deploy/server.env.example`、`cmd/wgft/config.go`、`cmd/wgft/server.go`、`cmd/wgft/agent.go` (設定の読み込みと終了コード) | B2、B9 | L7 |
| `build` | `.goreleaser.yaml`、`scripts/build-release.sh`、`scripts/goreleaser-checksum.sh`、`scripts/third-party-licenses.sh`、`scripts/check-release-assets.sh`、`scripts/docker-smoke.sh`、`deploy/Dockerfile.*`、`deploy/*.compose.yaml`、`go.mod`、`go.sum`、`.github/workflows/**` | B5、B6、B10 | 無し |
| `dataplane-net` | `internal/dataplane/**`、`internal/nettun/**`、`internal/netpipe/**`、`internal/agent/**` の転送の経路 | 無し (C1 と C5 は次の段階の完了時に流し直す) | L1 |
| `phase` | 7a.8 節の段階の完了 | C 類 | すべて |
| `rc` | リリースの候補の版 | 「リリース候補ごと」の項目 | すべて |
| `manual-release` | 「v1 の前に 1 回」の項目を関係する変更の後に流し直すとき | E 類の該当する項目 | 無し |

表の対象のパスは、実装の移動 (7a.7 節の package 配置) に合わせて改めます。

## CI とラボの関係

CI (`.github/workflows/ci.yml`) は、ホストで完結する A1 から A8 と、B 類のうち GitHub の runner で動くものを、変更の内容に応じて流します。ラボの結合テストは Incus の VM を必要とするので、CI では流しません ([CLAUDE.md](../CLAUDE.md) の「テストの分け方」)。ラボの一式 (A9) と、ラボを使う B 類は、PR を出す開発者がラボで流し、その結果を PR の本文に書きます。

ラボのスクリプトは、どれも自分で server、エージェント、宛先を立てて片付けるので、互いに独立しています。この独立性があるので、ラボの一式は並列に流せます。既定の流し方は、1 台の Lab Host VM の中に Sandbox を並べる [tools/labhost](../tools/labhost) です。`labhost run -parallel N all` は、前節の `parallel` な確認をプールで並列に流し、そのあと `exclusive-*` な確認を 1 つずつ流します。1 台の Lab Host VM で一式を流すと 約 10 分以内 (既定の 2 vCPU / 2 GiB の Lab Host VM で並列数 8 のときの実測は、L15 を加える前で 338 秒、L16 と L17 を加えた後で 600 秒)かかります。複数の使い捨て VM に分けて流す道具もあり、8 台で約 2.5 分に縮みますが、リポジトリには含めていません。`lab/lab` は `WGFT_LAB_VM` で VM の名前を変えられるので、同じ仕組みで複数の VM を立てられます。どちらの道具も使わない開発者は、1 台の VM で確認を 1 つずつ順に流せます。その場合は 10 分以上かかります。`lab/lifecycle.sh` の check 5、5b、5c、5d、5e と `rates.sh` はどれもフラッドで CPU を使うので、複数の VM に分ける流し方では他の VM と CPU を取り合わない VM で流し、Sandbox で流す場合は `exclusive-heavy` の分類が単独の実行に振り分けます。

開発の途中でラボの確認を流し直すときは、`lab/lifecycle.sh` に確認の番号を指定して、その確認だけを流せます (`lab/lab exec vm bash /wgft/lab/lifecycle.sh kernel 3 3b`)。

CI は、`build-test` (A1 から A7)、B4 (`windows-test`)、B5 (`release-snapshot`)、B6 (`govulncheck`)、B8 (`macos-test`) を、変更の内容に応じてだけ流します。振り分けは `.github/workflows/ci.yml` の `changes` という 1 つのジョブが担い、`dorny/paths-filter` で変更されたパスを調べます。振り分けはワークフロー全体の `paths:` ではなく、ジョブごとの `if:` で行います。ワークフローの `paths:` で絞ると、当たらない PR ではジョブそのものが実行されず、GitHub の checks の一覧に現れません。ブランチ保護がこれらを必須の check にした場合、現れない check はいつまでも待ち続け、マージを永久に塞ぎます。ジョブごとの `if:` であれば、当たらない PR でもジョブは実行され、内容を飛ばして skipped で終わります。GitHub は skipped のジョブを必須の check の合格として扱うため、マージを塞ぎません。

`build-test` の絞り方は、他のジョブと向きが逆です。他のジョブは流す条件をパスの一覧で数え上げますが、`build-test` は skip する条件を数え上げます。A1 から A7 の検査が見るのは Go のソース、`go.mod`、`go.sum`、および Go のテストが読むファイルだけなので、Markdown の文書と `docs/images/` の画像だけを変えた PR では結果が変わりません。`changes` ジョブは変更されたパスの一覧を受け取り、一覧のすべてが Markdown の文書か `docs/images/` の画像であるときにだけ `build-test` を skip します。当てはまらないパスが 1 つでも混じれば流します。`docs/cli.md` は Markdown ですが、`cmd/wgft/helptext.go` から生成して `TestCLIDocUpToDate` が照合するので、文書としては扱いません。

向きを逆にした理由は、A2 の `go test ./...` が Go 以外のファイルも読むことにあります。読み取りの対象は `docs/cli.md`、`internal/vpsd/admin` が `go:embed` で取り込む Web UI のテンプレートと静的ファイル、`tools/labhost` の `suite_test.go` が読む `lab/suite.txt`、`internal/policy` と `internal/dataplane/linuxkernel/nft` の `testdata` です。流す条件を数え上げる書き方では、後から加わった読み取り先が漏れて、検査が静かに skip されます。skip する条件を数え上げる書き方では、一覧に無いパスはすべて流す側に倒れます。

B4 と B8 は、前節の表の `agent-platform` の契機どおりには絞りません。`agent-platform` の契機は、CI では再現できない実機の確認 (D1、D2、E4、E5) の定義としてそのまま残しますが、`windows-test` と `macos-test` は、Go のソースファイル (`*.go`) 1 つでも、`go.mod`、`go.sum` のどちらかでも変えた PR で流します。理由は、この 2 つのジョブが実行する `cmd/wgft` と `internal/agent` などのテストの一式が、実際のサーバのデータベースや admin backend を組み立てるためです。組み立てに使う依存は `internal/vpsd/store`、`internal/vpsd/admin`、`proto`、`internal/model`、`internal/policy`、`internal/resource`、`internal/nettun` など広い範囲に及び、パスの一覧として手で追いかけると保守のたびに漏れが生じます。加えて、特定の OS でだけ壊れる変更は、`*_windows.go` のようなプラットフォーム固有のファイルの外に置かれることもあります。共有パッケージの中でファイルパスや `file:` の URI をスラッシュ区切りで組み立てるコードは、その一例です。Linux と macOS では動いても Windows では壊れ、これを捉えられるのは実際に Windows で流すジョブだけです。この理由から、`windows-test` と `macos-test` は Go のコードと `go.mod`、`go.sum` のどれも変えない PR (文書、`lab/` のスクリプト、`deploy/` の設定ファイル、画像だけの変更) でだけ skip します。`scripts/portable-test-packages.sh` も同じ契機に入れています。このスクリプトが 2 つのジョブの対象そのものを決めるためです。

B4 と B8 が `go test` に渡す package は、スクリプトが数え上げます。対象は、その `GOOS` でビルドできる package のうち、その環境での失敗が既に分かっているものを除いた全部です。`go list ./...` は `//go:build linux` の付いたファイルだけからなるディレクトリを外すので、`internal/vpsd`、`internal/dataplane/linuxkernel`、`internal/platform/linux` は自然に対象から外れます。除く package とその理由はスクリプトの中にあります。2026-09-23 までは ci.yml が package のパスを 2 か所に直書きしており、新しい package を加えたときに一覧に入れ忘れた分が Windows と macOS で一度も走らない状態になりました。`go test ./...` をこの 2 つのジョブで流さない理由は変えていません。`internal/dataplane/userspace`、`internal/vpsd/store`、`tools/labhost` には、この変更より前から native Windows で落ちるテストがあり、issue #109 が記録しています。`internal/dataplane/userspace` では `TestPrepareBindFailureIsFailClosed` が落ちます。`internal/vpsd/store` では `TestOpenTightensExistingModesTo0600` と `TestNarrowModeKeepsOwnerBits` が落ちます。どちらも Windows の分岐を持たずにファイルのモードを `0o600` と `0o400` に照合しており、Windows は POSIX のパーミッションのビットを保持しません。`tools/labhost` では `TestRunLockNamesItsHolder` が落ちます。ロックの持ち主の名前を `/proc/<pid>/comm` から読むので、POSIX ではなく Linux を前提にしており、`/proc` の無い macOS でも落ちる見込みです。macOS で除くのは `tools/labhost` だけです。`internal/vpsd/store` と `internal/dataplane/userspace` は、issue #109 が挙げる 3 つのテストを含めて macOS の runner で通ることを確かめました。

B5 は、前節の表の `build` の契機 (`.goreleaser.yaml`、GoReleaser のフックのスクリプト、`deploy/Dockerfile.*`、`deploy/*.compose.yaml`、`go.mod`、`go.sum`、`.github/workflows/**`) どおりに絞ります。B5 が捉えるのは GoReleaser の設定とフック、成果物の名前の食い違いであり、通常の Go のソースの変更はここに触れません。コードがビルドできることは `build-test` のビルドとクロスビルドの手順がすべての PR で確かめるので、`build` の契機を広げていません。

B6 は `build` の契機に加えて、Go のソースファイルの変更でも流します。`govulncheck` は既知の脆弱性への到達可能性をコード全体の呼び出しグラフから判定するため、`go.mod` や `go.sum` を変えない Go のソースの変更だけでも、既存の脆弱な依存関係への呼び出しの経路が新しく生まれることがあります。これは前節の表の `build` だけに絞った記述より広い判定です。

パスによる判定ができない、または信用できないときは、契機を問わずすべてを流す側に倒します。`changes` ジョブの `paths-filter` の実行が失敗したとき、比較対象の直前のコミットが無いとき (ブランチの最初の push、force push)、`workflow_dispatch` による手動実行のとき、`.github/workflows/**` 自身を変更したとき (振り分けの仕組み自身の変更を、その仕組みに判定させないため) は、`build-test`、B4、B5、B6、B8 のすべてを流します。B6 はこれに加えて、週に 1 回の定期実行と `workflow_dispatch` でも流します。定期実行はコードを変えていない PR にも起きるため、この場合の失敗は外部の脆弱性の情報の変化によるものであり、コードの不具合とは限りません。定期実行が失敗すると、GitHub はリポジトリの所有者に既定でメールを送ります。追加の通知の仕組みや issue を起票する bot は用意していません。

netns のトポロジを組む `lab/netns.sh` は Incus に依存しないので、GitHub の runner の上で root としてラボの一式を流す案があります。ただし、runner のカーネルの版と、runner で動く Docker が有効にする `br_netfilter` の影響が結果に混ざるので、ラボを VM に切り分けた理由 (CLAUDE.md の「開発用ラボの立て方」) と両立するかは未確認です。v1 では採りません。

## ラボの一式を隔てる単位

ラボの一式は、2 つの単位で隔てて流せます。1 つは VM です。使い捨ての VM を複数立て、確認ごとに
別の VM を割り当てます。もう 1 つは Sandbox です。1 台の VM を OS とカーネルを与える Lab Host
とし、その中に使い捨ての Sandbox を並べます。Sandbox は、6 つの network namespace
(`wgft-<id>-client`、`-vps`、`-router`、`-home`、`-lan`、確認の shell 自身が動く `-runner`)、
`/tmp/wgft-lab/<id>/` の作業ディレクトリ、自分が起こしたプロセスをひとまとまりに持ちます。

network namespace は、インタフェース名、アドレス、待ち受けポート、`127.0.0.1:8686`、WireGuard
のポート、`table inet wgft`、conntrack のテーブルをすでに隔てています。Sandbox が分けるのは、
network namespace が隔てない部分、つまり作業ディレクトリとプロセスの所有だけです。Sandbox の
発行と後片付けは [tools/labhost](../tools/labhost) が担い、使い方は [lab/README.md](../lab/README.md)
にあります。

[lab/suite.txt](../lab/suite.txt) は、確認ごとに次の 4 つの分類のどれかを持ちます。

| 分類 | 意味 |
|---|---|
| `parallel` | 他の Sandbox と同時に流せます。触るものが自分の namespace と自分の作業ディレクトリの中に閉じます |
| `exclusive-heavy` | Lab Host VM の中で単独で流します。RSS か到達頻度の測定値を主張の根拠にするため、他の確認と資源を取り合うと結果が変わります |
| `exclusive-timing` | Lab Host VM の中で単独で流します。壁時計で測る区間の中で何が起きないかを主張するため、VM を分け合うと前の段の収束が区間に食い込みます |
| `exclusive-global` | Lab Host VM の中で単独で流します。`nf_conntrack_max` のように network namespace が隔てない値を変えるため、VM の中に 1 つしかありません |

`labhost run all` は、`parallel` の確認をプールで並列に流し、そのあと `exclusive-*` の確認を
1 つずつ流します。確認ごとの並列可否は、この文書の表に個別に書く代わりに
[lab/suite.txt](../lab/suite.txt) の 1 か所にまとめてあります。

## テストの一覧

一覧の列は次の内容を示します。

- リスク:そのテストだけが捉えられる失敗を書きます
- 環境:テストを流すのに必要な機材と場所を書きます
- 契機:前節の表の契機を書きます
- 頻度:契機に当たったときに流す回数の目安を書きます
- 所要時間:ラボの VM が起動している状態での目安を書きます。「見込み」は、まだ存在しないテストの見積もりです
- 自動化:「自動」は判定まで機械が行い、「半自動」は実行を機械が行って結果を人が読み、「手作業」は人が操作して確かめます

「新設」の印の付いた項目は、まだ存在しないか自動化されていないテストです。新設の項目の詳細は後述の「新設と自動化が未了の項目」にあります。

### A 類 (すべての PR)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 所要時間 | 自動化 |
|---|---|---|---|---|---|---|---|
| A1 | `gofmt -l`、`go mod tidy` の差分、`go vet`、`go build ./...` | 書式の崩れ、`go.mod` の不整合、ビルドの失敗 | CI (Linux) | コードを変える PR | PR の更新ごと | 1 分前後 | 自動 |
| A2 | `go test ./...` | 単体で確かめられる退行全般 (`docs/cli.md` とヘルプの食い違いを捉える `TestCLIDocUpToDate` を含めて) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 1 から 2 分 | 自動 |
| A3 | Admission Policy の共有 fixture (`internal/policy/admissiontest`、`internal/policy/testdata/admission`) | nftables のコンパイラと Go の評価器の判定、drop の種類、カウンタの食い違い (7a.9 節) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 数秒 | 自動 |
| A4 | 計画と収束の故障注入 (`internal/planner`、`internal/reconcile` の retry、repair、drift のテスト、`internal/dataplane` の fail-closed のテスト) | Prepare、Commit の失敗の扱い、世代の前進、再試行の誤り (7a.3 節) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 数秒 | 自動 |
| A5 | nftables の行の生成 (`internal/dataplane/linuxkernel/nft` と `internal/policy/nftables` の単体テスト) | 行の順序、行の抜け、ルールごとの fail-closed の誤り (カーネルを使わない照合) | CI (Linux)、ホスト | コードを変える PR | PR の更新ごと | 数秒 | 自動 |
| A6 | `staticcheck` | 静的解析で分かる誤り | CI (Linux) | コードを変える PR | PR の更新ごと | 1 分前後 | 自動 |
| A7 | Windows と macOS へのクロスビルドと `go vet` | 共有のパッケージの変更で Windows、macOS のビルドが壊れること | CI (Linux) | コードを変える PR | PR の更新ごと | 数分 | 自動 |
| A8 | 出力と公開ファイルの検査 (`scripts/check-japanese`、`scripts/check-ascii-punct.sh`、`scripts/check-log-tokens.sh`) | ツールの出力への日本語の混入、全角記号、ログへのトークンの値の出力 | CI (Linux) | すべての PR | PR の更新ごと | 1 分未満 | 自動 |
| A9 | ラボの一式 (L 番号のうち実装済みの確認。今は L1 から L17。モードを持つ確認は両モードで) | 領域をまたぐ変更の見落としを含む、結合したときの退行全般。7a.8 節の共通の完了条件 | ラボ (1 台の Lab Host VM の中で Sandbox を並列に。使い捨て VM で 1 確認 1 台の並列、1 台で順に、も残ります) | コードを変える PR、`phase`、`rc` | マージの前に 1 回 | Sandbox で 約 10 分以内 (既定の 2 vCPU / 2 GiB の Lab Host VM で並列数 8 のときの実測は、L15 を加える前で 338 秒、L16 と L17 を加えた後で 600 秒)、複数の VM で並列に約 2.5 分から 3 分 (3 台で約 185 秒)、1 台で順に 10 分以上 | 自動 (開発者が起動) |

### ラボの一式の内訳

| 番号 | テスト | リスク | 環境 | 開発の途中で選ぶ契機 | 頻度 | 所要時間 | 自動化 |
|---|---|---|---|---|---|---|---|
| L1 | `lab/e2e.sh` (kernel と userspace) | 登録、TCP と UDP の転送、3000 バイトの UDP、PROXY protocol、deny による切断、撤去の退行 | ラボ | `relay`、`userspace`、`protocol`、`agent-platform`、`dataplane-net` | A9 として | モードごとに約 35 秒 | 自動 |
| L2 | `lab/connlimit.sh` | 送信元ごとの同時フロー数の上限 (`ct count`) が実際のパケットで守られないこと、既存のフローの追い出し | ラボ | `admission`、`kernel`、`nft-emit` | A9 として | 約 30 秒 | 自動 |
| L3 | `lab/rates.sh` (kernel と userspace) | 3 つのレートと `Relay` のルールのレートの実際の通過数が両モードで食い違うこと、拒否した段が後の段のトークンを使うこと、TCP のルールに `packet_rate` が効くこと | ラボ | `admission`、`nft-emit`、`relay`、`userspace` | A9 として | モードごとに約 50 秒 | 自動 |
| L4 | `lab/lifecycle.sh` check 1 | server の再起動の間に kernel モードの転送と conntrack が途切れること | ラボ | `reconcile`、`kernel`、`userspace`、`protocol` | A9 として | 1 分前後 | 自動 |
| L5 | `lab/lifecycle.sh` check 2 | 無関係なルールの追加、変更、削除で既存のフローが切れること、成立済みの TCP のセッションを切ったルールが 10 秒以内に転送に戻らないこと | ラボ | `reconcile`、`rule-ops`、`kernel` | A9 として | 1 分前後 | 自動 |
| L6 | `lab/lifecycle.sh` check 3、3b | Relay の bind の失敗が nftables に漏れること、テーブルの差し替えの失敗で待ち受けが戻らないこと | ラボ | `relay`、`reconcile` | A9 として | 1 分前後 | 自動 |
| L7 | `lab/lifecycle.sh` check 4 | `server teardown` が wgft の物以外を削除すること | ラボ | `kernel`、`deploy` | A9 として | 1 分未満 | 自動 |
| L8 | `lab/lifecycle.sh` check 5、5b、5c、5d、5e | 上限までのフラッドでメモリがソフト上限と余裕の和を超えること (check 5 は半分の予算、5b は既定の予算)、1 本のルールへのフラッドが他のルールの新しいフローまで止めること (5c は 2 本、5d は 3 本のルール)、既定より小さい予算で隔離が崩れること (5e) | ラボ (CPU を占有できる VM) | `resource`、`userspace` | A9 として | 3 から 4 分 | 自動 |
| L9 | `lab/lifecycle.sh` check 6、7、8 | ルール単位の失敗が fail-closed にならないこと、backend 全体の失敗で世代が進むこと、再試行で回復しないこと | ラボ | `reconcile`、`relay` | A9 として | 数分 | 自動 |
| L10 | `lab/lifecycle.sh` check 9 | 外から削除された nftables のテーブルが戻らないこと | ラボ | `kernel`、`reconcile` | A9 として | 1 分前後 | 自動 |
| L11 | `lab/split-merge.sh` (kernel と userspace) | Web UI の分割と統合で流れている UDP のセッションが切れること | ラボ | `rule-ops` | A9 として | 約 50 秒 | 自動 |
| L12 | `lab/import-export.sh` (kernel と userspace) | Web UI の書き出しと読み込みの形式の食い違い、確認後の変更の見落とし | ラボ | `rule-ops` | A9 として | 約 20 秒 | 自動 |
| L13 | `lab/ipv6.sh` (kernel と userspace) | IPv6 の送信元が deny をすり抜けること、IPv6 のフラッドが集約のレートのトークンを使うこと | ラボ (IPv6 を加えた netns) | `admission`、`relay` | A9 として | モードごとに約 25 秒 | 自動 |
| L14 | `lab/lifecycle.sh` check 10 (kernel と userspace) | エージェントの停止後も、`agent ls` と Web UI の一覧が最後のハートビートを生きた状態のまま示すこと (design.md の 5.2 節) | ラボ | `rule-ops`、`protocol`、`agent-platform` | A9 として | モードごとに約 1 秒から 2 秒 | 自動 |
| L15 | `lab/lifecycle.sh` check 11 (kernel と userspace) | エージェントの無効化がそのエージェントのルールの転送を止めないこと、他のエージェントのルールまで止めること、有効化で各ルールが自分の `enabled` に戻らないこと、有効化が bind 中のポートを拒まないこと、公開に失敗した無効化がエージェントに届かないこと (design.md の 5.1 節)、無効なエージェントのルールで `server doctor` と `status` が失敗を報告すること、削除したエージェントに残ったルールの `server doctor` と `status` の結果が変わること (design.md の 10.2a、10.2b 節) | ラボ | `reconcile`、`rule-ops`、`protocol` | A9 として | 単独で kernel モードは約 5 秒、userspace モードは約 40 秒 (userspace は server の再起動の後のトンネルの張り直しを待つ)。kernel モードの約 5 秒は、保持していたテーブルの削除の通知ですぐに公開し直す最善の場合です。通知で公開し直さなければ 30 秒ごとの再試行を待ち、確認はその待ちに 40 秒を許します | 自動 |
| L16 | `lab/agentkernel.sh` check 16、17、18、19、22、24、25、resolve、drift、notify、session、route、pin、reconnect、stale、teardown (kernel と userspace) | カーネルモードのエージェントの基本の転送とルール状態の到達、停止と再起動をまたぐ成立済みフローの継続、無関係な変更や再対象化や削除でのフローの扱い、許可一覧とループバックの拒否、自ホストと他のテーブルからの隔離、MSS clamp、無効化による DNAT の撤去、名前解決の失敗時の直前アドレスへの転送継続、外部からの変更への収束と変更の通知による早期の収束、ポリシールーティングの変化の検出、サーバの乗っ取りに対する帯とアドレスの拒否、サーバの再起動をまたぐ再接続とトンネルの陳腐化への対応、`wgft agent teardown` の挙動 (design.md の 7b、9、10.3 節) | ラボ | `agent-platform` | A9 として | kernel モードは 1 組あたり数十秒から約 5 分、userspace モードは同じ組で数十秒から約 5 分 (reconnect と stale は kernel モードだけの検査で、userspace モードでは SKIP になり数秒で終わります) | 自動 |
| L17 | `lab/agentdoctor.sh` (kernel と userspace) | `wgft agent doctor` の判定が、稼働中と停止中の切り分け、テーブルの行の欠けや変更や差し替えの見分け、`ip_forward` と wgft0 の状態、経路、無効化、呼び出し元の権限の有無による結果の違いで、カーネルモードのエージェントの実際の状態と食い違うこと (design.md の 10.2c 節) | ラボ | `agent-platform` | A9 として | モードごとに約 1 分 | 自動 |

### B 類 (関係する変更の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 所要時間 | 自動化 |
|---|---|---|---|---|---|---|---|
| B1 | build tag `lab` の nftables のテスト (`lab/lab test internal/dataplane/linuxkernel/nft`。server の `table inet wgft` とエージェントの `table inet wgft_agent` のゴールデンテスト、他のテーブルを触らないこと、wg からの転送の遮断、google/nftables での読み戻し、エージェントの表の全幅までの範囲の読み込みと、network namespace の間で他のテーブルの DNAT に wgft0 から届かないこと) | 生成した式が実際のカーネルで同じ `nft list` にならないこと。エージェントの表では `nft --debug=netlink list` の式の列も比べる。大きな範囲の map の要素が欠けること。wgft0 から公開していないポートに届くこと | ラボ | `nft-emit`、`kernel`、`admission` | 契機に当たる PR ごとに 1 回 | 数十秒 | 自動 (開発者が起動) |
| B2 | build tag `lab` の WireGuard、ホストの検査、teardown のテスト (`internal/dataplane/linuxkernel/wg`、`internal/platform/linux`、`internal/vpsd`) | 他の wg インタフェースの乗っ取り、所有の判定の誤り、他のテーブルの削除 | ラボ | `kernel`、`deploy` | 契機に当たる PR ごとに 1 回 | 数十秒 | 自動 (開発者が起動) |
| B3 | 実際の Caddy での HTTPS の経路 ([lab/caddy/README.md](../lab/caddy/README.md)) | PROXY protocol のヘッダを実際のリバースプロキシが読めないこと | ラボ | `relay` | 契機に当たる PR ごとに 1 回 | 10 分前後 (見込み) | 手作業 |
| B4 | CI の `windows-test` (`internal/dataplane/userspace/utun` の `TestAgentServerInProcessForwarding` を含む。後述の「実機の確認を小さな回帰テストに置き換えた範囲」) | Windows でだけ通る経路 (認証情報の ACL、`LockFileEx`、UDP の待ち方) の退行と、エージェントのトンネル・中継の転送そのものの退行 (D1 の一部の置き換え) | CI (Windows の runner) | `agent-platform` | 契機に当たる PR の更新ごと | 数分 | 自動 |
| B5 | CI の `release-snapshot` | GoReleaser の設定、フック、成果物の名前の食い違い | CI (Linux) | `build`、`rc` | 契機に当たる PR の更新ごと | 数分 | 自動 |
| B6 | CI の `govulncheck` | 依存するモジュールの既知の脆弱性 | CI (Linux) | `build`、`rc`、週に 1 回の定期実行 | 契機に当たる PR の更新ごと。定期実行は週に 1 回 | 1 分前後 | 自動 |
| B7 | `lab/version-skew.sh` | 旧 agent と新 server、新 agent と旧 server、legacy v0 の agent と新 server の組で、登録、全体状態の配信、転送、再接続が壊れること。旧い側が表せない機能のルールを理由付きの `not_active` にすること (7a.6 節) は、該当する capability がまだ無いため確認を SKIP する。新しい server と旧い agent の組では、agent の無効化で転送が止まらないこと、有効化で転送が戻らないこと、無効化が VPS 側だけにとどまり旧い agent 自身に届かないこと、`agent ls`、`status`、`server doctor` が無効を示さないこと、無効化の間に旧い agent が落ちたり再接続を繰り返したりすること (5.1 節) | ラボ (直前のリリースと legacy v0 のバイナリを GitHub の Releases から取得してキャッシュする。ラボの VM から GitHub への経路が無い場合は、バイナリを事前に置く) | `protocol`、`rc` | 契機に当たる PR ごとと、リリース候補ごとに 1 回 | 数分 | 自動 (開発者が起動) |
| B8 | CI の `macos-test` (`internal/dataplane/userspace/utun` の `TestAgentServerInProcessForwarding` を含む) | macOS でだけ通る経路 (UDP の送信バッファの既定 9216 バイトを超えるデータグラムの書き込み) の退行 (D2 の一部の置き換え。後述の「実機の確認を小さな回帰テストに置き換えた範囲」) | CI (macOS の runner) | `agent-platform`、`rc` | 契機に当たる PR の更新ごと | 1 分から 2 分 (初回の実行は 1 分 15 秒) | 自動 |
| B9 | 配布物の VM 試験 (`scripts/dist-vm.sh`) | 同梱の unit で起動しないこと、VM の再起動の後に転送が戻らないこと、設定の誤りで再起動を繰り返すこと | 2 台の VM (server と agent) | `deploy`、`rc` | 契機に当たる PR ごとに 1 つのディストリビューションで、リリース候補ごとに 3 つのディストリビューションで | 約 4 分 (Debian 12、Ubuntu 24.04、Fedora 44 のいずれも) | 自動 (開発者が起動) |
| B10 | Docker のイメージの疎通 (`scripts/docker-smoke.sh`) | `deploy/Dockerfile.*` から作ったイメージで server と agent が動かないこと | Docker か Podman のある Linux (ホスト、CI の runner、ラボの VM のどれでも可) | `build`、`rc` | 契機に当たる PR ごとと、リリース候補ごとに 1 回 | キャッシュが温まっていれば約 8 秒、初回はイメージの取得を含めて約 30 秒 | 自動 (開発者が起動) |

### C 類 (段階の完了の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 所要時間 | 自動化 |
|---|---|---|---|---|---|---|---|
| C1 | 悪い条件のネットワーク (新設) | 損失、遅延、小さい経路 MTU と ICMP の遮断、自宅側のアドレスの変化で、トンネルと転送が回復しないこと | ラボ (netns に `tc netem` と経路の変更を加える) | `phase`、`dataplane-net` | v1 の前に一度、以後は関係する変更 (network dataplane) を含む段階の完了時 | 10 分前後 (見込み) | 自動 (新設) |
| C2 | クラッシュと強制停止からの収束 (新設) | Prepare と Commit の間での強制終了や VM の強制停止の後に、宣言した状態へ収束しないこと | ラボ | `phase`、`reconcile` | v1 の前に一度、以後は関係する変更 (収束の仕組み) を含む段階の完了時 | 数分 (見込み) | 自動 (新設) |
| C3 | 規模の試験 | ルール数とエージェント数が多いときの適用時間、テーブルの差し替え、全体状態の大きさの問題 | ラボ | `phase` | 段階の完了ごとに 1 回 | kernel 約 3 分、userspace 約 1 分半 (実測) | 自動 (開発者が起動) |
| C4 | ラボの一式を別のディストリビューションで | カーネルと nftables の版の違いによる挙動の違い (通知、`ct count`、式の表記) | ラボ (`WGFT_LAB_IMAGE` で別のイメージの VM) | `phase`、`kernel` | v1 の前に一度、以後は関係する変更 (kernel 側の経路) を含む段階の完了時 | A9 と同じ | 自動 (開発者が起動。Fedora は未対応) |
| C5 | 長時間の TCP と UDP (新設) | 通常の WireGuard のセッションの鍵の更新、ハートビート、conntrack の期限をまたいで長いセッションが切れること。`agent rotate-key` の後に新しい通信が戻らないこと | ラボ | `phase`、`resource`、`dataplane-net` | v1 の前に一度 (Phase 6 の完了時)、以後は関係する変更 (Resource Guard、network dataplane) を含む段階の完了時 | 1 時間以上 (見込み) | 自動 (新設) |
| C6 | 小さいメモリの環境 (新設) | 256 MiB の VPS の目安の設定で、フラッドの下で server が OOM で落ちること | ラボ (メモリを制限した cgroup) | `phase`、`resource`、`dataplane-net` | v1 の前に一度 (Phase 6 の完了時)、以後は関係する変更 (Resource Guard、network dataplane) を含む段階の完了時 | 数分 (見込み) | 自動 (新設) |

### D 類 (リリース候補の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 所要時間 | 自動化 |
|---|---|---|---|---|---|---|---|
| D1 | Windows のエージェントの smoke (新設) | リリースのバイナリが Windows で登録、転送、再接続、状態の保持に失敗すること | Windows の VM か Windows の実機 | `rc` | リリース候補ごとに 1 回 | 30 分前後 | 手作業 (v1)。自動化は v1.1 以降 |
| D2 | macOS のエージェントの smoke (新設) | リリースのバイナリが Apple シリコンの Mac で登録、転送、再接続、launchd での起動に失敗すること | Mac の実機 | `rc` | リリース候補ごとに 1 回 | 30 分前後 | 手作業 |
| D3 | リリースの成果物と署名の検証 | 成果物の欠け、`wgft version` の表記の誤り、`gh attestation verify` の失敗、GHCR のイメージの欠け | リリースの後の GitHub と GHCR | `rc` (タグの後) | リリースごとに 1 回 | 10 分前後 | 半自動 (成果物の名前は B5 が確かめる) |
| D4 | `lab/upgrade.sh`、`scripts/dist-vm.sh --upgrade` | 直前のリリースのデータベースと認証情報を現在のビルドが読めないこと、更新の間にルール・鍵・認証情報が変わること、片側だけを先に更新した組み合わせで転送が止まること、docs/setup.md の手順で導入した VM でバイナリだけを入れ替え、同梱の unit を再起動し、VM も再起動する経路で転送が戻らないこと。直前のリリースのデータは agent の無効化 (5.1 節) より前のものなので、更新した直後に既存の agent が無効として扱われて転送が止まること、更新の後に無効化した状態が server の再起動で失われること | ラボ (直前のリリースのバイナリを GitHub の Releases から取得してキャッシュする。lab/version-skew.sh と同じ) と、2 台の使い捨て VM (`scripts/dist-vm.sh` 自身の環境。直前のリリースのバイナリはホストで取得し、VM には push するだけです) | `rc` | リリース候補ごとに 1 回 | `lab/upgrade.sh` はモードごとに約 2 分半、両モードで約 5 分半。`scripts/dist-vm.sh --upgrade` は既定の確認に約 80 秒を足します (Debian 12 での実測) | 自動 (開発者が起動) |

### E 類 (手作業と実機の関門)

| 番号 | テスト | リスク | 環境 | 契機 | 頻度 | 所要時間 | 自動化 |
|---|---|---|---|---|---|---|---|
| E1 | 実 VPS での導入、再起動、撤去 | 実際のクラウドのイメージ (最小構成、ホストのファイアウォール、`flush ruleset` で始まる設定) で手順どおりに動かないこと | 試験用の実 VPS と自宅の Linux のエージェント | `manual-release`、`deploy`、`kernel` | v1 の前に 1 回、以後は契機に当たるとき | 1 時間前後 | 手作業 |
| E2 | 実回線の自宅ルータと NAT | CGNAT や IPv4 over IPv6 の回線、経路 MTU の小さい回線で登録とトンネルが成り立たないこと | 実回線と実際の自宅ルータ | `manual-release`、`dataplane-net` | v1 の前に 1 回、以後は契機に当たるとき | 30 分前後 | 手作業 |
| E3 | 実回線での WAN のアドレスの変化 | 回線の再接続でアドレスが変わった後に、エージェントが戻らないこと、窃取の検知が誤って働くこと | 実回線 | `manual-release`、`protocol` | v1 の前に 1 回、以後は契機に当たるとき | 30 分前後 | 手作業 |
| E4 | Windows の実機での利用 | スリープと復帰、ネットワークアダプタの無効と有効、Wi-Fi の再接続の後に戻らないこと | Windows の実機 | `manual-release`、`agent-platform` | v1 の前に 1 回、以後は契機に当たるとき | 1 時間前後 | 手作業 |
| E5 | Mac の実機での利用 | スリープと復帰、Wi-Fi やインタフェースの変化、再起動の後に戻らないこと | Mac の実機 | `manual-release`、`agent-platform` | v1 の前に 1 回、以後は契機に当たるとき | 1 時間前後 | 手作業 |
| E6 | 実アプリケーションでの長時間の利用 | 実際の利用者の通信で数日単位に現れる切断、メモリの増加、ログの異常 | 実 VPS と実アプリケーション | `manual-release`、`dataplane-net`、`resource` | v1 の前に 1 回、以後は契機に当たるとき | 数日 | 手作業 (外からの疎通の確認は機械でもできる) |

### F 類 (調査だけの実験)

| 番号 | 実験 | 得たい根拠 | 環境 | 契機 | 頻度 | 所要時間 | 置き換え先の回帰テスト |
|---|---|---|---|---|---|---|---|
| F1 | conntrack のメモリの費用の実測 (実施済み) | 65536 という推奨値が小さいメモリの環境でも非現実的でないことの設計の根拠 (7a.10 節) | ラボ | 対応するカーネルの範囲の変更 | v1 の前に 1 回 | 1 時間前後 | 診断の文言にメモリの値が含まれないことの単体テスト (未実装) |
| F2 | 毎秒 4000 接続以上の負荷 | 拒否の経路の費用が高い接続の頻度でも一定であること | ラボ (CPU を占有できる VM) | 根拠が要るとき | 1 回 | 数時間 | L8 (到達できる頻度でのフラッド) |
| F3 | netlink の ENOBUFS の強制 | 通知の取りこぼしの後に購読を張り直して Observe すること | ラボ | 根拠が要るとき | 1 回 | 数時間 | 購読の失敗を模した単体テスト (未実装) と L10 |
| F4 | カーネルの版による通知の違い | 版ごとに nftables と rtnetlink の通知の出方が違うかどうか | 版の違う VM | 根拠が要るとき | 1 回 | 数時間 | C4 での L10 |
| F5 | メモリと CPU のプロファイル | フロー 1 本の費用、拒否した接続が残すメモリ | ラボ、実機 | 根拠が要るとき | 1 回 | 数時間 | L8 とメモリのソフト上限の計算式の単体テスト |
| F6 | パケットキャプチャによる調査 | 不具合の原因の特定 | ラボ、実機 | 不具合の調査 | 必要なとき | 不定 | 不具合を再現するラボの確認 |
| F7 | スループットの測定 | 転送の速さの目安 | ラボ、実機 | 性能の報告を受けたとき | 必要なとき | 1 時間前後 | 無し (性能の約束を文書に書いていないため) |
| F8 | トークンバケットの補充の境界と meter の期限 | 7a.9 節の許容差のうち未確認の点 | ラボ | 根拠が要るとき | 1 回 | 数時間 | A3 の fixture (補充の時刻から 10% 以上離して出来事を置く) |
| F9 | userspace と kernel の切り替えの断 | Phase 7 の受け入れ条件の値 | ラボ | Phase 7 の設計 | 1 回 | 1 時間前後 | Phase 7 の受け入れ条件のラボの確認 |

## v1 の項目と繰り返しの頻度

v1 は、設計文書 7a.8 節の Phase 1 から 6 を終えて v1.0 を出すまでを指します。v1 に必須の項目は、繰り返しの頻度によって 2 つに分かれます。すべてをリリースごとの関門にはしません。リリースごとに繰り返す必要があるのは、配布物と互換性のように、どの変更でも壊れうるものだけだからです。

リリース候補ごとに流す項目は次のとおりです。L1 はラボの一式に含まれるので、コードを変える PR ごとにも流れます。L13 も、実装した時点からラボの一式に加わります。

- 配布物の導入と起動:B9 (Debian 12、Ubuntu 24.04、Fedora 44)、B10 (Docker のイメージ)
- 旧版からの更新:D4
- 版の組み合わせ:B7
- TCP と UDP の基本の転送:L1
- IPv4 と IPv6 の fail-closed:L13
- 対応する OS での smoke:D1 (Windows)、D2 (macOS)、B8 (macOS の runner)

v1 の前に 1 回流し、以後は関係する領域を変えたときにだけ流し直す項目は次のとおりです。

- 256 MiB の環境でのフラッド:C6。Phase 6 の完了時に流し、以後は Resource Guard か転送の経路を変えた段階の完了時に流し直します
- 1 時間以上の通信:C5。Phase 6 の完了時に流し、以後は Resource Guard か転送の経路を変えた段階の完了時に流し直します
- conntrack のメモリの費用の測定:F1。実施済みで、対応するカーネルの範囲を変えたときに測り直します
- 悪い条件のネットワーク:C1。転送の経路を変えたときに流し直します
- クラッシュと強制停止からの収束:C2。収束の仕組みを変えたときに流し直します
- 別のディストリビューションでのラボの一式:C4。kernel 側の経路を変えたときに流し直します
- スリープと復帰:E4、E5。エージェントの OS ごとの経路を変えたときに流し直します
- 実 VPS と実回線の確認:E1、E2、E3。導入の手順、kernel 側の経路、stream の接続を変えたときに流し直します
- 実アプリケーションでの長時間の利用:E6。転送の経路か Resource Guard を変えたときに流し直します

v1 の条件のうち、公式に対応をうたう 3 つのディストリビューションでの配布物の確認 (B9) は、`scripts/dist-vm.sh` として実装済みで、Debian 12、Ubuntu 24.04、Fedora 44 のいずれでも確かめました。版の組み合わせ (B7) は `lab/version-skew.sh` として実装済みです。ただし、旧い側が表せない機能のルールを理由付きの `not_active` にすることの確認だけは、該当する capability がまだ無いため未了です (後述の「B7 の not_active の確認」)。旧版からの更新 (D4) のうち、同梱の unit と実際の VM の再起動を経由する部分は `scripts/dist-vm.sh --upgrade` として実装済みで、Debian 12 で確かめました (後述の「D4 の残りの項目 (実装済み)」)。Ubuntu 24.04 と Fedora 44 でのこの部分は未確認です。エージェントのカーネルモードの配布物は `scripts/dist-vm.sh --agent-kernel` で確かめます。このフラグは、エージェントを drop-in の `deploy/agent.kernel.conf` と `WGFT_MODE=kernel` で入れて B9 の確認を流し、権限、エージェントの停止中の転送、`agent doctor`、drop-in が無い場合の終了コード 3、`wgft agent teardown` によるユーザー空間モードへの戻し、カーネルモードへの切り替え直しの確認を加えます。`deploy/agent.kernel.conf` を変える PR では、B9 をこのフラグ付きで流します。Debian 12 で確かめました。Ubuntu 24.04 と Fedora 44 では未確認です。

別のディストリビューションでのラボの一式 (C4) のうち、Ubuntu 24.04 での実行は完了しました。カーネル 6.8.0、nftables v1.0.9 の Ubuntu 24.04 の Lab Host VM で `labhost run -parallel 8 all` を流し、同じコミットの既定の Debian 12 (カーネル 6.1.0、nftables v1.0.6) の結果と比較したところ、判定はどちらも PASS 291、FAIL 0、SKIP 16 で一致し、確認ごとの PASS と SKIP の数も一致しました。C4 が挙げていた、新しいカーネルと nftables の版による挙動の違い (通知の出方、`ct count` の値、式の表記) は、今回流した一式の範囲では表れませんでした。もっと大きな規模や、この 2 つより新しいカーネルと nftables での挙動は未確認です。

Fedora 44 (カーネル 7.2.5、nftables v1.1.6) でも同じ一式を既定の設定で流し、こちらも PASS 291、FAIL 0、SKIP 16 で、確認ごとの数も Debian 12 と一致しました。ただし Incus の `images:fedora/44` イメージには、`firewalld` と SELinux のポリシー (`selinux-policy` 一式) がどちらも入っておらず、`getenforce` は Disabled でした (`/sys/fs/selinux` はマウントされているので、カーネル自体は SELinux に対応していますが、適用するポリシーが無い状態です)。実機の Fedora Server や Workstation は既定でこの両方が有効なので、今回の一式はその条件を再現していません。SELinux が enforcing の状態と firewalld が動く状態でラボのトポロジと一式が通ることは未確認で、確かめるには `selinux-policy-targeted` と `policycoreutils` の導入、relabel、再起動による enforcing 化、`firewalld` の導入と有効化を、`lab/lab` の外で別途行う必要があります。Fedora への対応は v1.1 以降でよい項目のままなので、この未確認の点は v1 の関門には含めません。

## 更新と戻しの約束

更新の経路は保証します。旧版への戻しは互換性の保証に含めず、各版で観測した挙動だけを記録します。戻す必要があるときは、更新の前に取ったデータの置き場のバックアップから戻します。戻しを約束すると、サーバのデータベースのスキーマ、migration、知らないフィールドの保存、状態ファイル、wire protocol の変更を、旧い版が読める形に永久に縛るためです ([設計文書](design.md) 7a.6 節)。D4 はこの約束に従い、更新を確かめ、戻しについては挙動を記録するだけにします。

## 新設と自動化が未了の項目

各項目は、確かめる内容、今のラボで足りない理由、必要な環境、流す時期、流す契機、自動か手作業か、v1 に必須か v1.1 以降でよいか、の 7 点で定めます。v1 の項目には、前節の繰り返しの頻度を付けます。

### B7 の not_active の確認

- 内容:`lab/version-skew.sh` のうち、旧い側が表せない機能のルールを理由付きの `not_active` にすることの確認です (7a.6 節)。登録、全体状態の配信、転送、再接続の確認は実装済みで、この項目だけが未了です
- 足りない理由:`SupportedCapabilities` (`proto/version.go`) の語彙は今のところ空です。planner にも stream の版と機能の交渉にも、capability に紐づく機能はまだ無いので、確かめる対象がありません
- 環境:ラボです
- 時期:最初の capability を追加する変更に合わせます
- 契機:`protocol`
- 自動化:自動の見込みです
- v1:B7 自体は必須ですが (前述の「版の組み合わせ:B7」)、この部分だけは対応する機能が無い間は満たせません。capability を追加する変更のときに `lab/version-skew.sh` へこの確認を実装し、そのときに満たします

### C1 悪い条件のネットワーク

- 内容:homerouter の WAN 側に損失、遅延、並べ替えを加えた状態での転送を確かめます。経路 MTU を 1454 と 1460 に下げて ICMP を落とした状態で、大きな TCP と UDP が通ることを確かめます。homerouter の WAN のアドレスを変えて NAT の状態を削除した後に、エージェントが再接続し、窃取の検知が誤って働かないことも確かめます
- 足りない理由:ラボの一式のネットワークには損失も遅延も無く、MTU とアドレスも一定なので、回線の品質とアドレスの変化による失敗が起きません
- 環境:既存の netns に `tc netem`、MTU の変更、アドレスの変更を加えたラボです。複数の VM は要りません
- 時期:v1 の前に一度流し、以後は関係する変更 (network dataplane) を含む段階の完了時に流し直します
- 契機:`dataplane-net`、`phase`
- 自動化:自動です
- v1:必須で、v1 の前に 1 回の項目です。自宅の回線には MTU の小さい方式が多く、利用者の環境で起きやすい失敗を自動で再現できる試験は他にありません

### C2 クラッシュと強制停止からの収束

- 内容:ルールの変更を続けながら server を SIGKILL で止めて起動し直したとき、サーバのデータベース、nftables、エージェントの状態が宣言した状態へ収束することを確かめます。VM を強制停止した後にも同じことを確かめます (7a.1 節の優先順位 4)
- 足りない理由:L4 は、変更の無い状態での停止と再起動を確かめます。変更の途中での強制終了と、ディスクへの書き込みの途中での停止は確かめません。故障注入の単体テスト (A4) は Prepare と Commit の失敗を模しますが、プロセスの消滅は模しません
- 環境:ラボです。VM の強制停止の場面には B9 の VM を使います
- 時期:v1 の前に一度流し、以後は関係する変更 (収束の仕組み) を含む段階の完了時に流し直します
- 契機:`reconcile`、`phase`
- 自動化:自動です
- v1:必須で、v1 の前に 1 回の項目です。Phase 4 で導入した世代と収束の約束を、プロセスの消滅に対して確かめる試験は他にありません

### C3 規模の試験

- 内容:[lab/scale.sh](../lab/scale.sh) が、1 台の server と 5 台のエージェントで、ルール数を 10 から 1000 まで増やしながら、適用の時間、全体状態の大きさ、RSS、Web UI の応答が実用の範囲にあることを確かめます。ルールは `rule import` の 1 回のバッチと、`rule add` の 1 本ずつのどちらでも追加します
- 足りない理由:A9 のラボの一式は、数本のルールと 1 台のエージェントだけを使うので、規模を上げた経路を確かめません
- 環境:ラボです
- 時期:段階の完了ごとに流します。実施済み:2026-09-21、Debian 12
- 契機:`phase`
- 自動化:自動です。`lab/lab exec vm bash /wgft/lab/scale.sh kernel` と `lab/lab exec vm bash /wgft/lab/scale.sh userspace` を開発者が起動します。段階の完了ごとという頻度のため、A9 のラボの一式には含めません (D4 の `lab/upgrade.sh` と同じ位置づけ)
- v1:v1.1 以降でよい項目です。想定する利用 (自宅の数本のルール) では規模の問題の報告が無く、設計文書にも規模の約束がありません
- 分かったこと:kernel モードは 100 本前後のルールで適用が丸ごと失敗していました。原因は netlink のソケットバッファで、修正の後は両方のモードが 1000 本まで通ります。経緯は設計文書の 6.1 節と改訂の記録に、測定値の一覧は実施した PR の本文に書きます

### C4 ラボの一式を別のディストリビューションで

- 内容:A9 と同じ一式を、既定の Debian 12 (対応の下限) 以外のイメージの VM で流します
- 足りない理由:既定のラボは Debian 12 だけなので、新しいカーネルと nftables での挙動の違い (通知の出方、`nft list` の表記) を確かめません
- 環境:`WGFT_LAB_IMAGE` で別のイメージを選んだ Lab Host VM です。ディストリビューションごとに 1 台の Lab Host VM を立て、その中で一式を `labhost run -parallel N all` で流します。`lab/lab` は `/etc/os-release` の ID でパッケージ管理コマンドとパッケージ名を振り分けるので、Ubuntu 24.04 と Fedora のどちらも今の導入の手順 (`lab/lab up`) で立てられます
- 時期:v1 の前に一度流し、以後は関係する変更 (kernel 側の経路) を含む段階の完了時に流し直します
- 契機:`kernel`、`phase`
- 自動化:自動です。開発者が起動します
- v1:Ubuntu 24.04 での実行は必須で、v1 の前に 1 回の項目です。この項目は満たしました (結果は後述の「v1 の項目と繰り返しの頻度」の節)。Fedora への対応は v1.1 以降でよい項目のままで、既定の設定での一式は流しましたが、SELinux が enforcing の状態と firewalld が動く状態での確認は未確認です (同節)

### C5 長時間の TCP と UDP

- 内容:1 本の TCP の接続と 1 本の UDP のセッションを 1 時間以上保ち、通常の WireGuard のセッションの鍵の更新、エージェントのハートビート、conntrack の期限をまたいでも使い続けられることを確かめます。`agent rotate-key` はトンネルを作り直して既存のセッションを切る (設計どおりの挙動) ので、長いセッションの条件には含めません。別の確認として、`agent rotate-key` の後に新しい TCP と UDP の通信が戻ることを確かめます
- 足りない理由:ラボの一式のフローは、数秒から数十秒で終わります。`agent rotate-key` の後の回復を確かめるラボの確認もありません
- 環境:ラボです
- 時期:v1 の前に一度 (Phase 6 の完了時) 流し、以後は関係する変更 (Resource Guard、network dataplane) を含む段階の完了時に流し直します
- 契機:`phase`、`resource`、`dataplane-net`
- 自動化:自動です。保つ時間は引数で決めます
- v1:必須で、v1 の前に 1 回の項目です。wgft の主な用途はゲームのような長いセッションであり、実アプリケーションでの利用 (E6) の前に機械で確かめられます

### C6 小さいメモリの環境

- 内容:メモリを 256 MiB に制限した server と agent を、設計文書 7 節の目安の設定 (`WGFT_MAX_UDP_FLOWS=2048`、`WGFT_MAX_TCP_FLOWS=1024`) で動かし、上限を超えるフラッドの下でも OOM で落ちないことを確かめます
- 足りない理由:ラボの VM は 2 GiB のメモリを持ち、check 5 はプロセスのメモリを制限しません
- 環境:cgroup でプロセスのメモリを制限したラボです
- 時期:v1 の前に一度 (Phase 6 の完了時) 流し、以後は関係する変更 (Resource Guard、network dataplane) と目安の値の変更を含む段階の完了時に流し直します
- 契機:`phase`、`resource`、`dataplane-net`
- 自動化:自動です
- v1:必須で、v1 の前に 1 回の項目です。文書に書いた目安の値を確かめる手段が他にありません

### D1 と D2:Windows と macOS のエージェントの smoke

内容、足りない理由、環境は、後述の「Windows と macOS のエージェント」にあります。

- 時期:リリース候補ごとに流します
- 契機:`rc`
- 自動化:手作業です。D1 の自動化は v1.1 以降の候補です
- v1:どちらも必須で、リリース候補ごとの項目です

### D4 の残りの項目 (実装済み)

- 内容:`lab/upgrade.sh` は、直前のリリースの server と agent で代表的な構成 (TCP、UDP、ポート範囲、拒否リストと許可リストを持つルール、3 つのレートすべてを持つ TCP のルール、無効化したルール、Relay の PROXY protocol のルール) を作り、転送を確かめたうえで、両方を止めて現在のビルドに入れ替え、同じデータディレクトリで再開したときにルールが 1 件ずつ完全に一致すること、鍵と認証情報が変わらないこと、再登録が要らないこと、無効化と拒否/許可リストが効いたままであることを確かめます。片側だけ先に更新した 2 通りの組み合わせ (新しい server と旧い agent、旧い server と新しい agent) も、旧いデータのまま転送が保てることを確かめます。旧いリリースの版は環境変数 `WGFT_UPGRADE_OLD_VERSION` (既定は v1.1.3) で選び、過去に更新を約束した版のうち最も古い `WGFT_UPGRADE_OLD_VERSION=0.4.0` でも同じ一式を流せます。TCP の packet_rate が保存だけされて効かなくなったこと、Relay の待ち受けが IPv4 だけになること、`rule ls` に Resource Guard の予算の行が新しく出ることの 3 点は、選んだ旧いリリース自身の出力と比べ、その版がまだその挙動を持たないときだけ「新しく現れた変化」として確かめます。v1.1.3 は 3 点とも既に持つため、v1.1.3 を旧いリリースにしたときはこの比較を SKIP と報告し、v0.4.0 はまだ 3 点とも持たないため、v0.4.0 を旧いリリースにしたときは 3 点とも変化として確かめます。登録、全体状態の配信、転送、再接続そのものの検査は B7 (`lab/version-skew.sh`) が新しいデータで済ませているので、D4 は同じ検査を旧いデータの上で繰り返しません。userspace モードでは server 自身の WireGuard 公開鍵を CLI からも API からも読めないため、鍵が変わらないことは agent 側の公開鍵でだけ確かめています。1 本のルールがフロー予算をすべて使えることの再検証は L8 の役目なので、D4 では Resource Guard の行が出ることの確認にとどめます。ここまでは、この節が「残り」と呼んでいた時点からの変更はありません。更新が終わって現在のビルドに入れ替わった同じインスタンスの上で、agent の無効化と有効化 (5.1 節) も確かめます。直前のリリースのデータは agent の無効化より前のものなので、更新した直後の home は有効であること、`wgft agent disable` で転送が止まり、その無効化が server の再起動をまたいで保たれること、`wgft agent enable` で転送が戻ることを確かめます
- 実装済みの残り:`scripts/dist-vm.sh --upgrade` (B9 の任意の追加の段階。既定では流れず、フラグを渡したときだけ流れるので、B9 の既存の確認とその所要時間は変わりません) が、同梱の unit と実際の VM の再起動を経由する更新の確認を実装しました。直前のリリースの既定の選び方は次のとおりです。候補は、HEAD から辿れる安定版のタグと、HEAD のコミットより前に作られた辿れない安定版のタグです。HEAD 自身を指すタグは除きます。辿れないタグの major.minor は、辿れるタグのうち版が最大のものの major.minor 以下でなければなりません。既定に選ぶタグは、候補のうち版が最大のものです。プレリリースのタグは候補になりません。`WGFT_DIST_VM_UPGRADE_OLD_VERSION` で `lab/upgrade.sh` と同じ形式で上書きできます。保守の枝でリリースした後、main に新しいコミットが無いまま関門を流すと、既定ではその版を選ばないことがあります。その場合は `WGFT_DIST_VM_UPGRADE_OLD_VERSION` で明示します。直前のリリースを、そのリリース自身の tag が持つ `deploy/server.service` と `deploy/agent.service` で、docs/setup.md の手順のとおり 2 台の VM (server と agent) に導入します。`lab/upgrade.sh` と同じ 7 種のルールを作って転送を確かめ、release notes の「Upgrading」節が指示するとおりデータディレクトリを控えたうえで、server のバイナリだけを入れ替えて unit を再起動し、ルールが `rule ls --json` で 1 件ずつ一致すること、agent が再登録せずに再接続すること、7 種すべてのルールで転送が戻ること、`wgft server check` が何も指摘しないことを確かめます。続けて agent のバイナリも同じ手順で入れ替え、同じ一式を確かめたうえで、server の VM、次に agent の VM を再起動して、手を加えずに転送が戻ることを確かめます。それぞれの入れ替えが転送を止めた秒数を記録しますが、上限を決めていないため主張の根拠にはしません (前述の「更新と戻しの約束」)。同梱の unit がその版から変わっているかどうかは、コメントを除いた行を実行時に diff して判定し、変わっていなければ「バイナリだけを入れ替える場合」と「unit も入れ替える場合」の結果が同じと判断してどちらか一方だけを流します (v0.5.1 を直前のリリースにした今回はコメントの行しか変わっておらず、この判断で SKIP と報告しました)。データベースのファイルを読めない状態からの再起動が失敗することは、そのファイルの権限を落として確かめます (StateDirectory 自体を chmod する方法は使えませんでした。DynamicUser と StateDirectory を持つ unit は、起動のたびに systemd がディレクトリ自体の権限を StateDirectoryMode に戻すため、ディレクトリではなくファイル自身の権限を落とす必要があります)
- まだ確かめていないこと:Ubuntu 24.04 と Fedora 44 でのこの追加の段階 (既定の Debian 12 でだけ確かめました)、Docker/compose での導入経路 (B10 の役目で、更新の確認を持ちません)、更新の順を入れ替えた場合 (agent を先に入れ替え、server を後に入れ替える場合。release notes はどちらの順も約束しますが、この追加の段階は server を先に入れ替える順だけを 1 回流します)。旧版への戻しは前述の「更新と戻しの約束」のとおり約束の対象外で、`lab/upgrade.sh` と同じく確かめていません
- 環境:ラボ (`lab/upgrade.sh`) と、2 台の使い捨て VM (`scripts/dist-vm.sh --upgrade`)
- 時期:リリース候補ごとに流します
- 契機:`rc`
- 自動化:自動です。開発者が起動します
- v1:必須で、リリース候補ごとの項目です。同梱の unit と実際の VM の再起動を経由する更新の確認は実装済みで、残るのは前述の「まだ確かめていないこと」です

### F1 conntrack のメモリの費用の実測

- 内容:conntrack のメモリの費用を実測し、65536 という推奨値が小さいメモリの環境でも非現実的でないことの設計の根拠を得ます。測定値はカーネルの版、設定、エントリの種類に依存するので、`server check` や起動時の診断に固定の値として出しません。観測の条件と結果だけを設計文書に残します
- 足りない理由:推奨値の根拠となる測定は、ラボの一式にも単体テストにもありません
- 環境:ラボです
- 時期:実施済みです (2026-09-20、Debian 12、Linux 6.1)。対応するカーネルの範囲を変えたときに測り直します
- 契機:カーネルの対応範囲の変更
- 自動化:手作業の測定です。回帰テストは測定値を固定するものではなく、`server check` と起動時の診断の文言にメモリの値が含まれないことを確かめる単体テストです (未実装)。`server check` が示すのは、今の上限、wgft が推奨する最小値 65536、表が埋まったときの影響、sysctl の例、上限を上げるとカーネルのメモリの使用量も増えうることだけです
- v1:必須で、v1 の前に 1 回の項目です。測定は済んでいます

### E 類の手作業の確認

- 内容:E1 から E6 の表のとおりです
- 足りない理由:クラウドの実際のイメージ、実回線の NAT と MTU、回線の再接続によるアドレスの変化、Windows と Mac のスリープやネットワークの変化、実際の利用者の通信は、ラボの VM では作れません
- 環境:試験用の実 VPS、実回線と自宅ルータ、Windows と Mac の実機、実アプリケーションです
- 時期:v1 の前に 1 回行い、以後は表の契機に当たる変更の後に行います
- 契機:`manual-release` と、表の各行の契機
- 自動化:手作業です。E6 のうち外からの疎通の確認だけは、機械で定期的に行えます
- v1:必須で、v1 の前に 1 回の項目です

## Windows と macOS のエージェント

Windows と macOS のエージェントの試験は、Linux のラボに含めません。Linux のラボは Incus の VM、network namespace、Linux のカーネル、nftables、WireGuard で組んだ環境であり、Windows と macOS に固有の経路 (認証情報の ACL、UDP の待ち方、UDP の送信バッファ、launchd、スリープ、ネットワークの変化) を再現しないためです。同じ理由で、Windows と macOS の試験をラボの一式 (A9) に含めません。

実機での確認は、Linux のラボでは起きない失敗を実際に捉えています。Windows の実機では、認証情報のファイルが PC の他の利用者から読める ACL を継承していたことと、UDP のセッションごとに 65535 バイトのバッファを保持し続け、既定の上限ではメモリのソフト上限を大きく超えることが分かりました。macOS の実機では、9216 バイトを超える UDP のデータグラムの宛先への書き込みが失敗することが分かりました (設計文書の改訂の記録、2026-09-19)。

Windows と macOS の試験は、次のように類を分けます。

| 時点 | Windows | macOS |
|---|---|---|
| すべての PR (A 類) | クロスビルドと `go vet` (A7) | クロスビルドと `go vet` (A7) |
| 関係する PR (B 類) | Windows の runner での単体テスト (B4) | macOS の runner での単体テスト (B8) |
| 段階の完了 (C 類) | 含めない (C 類は Linux の VM と悪い条件のネットワークを扱う) | 含めない |
| リリース候補 (D 類) | エージェントの smoke (D1) | エージェントの smoke (D2) |
| v1 の前と関係する変更の後の手作業 (E 類) | スリープと復帰、アダプタの無効と有効、Wi-Fi の再接続 (E4) | スリープと復帰、Wi-Fi とインタフェースの変化、再起動の後の launchd (E5) |

### Windows のエージェントの smoke の内容

D1 は、リリースのバイナリ (`wgft-windows-amd64.exe`) を、ラボか試験用の実 VPS の server に対して動かし、次の点を確かめます。

- 起動と登録:管理者の権限を持たない利用者が `agent run` を起動し、登録が通るかを確かめます
- TCP と UDP の転送:Windows 自身と LAN の他のホストへの転送が通るかを確かめます
- 大きな UDP:トンネルの MTU を超えるデータグラム (3000 バイトと 12000 バイト) が欠けずに届くかを確かめます
- 再接続:server の再起動と、エージェントの再起動の後に転送が戻るかを確かめます
- UDP の受信の固着:server の UDP のポートが一時的に届かなくなった後、送信は続くのに受信だけが止まったままにならないか、エージェントを再起動せずに戻るかを確かめます
- 状態の保持:保存した認証情報で、登録をやり直さずに起動できるかを確かめます。認証情報のファイルの ACL が保護されたままであることも確かめます
- ネットワークアダプタの無効と有効:アダプタを無効にして有効に戻した後に、転送が戻るかを確かめます
- リリースのバイナリ:ビルドし直した物ではなく Releases の物が、Windows Defender ファイアウォールの確認 (許可と取り消しのどちらでも) の後に動くかを確かめます

環境の候補は、Linux のホストの上の Windows の VM、Windows の CI の runner、Windows の実機の 3 つです。Windows の VM は、Linux のラボの netns の中には入らず、別の VM としてラボの server に接続します。Windows の VM で D1 のどこまでを再現できるかは未確認です。Windows の CI の runner で登録と転送を確かめるには、runner から届く server を CI から用意する仕組みが要るので、v1 では使いません。VM のスリープが実機のスリープと同じ経路 (ネットワークのドライバの停止と再開) を通るかは未確認なので、スリープと復帰は実機で確かめます (E4)。無人での常駐 (サービスや SYSTEM としての実行) は未確認で、v1 の確認の対象に含めません。

Windows の実機の代わりに、同じ Windows 機の WSL2 に server を置き、`networkingMode=mirrored` で client と結ぶ構成もあります。この構成は登録、ルールの扱い、認証情報の保存、D1 で使う CLI の確認には十分ですが、client と server が別のホストにある本来の構成の経路を再現しません。次の 3 点は、この構成だけで判定すると誤ります (issue #87)。

| 効果 | 内容 |
|---|---|
| 経路の再現 | mirrored networking では WSL2 の guest が Windows host のアドレスを共有するため、待ち受けの無いポート宛てのデータグラムは guest に届かず、Windows host 自身が ICMP を返します。実 VPS を実回線越しに使う確認では、同じ種の送信でも WinRingBind に WSAECONNRESET は現れませんでした。VPS が ICMP を生成したか、経路上で失われたかは切り分けていません |
| MTU の頭打ち | mirrored の経路は wgft と無関係な UDP の制御用の応答でも頭打ちになるため、3000 バイトと 12000 バイトの確認は判定できません。1420 バイトのトンネルの MTU を上回る転送そのものは、この経路でも成功しました |
| アダプタの無効と有効 | Windows host のアダプタを無効にして有効に戻しても、mirrored networking の guest は自分のネットワークインタフェースを失ったままでした。server がその guest にあると、client の経路の消失と server の消失が同時に起き、アダプタの項目を切り分けられません |

D1 の「UDP の受信の固着」「大きな UDP」「ネットワークアダプタの無効と有効」を確かめるには、client と server が別のホストにある構成が要ります。WSL2 の mirrored networking は、それ以外の D1 の確認には有効な近道です。

### macOS のエージェントの smoke の内容

D2 は、リリースのバイナリ (`wgft-darwin-arm64`) を Apple シリコンの Mac の実機で動かし、次の点を確かめます。

- リリースのバイナリ:README の手順 (`curl` での取得と sha256 の照合) で導入したバイナリが、Gatekeeper に止められずに動くかを確かめます
- launchd:同梱の `deploy/io.github.rahanahu.wgft.agent.plist` で LaunchDaemon として起動し、強制終了の後に再起動されるかを確かめます
- TCP と UDP の転送:Mac 自身と LAN の他のホストへの転送が通るかを確かめます
- 大きな UDP:9216 バイトを超えるデータグラム (12000 バイト) が宛先に届くかを確かめます
- 再接続:server の再起動と Mac の再起動の後に、転送が戻るかを確かめます

macOS の挙動は Linux の上で再現できるとはみなしません。macOS の CI の runner は単体テスト (B8、CI の `macos-test`) には使えますが、launchd、スリープと復帰、ネットワークの変化の確認は、実機での手作業の関門 (D2 と E5) にします。runner の macOS が実機と同じ UDP の送信バッファの既定 (9216 バイト) を持つかは未確認です。FileVault を無効にした Mac でのログイン無しの起動と、ログアウトの後の動作は未確認です。

### 実機の確認を小さな回帰テストに置き換えた範囲

`internal/dataplane/userspace/utun` の `TestAgentServerInProcessForwarding` は、エージェント側のトンネルと中継 (`internal/agent` が組む `internal/dataplane/userspace/tunnel` と `internal/dataplane/userspace/relay` の組み合わせ) と、VPS 側のユーザー空間モードが使う部品 (`utun.Tunnel`、`relay.Manager`、`internal/policy/goengine` の評価器) を、1 つのプロセスの中で実 UDP (127.0.0.1、ループバックだけ) で繋ぎ、TCP と UDP を実際に転送します。CI では `build-test` (Linux)、`macos-test` (B8)、`windows-test` (B4) の 3 つがこのテストを PR ごとに流します。

確かめる内容は、TCP の往復、両方向とも正常に切断できること、100・1400・3000・12000 バイトの UDP のデータグラムが欠けずに往復すること (3000 バイトはトンネルの MTU を超え、12000 バイトは前述の macOS の既定の UDP 送信バッファ 9216 バイトを超えます)、エージェント側を同じ鍵で落として立て直した後に転送が戻ることです。D1 と D2 のうち「TCP と UDP の転送」と「大きな UDP」の項目を、この 3 つの CI runner の範囲で PR ごとに機械で確かめます。

VPS 側は `userspace.Backend` という型そのものではなく、`Backend` が組む部品を同じ手順で直接組んでいます。`Backend` に `Close` が無く、1 つのプロセスの中で後始末をしながら `-count` で繰り返し流すテストの土台にできないためです。VPS 側の「公開ポート」は、production の非公開の `hostNetwork` (全インタフェースに bind する) の代わりに、127.0.0.1 だけに bind するテスト用の実装を使います。VPS 側の実装 (`internal/vpsd`) は Linux 限定なので、この違いは実際の配布物の挙動には影響しません。

「userspace の server 側のコードが Windows と macOS でビルドできるか」は確かめました。`internal/dataplane/userspace` とその下位パッケージ (`utun` を含む) は、4 つの対象 (windows/amd64、windows/arm64、darwin/amd64、darwin/arm64) で `go build` と `go vet` を通ります。ビルドできないのは `internal/vpsd` そのもの (google/nftables など Linux 限定の依存を持つ、カーネルの nftables を操作する層) で、`internal/dataplane/userspace` はその依存を持ちません。

このテストは、以前は Windows でだけ結果を判定せず SKIP していました。原因は、wireguard-go の `conn.NewDefaultBind()` が Windows で返す `WinRingBind` が `SIO_UDP_CONNRESET` を無効にせず、届いた ICMP port unreachable が `WSAECONNRESET` として次の受信に現れ、`device.RoutineReceiveIncoming` がこれを回復不能な誤りと判定して受信ループを止めることでした (詳しい経緯は [design.md](design.md) の改訂の記録にあります)。この不具合は Pull Request #107 が直し、`internal/dataplane/userspace/tunnel` と `internal/dataplane/userspace/utun` の `newBind()` は、Windows でだけ `conn.NewStdNetBind()` を明示して使います。この修正を当てて SKIP を外した状態を Windows の実機で 13 回実行した実験では 10 回通り、残る 3 回の失敗はトンネル側の不具合ではなく、テスト自身が wg の `listen_port` をホストが決めた範囲から連続 50 個走査して選んでいた弱さ (空きポートが見つからない) によるものでした。この走査は、`ListenPort` に 0 を渡して OS に選ばせ、実際に割り当てられたポートを `IpcGet` で読み返す形に変え、SKIP も外しています。この形にした後、CI の `windows-test` でこのテストは 5 回続けて通りました。Windows の実機での再実行は未確認です。

このテストの後も、launchd での起動、認証情報ファイルの ACL、スリープと復帰、ネットワークアダプタの変化、リリースの実バイナリそのものの確認、D1 の「UDP の受信の固着」(実サーバーに対する実機での通しの確認がまだ無いため。改訂の記録を参照) は実機に残ります (D1、D2、E4、E5)。

## 高価な実験を小さな回帰テストへ置き換える規則

F 類の実験と、C 類から E 類の高価な確認は、次の規則で小さな回帰テストに置き換えます。

1. 実験の目的は仕様の根拠を得ることなので、根拠を得たら実験を終えます。結果の要約と、設計と仕様への影響は、設計文書の「改訂の記録」に書きます ([CLAUDE.md](../CLAUDE.md) の「実験の置き場所」)
2. 根拠のうち、今後のコードの変更で崩れうるものだけを回帰テストにします。コードの変更で崩れない性質 (カーネルの定数、特定の機器の性能) は回帰テストにしません
3. 回帰テストは、崩れうる性質を確かめられる最も安い環境に置きます。安い順に、ホストの単体テスト (A1 から A8)、ラボの一式の 1 つの確認 (L 番号)、ラボの一式の外の確認 (B 類)、複数の VM や実機の確認 (C 類から E 類) です
4. 回帰テストは、実験の測定値そのものではなく、測定値から決めた上限や判定を確かめます。中継のフロー 1 本のメモリの費用を調べるプロファイル (F5) を例に取ると、回帰テストは測定のやり直しではなく、上限までのフラッドで RSS がソフト上限と余裕の和の内側にあることの確認 (L8) です
5. 同じ実験をやり直すのは、根拠の前提 (カーネルの版、依存するライブラリ、設計の決定) が変わったときだけです

各実験の置き換え先は、F 類の表の「置き換え先の回帰テスト」の列にあります。E 類の実機の確認で見つかった不具合も同じ規則に従い、再現できる範囲を A 類か B 類のテストにします。macOS の UDP の送信バッファの不具合を relay の単体テストで扱い、そのテストを B8 で macOS の runner に流すのがこの規則の例です。
