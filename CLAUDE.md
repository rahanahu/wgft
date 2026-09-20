# wgft の開発の約束

This file holds the project conventions, in Japanese, for anyone changing the code, including Claude Code, which reads it automatically. The README, SECURITY.md and all tool output are in English, and issues and pull requests in English are welcome.

wgft の VPS 側はカーネルの nftables、WireGuard、conntrack を直接操作します。そのため、この操作を確かめる開発環境と、変更の進め方に関する約束があります。

## 開発用ラボの立て方

コードの編集と `go test` はホストで行います。nftables、wg0、conntrack が絡む実験と、端から端までの結合テストは、Incus の VM `wgft-lab` の中の network namespace で行います。ホストや Docker でカーネル機能を試すと、ホスト自身のカーネルバージョンや、Docker が有効にする `br_netfilter` 経由のルールと conntrack が結果に混ざるため、VM に切り分けます。

ラボの起動は `lab/lab up` の 1 コマンドで済みます。Incus が入っていて自分が `incus-admin` グループに属していれば、VM の作成、パッケージの導入、`client - vps - homerouter(NAT) - home` の 4 つの network namespace によるトポロジの構築までがこの 1 コマンドに含まれます。ビルドは `lab/lab build` がホスト上の Go コードを VM の `/usr/local/bin` にインストールし、`lab/lab exec <ns> <コマンド>` で各 namespace 内のプロセスを起動します。壊れた状態になったら `lab/lab reset` でスナップショットに戻せます。詳しい手順は [lab/README.md](lab/README.md) にあります。

## テストの分け方

`go test ./...` はホストで実行する単体テストで、ネットワーク namespace や root 権限を必要としません。`lab/` 配下の結合テストは Incus の VM を必要とするため、CI では実行されません。開発者はコードを変える PR のマージの前にラボの結合テストの一式を流し、CI には単体テストと後述の静的検査だけを任せます。文書だけを変える PR では、ラボを流しません。どのテストをどの変更と時点で流すかは [docs/testing.md](docs/testing.md) に定めてあります。

## 実験の置き場所

nftables や WireGuard の挙動を確かめる使い捨ての実験コードは、このリポジトリには含めていません。実験はラボで行い、結果の要約と、設計と仕様への影響を [docs/design.md](docs/design.md) の「改訂の記録」に書きます。要約は、何を確かめて何が分かったかと、未確認の点です。試行の回数、所要時間、測定値の一覧などの詳細はプルリクエストの本文に書き、改訂の記録には書きません。

## 設計文書を先に直す順序

決定事項を変えるときは、設計文書([docs/design.md](docs/design.md))を先に直してから実装します。ラボでの実験によって設計の前提が崩れた場合も、設計文書の改訂(改訂の記録への追記を含む)、実装、の順で進めます。

## コミットの粒度

1 つのコミットは 1 つの話題にします。設計文書の改訂を伴う実装は、改訂と実装を同じコミットに入れます。コミットメッセージは英語で書き、1 行目は Conventional Commits の形にします。

```
<type>(<scope>): <要点>       1 行目。72 文字以内、命令形、末尾にピリオドを付けない

<なぜ変えたか。何を確かめたか>  本文。省略可
```

`type` は次の 8 つだけを使います。`scope` は任意で、`server`、`agent`、`nft`、`wg`、`ui`、`cli`、`docker`、`deps` のようにパッケージや対象を短く書きます。

| type | 使いどころ |
|---|---|
| `feat` | 利用者から見える機能の追加 |
| `fix` | 不具合の修正。守りの穴を塞ぐ変更も含みます |
| `docs` | README、設計文書、コメントだけの変更 |
| `refactor` | 挙動を変えないコードの整理 |
| `test` | テストだけの変更 |
| `build` | ビルド、GoReleaser、Dockerfile、go.mod |
| `ci` | GitHub Actions と検査スクリプト |
| `chore` | 上のどれでもない雑務 |

設計文書の改訂を伴う変更は、その改訂を同じコミットに含めて `feat` か `fix` にします。設計文書だけを変えるときは `docs` です。

プルリクエストのタイトルも、コミットの 1 行目と同じ形 (`<type>(<scope>): <要点>`) にします。複数のコミットを含むときは、主な変更の `type` を使います。main にはスカッシュでマージします。このリポジトリの現在の設定 (GitHub の既定の「コミットが 1 つならその 1 行目、複数ならタイトル」) では、main のコミットの 1 行目は、コミットが 1 つだけのプルリクエストではそのコミットの 1 行目、複数のときはタイトルになります。このため、タイトルとコミットの 1 行目の両方をこの形にします。

リリースは、版の記述 (README の Status の節) を直すコミットを `chore(release): vX.Y.Z` の形で main に入れ、そのコミットにタグ `vX.Y.Z` を打ちます。版の上げ方は、前回のタグ以降に互換を崩す変更があれば major、`feat` があれば minor、`fix` だけなら patch です。ただし 1.0 より前は、互換を崩す変更も minor で上げます。

別のセッションや別の人が同時に作業していることがあります。`git status` で自分のものではない未コミットの変更を見つけたら、自分の変更と混ぜずに、触らないでおきます。

## CI が通す検査

`.github/workflows/ci.yml` は push と pull request のたびに次を検査します。`gofmt -l` によるフォーマットの確認、`go vet`、ビルドと `go test ./...`、`staticcheck` による静的解析、文字列リテラルへの日本語混入の検査([scripts/check-japanese](scripts/check-japanese/)。ツールの出力は英語だけを使う約束のためです)、公開対象ファイルの全角記号の検査([scripts/check-ascii-punct.sh](scripts/check-ascii-punct.sh))です。ラボの結合テストは Incus の VM を必要とするため、CI には含まれません。

## v1.0 までの内部構造の固定

v1.0 をリリースするまで、内部構造は原則として固定します。package の分け方と層の分け方は、移行の完了後に点検し、現時点で変更する実利が無いことを確かめました。点検の結果は [docs/design.md](docs/design.md) の「改訂の記録」にあります。

固定の対象は次の 4 つです。

- package の境界
- 依存の向き。規範は [docs/design.md](docs/design.md) の 7a.7 節で、`internal/dataplane/deps_test.go` が検査します
- 層の間の interface
- 新しい抽象の層の追加

次の変更は、固定の対象に含めません。

- 不具合の修正
- package の内部の整理
- テスト、ラボ、テストの harness
- 文書
- 依存の更新
- 運用者に見える文言

固定の対象を変更できるのは、再現できる実害を具体的に示せる場合だけです。実害は、不具合、テストのフレーク、レビューで 2 回以上見つかった同じ種類の誤りのいずれかです。コードが整うことは、変更の理由にしません。変更するときは、実害をプルリクエストの本文に引用します。

作業の途中で固定の対象に当たる改善を見つけたときは、変更せずにプルリクエストの本文か Issue に記録します。

## コードと出力の約束

- ツールの出力 (ログ、エラー、CLI のヘルプと結果) は英語だけで書きます。i18n は持ちません。Web UI だけが `internal/vpsd/admin/i18n.go` で日英を切り替えます。コードのコメントは日本語のままで構いません
- 設定は `WGFT_*` の環境変数で受け取ります。ファイルはその dotenv、フラグはその別名です。`--force`、`--purge`、`--adopt-existing`、`--yes`、`--dry-run` のような 1 回限りの操作はフラグでしか渡せません。規範は [docs/design.md](docs/design.md) の 11a 節です
- 利用者に見える呼び名とコードの識別子を対応させます。agent の `agent.json` は「認証情報 (credentials)」で、パッケージも `internal/agent/credentials` です。server の SQLite は「サーバのデータベース」(`DBPath`) です。設計文書だけは「状態ファイル」と呼びます (3 節の用語)。VPS 側のデーモンは設計文書と内部では `vpsd`、利用者に見える名前は `server` です
- 環境を見て挙動を推測しません。モードもファイアウォールも、明示された値に従うか、提示して止まります

## 文書の約束

- README は `README.md` (英語) と `README.ja.md` (日本語) の 2 本です。構成と情報量を同じにし、片方を直したらもう片方も直します。英語は英語として自然な書き方で構いません
- 日本語の文書は次の規範に従います。書く前に読み直します
  - https://raw.githubusercontent.com/megmogmog1965/claude-code-writing-style/main/plugins/writing-style/skills/style-review/references/rules.md
  - https://gist.githubusercontent.com/k16shikano/fd287c3133457c4fd8f5601d34aa817d/raw (日本語技術文書の文章規範)
  - https://gist.githubusercontent.com/k16shikano/eb2929f13ed19c97188393d297be8432/raw (「駄文の見分け方」の部分だけ使います。文書自身を語る文は削ります)
- 要点は次のとおりです。です・ます体で書きます。項目を主語にした定義文にします。体言止め、指示語 (ここ、そこ)、擬人化 (プログラムに「教える」)、翻訳調 (「前面に出して」) を使いません。くだけた語 (足す、消す、上げる) は書き言葉にします。見出しは内容を特定する名詞句にします。箇条書きのラベルは名詞句とコロンにします。未確認のことは「未確認」と書きます
- 括弧とコロンは ASCII にします。README では括弧による補足をできるだけ使わず、別の文にします。図は README なら Mermaid にします
- 試していないことを手順として書きません。ラボか実機で通したものだけを書きます

## コマンドのヘルプとリファレンスの直し方

コマンドの長い説明と使用例は `cmd/wgft/helptext.go` の表にまとめてあります。コマンドの定義には 1 行の `Short` だけを置きます。[docs/cli.md](docs/cli.md) はこのヘルプから生成した文書で、手では編集しません。ヘルプを変えたら、次のコマンドで生成し直して同じコミットに入れます。

```
go test ./cmd/wgft -run TestCLIDocUpToDate -update
```

`go test` は docs/cli.md がヘルプと一致しているかを照合するので、生成を忘れると CI が落ちます。実行できるコマンドに使用例が無い場合も、テストが落ちます。ヘルプに挙動を書くときは、ラボで確かめたことだけを書きます。README の日英にはコマンド一覧の表を置いておらず、コマンドの説明は docs/cli.md と `wgft <command> --help` に一本化しています。

## Web UI のスクリーンショットの撮り直し方

README.md と README.ja.md が使う `docs/images/dashboard.png`(英語)と `dashboard.ja.png`(日本語)は、`scripts/screenshot-ui.sh` で撮影します。ラボの VM も実機の VPS も要りません。

このスクリプトは `tools/uidemo` をビルドして 127.0.0.1:8687 に Web UI を起動します。8687 が使われていれば止まります (実機の管理 API を SSH で転送している最中に実機の画面を撮ってしまわないため)。`tools/uidemo` は admin パッケージの公開 API(`New`、`Serve`)だけを使い、固定のサンプルデータ(エージェント 3 台、5 グループのルール、警告 1 件)を返す Backend です。サーバーが起動したら、Headless Firefox で `?lang=en` と `?lang=ja` の 2 枚を撮影し、`docs/images` へ上書きしてからサーバーを止めます。撮影には Firefox(`/usr/bin/firefox`)が要ります。

手順は `bash scripts/screenshot-ui.sh` の実行だけです。Web UI のテンプレートや文言を変えたとき、サンプルデータの形を変えたときは、このコマンドで撮り直し、`git diff --stat` で差分の大きさを確かめてからコミットします。サンプルデータの値そのものは `tools/uidemo/main.go` にあります。

## 単体テストのカバレッジが低いパッケージ

`internal/vpsd`、`internal/vpsd/wg`、`internal/agent` は、単体テストのカバレッジが意図的に低いパッケージです。これらはカーネルの nftables や WireGuard、実ネットワークとの配線を担う層であり、モックに置き換えると確かめられる範囲が狭くなります。この層は `lab/` の結合テストで、実機に近い環境での動作を確かめる方針を取っています。
